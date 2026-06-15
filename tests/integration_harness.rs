use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be valid")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hypr-nav-it-{}-{}-{}",
            label,
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(&path).expect("test directory should be created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct HyprServer {
    socket_path: PathBuf,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl HyprServer {
    fn start(runtime_dir: &Path, sig: &str, active_class: &str, active_pid: u32) -> Self {
        Self::start_with_response(
            runtime_dir,
            sig,
            &format!(
                "Window abc123 -> test window:\nclass: {}\npid: {}\n",
                active_class, active_pid
            ),
        )
    }

    fn start_with_response(runtime_dir: &Path, sig: &str, active_response: &str) -> Self {
        Self::start_with_options(runtime_dir, sig, active_response, false)
    }

    fn start_with_response_then_stop(runtime_dir: &Path, sig: &str, active_response: &str) -> Self {
        Self::start_with_options(runtime_dir, sig, active_response, true)
    }

    fn start_with_options(
        runtime_dir: &Path,
        sig: &str,
        active_response: &str,
        stop_after_activewindow: bool,
    ) -> Self {
        let socket_dir = runtime_dir.join("hypr").join(sig);
        fs::create_dir_all(&socket_dir).expect("hypr runtime dir should be created");
        let socket_path = socket_dir.join(".socket.sock");
        let listener = UnixListener::bind(&socket_path).expect("hypr socket should bind");
        listener
            .set_nonblocking(true)
            .expect("hypr socket should be nonblocking");

        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let requests_clone = Arc::clone(&requests);
        let stop_clone = Arc::clone(&stop);
        let active_response = active_response.to_string();
        let socket_path_for_thread = socket_path.clone();

        let handle = thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _addr)) => {
                        let mut request = String::new();
                        let _ = stream.read_to_string(&mut request);
                        let request = request.trim().to_string();
                        if request == "activewindow" {
                            let _ = stream.write_all(active_response.as_bytes());
                            if stop_after_activewindow {
                                let _ = fs::remove_file(&socket_path_for_thread);
                                stop_clone.store(true, Ordering::Relaxed);
                            }
                        }
                        requests_clone
                            .lock()
                            .expect("requests lock should succeed")
                            .push(request);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            socket_path,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("requests lock should succeed")
            .clone()
    }
}

impl Drop for HyprServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = std::os::unix::net::UnixStream::connect(&self.socket_path);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct PtyProcess {
    script_child: Child,
    pid: u32,
}

impl PtyProcess {
    fn spawn(pid_file: &Path, envs: &[(&str, &str)]) -> Self {
        let mut command = Command::new("script");
        command
            .arg("-qefc")
            .arg("sh -lc 'echo $$ > \"$TEST_PID_FILE\"; while :; do sleep 1; done'")
            .arg("/dev/null")
            .env("TEST_PID_FILE", pid_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        for (key, value) in envs {
            command.env(key, value);
        }

        let script_child = command.spawn().expect("script process should spawn");

        let pid = wait_for_pid_file(pid_file);
        Self { script_child, pid }
    }
}

impl Drop for PtyProcess {
    fn drop(&mut self) {
        let _ = self.script_child.kill();
        let _ = self.script_child.wait();
    }
}

struct Harness {
    _dir: TestDir,
    runtime_dir: PathBuf,
    fake_bin_dir: PathBuf,
    log_path: PathBuf,
    hypr_sig: String,
}

impl Harness {
    fn new(label: &str) -> Self {
        let dir = TestDir::new(label);
        let runtime_dir = dir.path().join("runtime");
        let fake_bin_dir = dir.path().join("bin");
        fs::create_dir_all(&runtime_dir).expect("runtime dir should exist");
        fs::create_dir_all(&fake_bin_dir).expect("bin dir should exist");
        let log_path = dir.path().join("commands.log");
        let hypr_sig = "test-instance".to_string();

        write_script(
            &fake_bin_dir.join("kitty"),
            r#"#!/usr/bin/env bash
set -euo pipefail
echo "kitty $*" >> "$TEST_LOG"
if [[ "${1-}" == "--sleep-forever" ]]; then
  while :; do sleep 1; done
fi
if [[ "${1-}" == "@" && "${4-}" == "ls" ]]; then
  printf '%s' "${TEST_KITTY_LS_JSON:-[]}"
  exit 0
fi
if [[ "${1-}" == "@" && "${4-}" == "close-window" ]]; then
  if [[ "${TEST_KITTY_CLOSE_OK:-0}" == "1" ]]; then
    exit 0
  fi
  exit 1
fi
if [[ "${1-}" == "@" ]]; then
  if [[ "${TEST_KITTY_FOCUS_OK:-0}" == "1" ]]; then
    exit 0
  fi
  exit 1
fi
exit 1
"#,
        );
        write_script(
            &fake_bin_dir.join("nvim"),
            r#"#!/usr/bin/env bash
set -euo pipefail
echo "nvim $*" >> "$TEST_LOG"
case " $* " in
  *" --remote-expr winnr('\$') "*)
    printf '%s\n' "${TEST_NVIM_WIN_COUNT:-2}"
    exit 0
    ;;
  *" --remote-expr "*)
    printf '%s\n' "${TEST_NVIM_AT_EDGE:-0}"
    exit 0
    ;;
  *" --remote-send "*)
    if [[ "${TEST_NVIM_SEND_OK:-1}" == "1" ]]; then
      exit 0
    fi
    exit 1
    ;;
esac
exit 1
"#,
        );
        write_script(
            &fake_bin_dir.join("tmux"),
            r#"#!/usr/bin/env bash
set -euo pipefail
args=("$@")
if [[ "${args[0]-}" == "-S" ]]; then
  args=("${args[@]:2}")
fi
echo "tmux ${args[*]}" >> "$TEST_LOG"
joined=" ${args[*]} "
cmd="${args[0]-}"
case "$cmd" in
  list-clients)
    if [[ "$joined" == *" #{client_tty} #{pane_id} "* ]]; then
      printf '%s %s\n' "${TEST_TTY:?}" "${TEST_TMUX_PANE_ID:-%1}"
      exit 0
    fi
    if [[ "$joined" == *'#{client_session}'* && "$joined" == *'#{client_tty}'* ]]; then
      printf '%s\t%s\n' "${TEST_TMUX_SESSION:-$1}" "${TEST_TTY:?}"
      exit 0
    fi
    ;;
  list-panes)
    if [[ "$joined" == *" #{pane_tty} #{pane_id} "* ]]; then
      printf '%s %s\n' "${TEST_TTY:?}" "${TEST_TMUX_PANE_ID:-%1}"
      exit 0
    fi
    if [[ "$joined" == *" #{pane_tty} #{session_id} "* ]]; then
      printf '%s %s\n' "${TEST_TTY:?}" "${TEST_TMUX_SESSION:-$1}"
      exit 0
    fi
    if [[ "$joined" == *" #{pane_id} #{pane_at_left} #{pane_at_right} #{pane_at_top} #{pane_at_bottom} #{pane_active} "* ]]; then
      printf '%s\n' "${TEST_TMUX_PANE_ROWS:-%1 1 0 1 1 1}"
      exit 0
    fi
    ;;
  display-message)
    if [[ "$joined" == *" #{pane_at_left} "* || "$joined" == *" #{pane_at_right} "* || "$joined" == *" #{pane_at_top} "* || "$joined" == *" #{pane_at_bottom} "* ]]; then
      printf '%s\n' "${TEST_TMUX_AT_EDGE:-0}"
      exit 0
    fi
    if [[ "$joined" == *" #{window_id} "* ]]; then
      printf '%s\n' "${TEST_TMUX_WINDOW_ID:-@1}"
      exit 0
    fi
    if [[ "$joined" == *" #{pane_id} "* ]]; then
      printf '%s\n' "${TEST_TMUX_PANE_ID:-%1}"
      exit 0
    fi
    if [[ "$joined" == *$'#{session_name}\t#{window_panes}\t#{session_windows}'* ]]; then
      printf '%s\n' "${TEST_TMUX_SESSION_INFO:-1	2	1}"
      exit 0
    fi
    ;;
  select-pane)
    if [[ "${TEST_TMUX_SELECT_OK:-1}" == "1" ]]; then
      exit 0
    fi
    exit 1
    ;;
  detach-client|kill-pane)
    exit 0
    ;;
esac
exit 1
"#,
        );

        Self {
            _dir: dir,
            runtime_dir,
            fake_bin_dir,
            log_path,
            hypr_sig,
        }
    }

    fn envs(&self) -> Vec<(String, String)> {
        let mut path = self.fake_bin_dir.display().to_string();
        path.push(':');
        path.push_str(&std::env::var("PATH").unwrap_or_default());

        vec![
            (
                "XDG_RUNTIME_DIR".to_string(),
                self.runtime_dir.display().to_string(),
            ),
            (
                "HYPRLAND_INSTANCE_SIGNATURE".to_string(),
                self.hypr_sig.clone(),
            ),
            (
                "KITTY_LISTEN_ON".to_string(),
                "unix:/tmp/fake-kitty".to_string(),
            ),
            ("TEST_LOG".to_string(), self.log_path.display().to_string()),
            ("PATH".to_string(), path),
        ]
    }

    fn log_contents(&self) -> String {
        fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

fn write_script(path: &Path, contents: &str) {
    fs::write(path, contents).expect("script should be written");
    let mut perms = fs::metadata(path)
        .expect("script metadata should exist")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("script should be executable");
}

fn wait_for_pid_file(pid_file: &Path) -> u32 {
    for _ in 0..100 {
        if let Ok(contents) = fs::read_to_string(pid_file) {
            if let Ok(pid) = contents.trim().parse::<u32>() {
                return pid;
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("pid file was not populated");
}

fn wait_for_log_line(log_path: &Path, needle: &str) {
    for _ in 0..100 {
        let log = fs::read_to_string(log_path).unwrap_or_default();
        if log.contains(needle) {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("did not observe log line containing {}", needle);
}

fn wait_for_request(server: &HyprServer, needle: &str) -> Vec<String> {
    for _ in 0..100 {
        let requests = server.requests();
        if requests.iter().any(|request| request == needle) {
            return requests;
        }
        thread::sleep(Duration::from_millis(20));
    }
    server.requests()
}

fn spawn_process_named(name: &str) -> Child {
    Command::new("bash")
        .arg0(name)
        .args(["-c", "while :; do sleep 1; done"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("named process should spawn")
}

fn run_binary_status(bin_name: &str, args: &[&str], envs: &[(String, String)]) -> ExitStatus {
    let bin = match bin_name {
        "hypr-nav" => env!("CARGO_BIN_EXE_hypr-nav"),
        "hypr-tmux-nav" => env!("CARGO_BIN_EXE_hypr-tmux-nav"),
        "hypr-smart-close" => env!("CARGO_BIN_EXE_hypr-smart-close"),
        _ => panic!("unknown binary: {bin_name}"),
    };
    let mut command = Command::new(bin);
    command.args(args);
    command.env_remove("HYPR_CLOSE_LOG");
    command.env_remove("XDG_STATE_HOME");
    for (key, value) in envs {
        command.env(key, value);
    }
    command.status().expect("binary should run")
}

fn run_binary(bin_name: &str, args: &[&str], envs: &[(String, String)]) {
    let status = run_binary_status(bin_name, args, envs);
    assert!(status.success(), "binary exited with {status}");
}

#[test]
fn hypr_nav_prefers_kitty_before_hypr_fallback() {
    let harness = Harness::new("kitty-precedence");
    let hypr = HyprServer::start(
        &harness.runtime_dir,
        &harness.hypr_sig,
        "kitty",
        std::process::id(),
    );

    let mut envs = harness.envs();
    envs.push(("TEST_KITTY_FOCUS_OK".to_string(), "1".to_string()));

    run_binary("hypr-nav", &["left"], &envs);

    wait_for_log_line(
        &harness.log_path,
        "kitty @ --to unix:/tmp/fake-kitty focus-window --match neighbor:left",
    );
    let requests = hypr.requests();
    assert!(requests.iter().any(|request| request == "activewindow"));
    assert!(
        !requests
            .iter()
            .any(|request| request.starts_with("dispatch ")),
        "expected no Hypr fallback dispatch, got {requests:?}"
    );
}

#[test]
fn hypr_nav_detects_custom_class_kitty_by_pid() {
    let harness = Harness::new("kitty-pid-detect");
    let mut kitty_process = spawn_process_named("kitty");
    let hypr = HyprServer::start(
        &harness.runtime_dir,
        &harness.hypr_sig,
        "custom-terminal",
        kitty_process.id(),
    );

    let mut envs = harness.envs();
    envs.push(("TEST_KITTY_FOCUS_OK".to_string(), "1".to_string()));

    run_binary("hypr-nav", &["left"], &envs);

    let _ = kitty_process.kill();
    let _ = kitty_process.wait();

    wait_for_log_line(
        &harness.log_path,
        "kitty @ --to unix:/tmp/fake-kitty focus-window --match neighbor:left",
    );
    let requests = hypr.requests();
    assert!(requests.iter().any(|request| request == "activewindow"));
    assert!(
        !requests
            .iter()
            .any(|request| request.starts_with("dispatch ")),
        "expected no Hypr fallback dispatch, got {requests:?}"
    );
}

#[test]
fn hypr_nav_falls_back_to_hypr_when_kitty_navigation_fails() {
    let harness = Harness::new("kitty-fallback");
    let hypr = HyprServer::start(
        &harness.runtime_dir,
        &harness.hypr_sig,
        "kitty",
        std::process::id(),
    );

    let envs = harness.envs();
    run_binary("hypr-nav", &["right"], &envs);

    let requests = wait_for_request(&hypr, "dispatch movefocus r");
    assert!(
        requests
            .iter()
            .any(|request| request == "dispatch movefocus r"),
        "expected Hypr fallback dispatch, got {requests:?}"
    );
}

#[test]
fn hypr_nav_exits_nonzero_when_hypr_fallback_dispatch_fails() {
    let harness = Harness::new("kitty-dispatch-fail");
    let hypr = HyprServer::start_with_response_then_stop(
        &harness.runtime_dir,
        &harness.hypr_sig,
        "Window abc123 -> test window:\nclass: brave-browser\npid: 4242\n",
    );

    let envs = harness.envs();
    let status = run_binary_status("hypr-nav", &["right"], &envs);

    assert!(
        !status.success(),
        "failed Hypr dispatch should exit non-zero"
    );
    let requests = hypr.requests();
    assert_eq!(requests, vec!["activewindow".to_string()]);
}

#[test]
fn hypr_smart_close_closes_captured_kitty_hypr_window_only() {
    let harness = Harness::new("smart-close-kitty");
    let hypr = HyprServer::start(
        &harness.runtime_dir,
        &harness.hypr_sig,
        "kitty",
        std::process::id(),
    );

    let mut envs = harness.envs();
    envs.push(("TEST_KITTY_CLOSE_OK".to_string(), "1".to_string()));
    envs.push((
        "TEST_KITTY_LS_JSON".to_string(),
        r#"[{"is_focused":true,"tabs":[{"is_focused":true,"windows":[{"is_focused":true,"pid":999}]}]}]"#
            .to_string(),
    ));

    run_binary("hypr-smart-close", &[], &envs);

    let requests = wait_for_request(&hypr, "dispatch closewindow address:0xabc123");
    assert!(
        requests
            .iter()
            .any(|request| request == "dispatch closewindow address:0xabc123"),
        "expected exact Hypr closewindow dispatch, got {requests:?}"
    );
    assert!(requests.iter().any(|request| request == "activewindow"));
    assert!(
        !requests
            .iter()
            .any(|request| request == "dispatch killactive"),
        "expected no Hypr killactive dispatch, got {requests:?}"
    );
    let log = harness.log_contents();
    assert!(
        !log.contains("kitty @"),
        "smart-close must not use global kitty remote control, got {log}"
    );
}

#[test]
fn hypr_smart_close_does_not_log_by_default() {
    let harness = Harness::new("sc-nolog");
    let default_log = harness.runtime_dir.join("hypr-close/events.jsonl");
    let hypr = HyprServer::start(
        &harness.runtime_dir,
        &harness.hypr_sig,
        "kitty",
        std::process::id(),
    );

    let mut envs = harness.envs();
    envs.push((
        "XDG_STATE_HOME".to_string(),
        harness.runtime_dir.display().to_string(),
    ));

    run_binary("hypr-smart-close", &[], &envs);

    let requests = wait_for_request(&hypr, "dispatch closewindow address:0xabc123");
    assert!(
        requests
            .iter()
            .any(|request| request == "dispatch closewindow address:0xabc123"),
        "expected exact Hypr closewindow dispatch, got {requests:?}"
    );
    assert!(
        !default_log.exists(),
        "smart-close event logging should be opt-in"
    );
}

#[test]
fn hypr_smart_close_logs_captured_address_and_dispatch() {
    let harness = Harness::new("smart-close-log");
    let close_log = harness.runtime_dir.join("close-events.jsonl");
    let hypr = HyprServer::start_with_response(
        &harness.runtime_dir,
        &harness.hypr_sig,
        "Window abc123 -> test window:\nclass: kitty\ntitle: work terminal\npid: 4242\nfocusHistoryID: 0\n",
    );

    let mut envs = harness.envs();
    envs.push((
        "HYPR_CLOSE_LOG".to_string(),
        close_log.display().to_string(),
    ));
    run_binary("hypr-smart-close", &[], &envs);

    let requests = wait_for_request(&hypr, "dispatch closewindow address:0xabc123");
    assert!(
        requests
            .iter()
            .any(|request| request == "dispatch closewindow address:0xabc123"),
        "expected exact Hypr closewindow dispatch, got {requests:?}"
    );

    let events = fs::read_to_string(&close_log).expect("close log should be written");
    let mode = fs::metadata(&close_log)
        .expect("close log metadata should be readable")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    assert!(events.contains("\"event\":\"invoked\""), "{events}");
    assert!(events.contains("\"event\":\"active_captured\""), "{events}");
    assert!(
        events.contains("\"event\":\"dispatch_closewindow\""),
        "{events}"
    );
    assert!(events.contains("\"address\":\"0xabc123\""), "{events}");
    assert!(events.contains("\"title\":\"work terminal\""), "{events}");
    assert!(events.contains("\"focus_history_id\":0"), "{events}");
}

#[test]
fn hypr_smart_close_truncates_large_explicit_close_log() {
    let harness = Harness::new("sc-log-cap");
    let close_log = harness.runtime_dir.join("close-events.jsonl");
    fs::write(&close_log, vec![b'x'; 1024 * 1024 + 1]).expect("large log should be seeded");
    let hypr = HyprServer::start(
        &harness.runtime_dir,
        &harness.hypr_sig,
        "kitty",
        std::process::id(),
    );

    let mut envs = harness.envs();
    envs.push((
        "HYPR_CLOSE_LOG".to_string(),
        close_log.display().to_string(),
    ));

    run_binary("hypr-smart-close", &[], &envs);

    let requests = wait_for_request(&hypr, "dispatch closewindow address:0xabc123");
    assert!(
        requests
            .iter()
            .any(|request| request == "dispatch closewindow address:0xabc123"),
        "expected exact Hypr closewindow dispatch, got {requests:?}"
    );
    let metadata = fs::metadata(&close_log).expect("close log metadata should be readable");
    assert!(
        metadata.len() < 8192,
        "oversized close log should be truncated before append"
    );
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let events = fs::read_to_string(&close_log).expect("close log should be readable");
    assert!(events.contains("\"event\":\"invoked\""), "{events}");
    assert!(
        events.contains("\"event\":\"dispatch_closewindow\""),
        "{events}"
    );
    assert!(
        !events.starts_with('x'),
        "old oversized log contents should be truncated"
    );
}

#[test]
fn hypr_smart_close_respects_disabled_close_log_value() {
    let harness = Harness::new("sc-log-off");
    let default_log = harness.runtime_dir.join("hypr-close/events.jsonl");
    let hypr = HyprServer::start(
        &harness.runtime_dir,
        &harness.hypr_sig,
        "kitty",
        std::process::id(),
    );

    let mut envs = harness.envs();
    envs.push((
        "XDG_STATE_HOME".to_string(),
        harness.runtime_dir.display().to_string(),
    ));
    envs.push(("HYPR_CLOSE_LOG".to_string(), "off".to_string()));

    run_binary("hypr-smart-close", &[], &envs);

    let requests = wait_for_request(&hypr, "dispatch closewindow address:0xabc123");
    assert!(
        requests
            .iter()
            .any(|request| request == "dispatch closewindow address:0xabc123"),
        "expected exact Hypr closewindow dispatch, got {requests:?}"
    );
    assert!(
        !default_log.exists(),
        "disabled logging should not fall back"
    );
}

#[test]
fn hypr_smart_close_logs_failed_hypr_dispatch_and_exits_nonzero() {
    let harness = Harness::new("sc-dfail");
    let close_log = harness.runtime_dir.join("close-events.jsonl");
    let hypr = HyprServer::start_with_response_then_stop(
        &harness.runtime_dir,
        &harness.hypr_sig,
        "Window abc123 -> test window:\nclass: brave-browser\npid: 4242\n",
    );

    let mut envs = harness.envs();
    envs.push((
        "HYPR_CLOSE_LOG".to_string(),
        close_log.display().to_string(),
    ));

    let status = run_binary_status("hypr-smart-close", &[], &envs);

    assert!(
        !status.success(),
        "failed Hypr dispatch should exit non-zero"
    );
    assert_eq!(hypr.requests(), vec!["activewindow".to_string()]);
    let events = fs::read_to_string(&close_log).expect("close log should be written");
    assert!(
        events.contains("\"event\":\"dispatch_closewindow_failed\""),
        "{events}"
    );
    assert!(
        !events.contains("\"event\":\"dispatch_closewindow\","),
        "{events}"
    );
}

#[test]
fn hypr_smart_close_closes_captured_non_terminal_window() {
    let harness = Harness::new("sc-nonterm");
    let hypr = HyprServer::start(
        &harness.runtime_dir,
        &harness.hypr_sig,
        "brave-browser",
        std::process::id(),
    );

    let envs = harness.envs();
    run_binary("hypr-smart-close", &[], &envs);

    let requests = wait_for_request(&hypr, "dispatch closewindow address:0xabc123");
    assert!(
        requests
            .iter()
            .any(|request| request == "dispatch closewindow address:0xabc123"),
        "expected exact Hypr closewindow dispatch, got {requests:?}"
    );
    assert!(
        !requests
            .iter()
            .any(|request| request == "dispatch killactive"),
        "expected no Hypr killactive dispatch, got {requests:?}"
    );
}

#[test]
fn hypr_smart_close_rejects_unexpected_args_without_acting() {
    let harness = Harness::new("smart-close-args");
    let hypr = HyprServer::start(
        &harness.runtime_dir,
        &harness.hypr_sig,
        "kitty",
        std::process::id(),
    );

    let envs = harness.envs();
    let status = run_binary_status("hypr-smart-close", &["--dry-run"], &envs);

    assert!(!status.success(), "unexpected args should fail closed");
    assert!(
        hypr.requests().is_empty(),
        "unexpected args must not query or dispatch Hyprland"
    );
    assert!(harness.log_contents().is_empty());
}

#[test]
fn hypr_smart_close_fails_closed_when_active_window_identity_is_incomplete() {
    let harness = Harness::new("sc-bad-active");
    let hypr = HyprServer::start_with_response(
        &harness.runtime_dir,
        &harness.hypr_sig,
        "class: kitty\npid: 123\n",
    );

    let envs = harness.envs();
    let status = run_binary_status("hypr-smart-close", &[], &envs);

    assert!(
        !status.success(),
        "incomplete activewindow data should fail closed"
    );
    let requests = hypr.requests();
    assert!(requests.iter().any(|request| request == "activewindow"));
    assert!(
        !requests
            .iter()
            .any(|request| request.starts_with("dispatch ")),
        "incomplete activewindow data must not dispatch, got {requests:?}"
    );
}

#[test]
fn hypr_smart_close_fails_closed_when_tmux_target_is_ambiguous() {
    let harness = Harness::new("sc-tmux-ambig");
    let pid_file = harness.runtime_dir.join("terminal.pid");
    let pty = PtyProcess::spawn(&pid_file, &[("TMUX", "/tmp/fake-tmux,4242,0")]);
    let hypr = HyprServer::start(&harness.runtime_dir, &harness.hypr_sig, "termstub", pty.pid);

    let mut envs = harness.envs();
    envs.push(("TERMINAL".to_string(), "termstub".to_string()));

    let status = run_binary_status("hypr-smart-close", &[], &envs);

    assert!(
        !status.success(),
        "ambiguous tmux state should fail closed rather than close a window"
    );
    let requests = hypr.requests();
    assert!(requests.iter().any(|request| request == "activewindow"));
    assert!(
        !requests
            .iter()
            .any(|request| request.starts_with("dispatch ")),
        "ambiguous tmux state must not dispatch, got {requests:?}"
    );
}

#[test]
fn hypr_tmux_nav_prefers_nvim_before_tmux_and_hypr() {
    let harness = Harness::new("nvim-precedence");
    let nvim_socket = harness.runtime_dir.join("nvim.sock");
    let _nvim_listener = UnixListener::bind(&nvim_socket).expect("nvim socket should bind");

    let pid_file = harness.runtime_dir.join("terminal.pid");
    let nvim_socket_str = nvim_socket.display().to_string();
    let pty = PtyProcess::spawn(
        &pid_file,
        &[
            ("NVIM", &nvim_socket_str),
            ("TMUX", "/tmp/fake-tmux,4242,0"),
        ],
    );
    let hypr = HyprServer::start(&harness.runtime_dir, &harness.hypr_sig, "termstub", pty.pid);

    let tty = fs::read_link(format!("/proc/{}/fd/0", pty.pid))
        .expect("pty tty should be readable")
        .display()
        .to_string();

    let mut envs = harness.envs();
    envs.push(("TERMINAL".to_string(), "termstub".to_string()));
    envs.push(("TEST_TTY".to_string(), tty));
    envs.push(("TEST_NVIM_AT_EDGE".to_string(), "0".to_string()));
    envs.push(("TEST_NVIM_SEND_OK".to_string(), "1".to_string()));

    run_binary("hypr-tmux-nav", &["left"], &envs);

    wait_for_log_line(&harness.log_path, "nvim --server");
    let log = harness.log_contents();
    assert!(
        log.contains("--remote-send <C-w>h"),
        "expected nvim navigation, got {log}"
    );
    assert!(
        !log.contains("tmux select-pane"),
        "expected tmux not to be used when nvim handled navigation: {log}"
    );
    let requests = hypr.requests();
    assert!(
        !requests
            .iter()
            .any(|request| request.starts_with("dispatch ")),
        "expected no Hypr fallback dispatch, got {requests:?}"
    );
}

#[test]
fn hypr_tmux_nav_falls_back_to_tmux_before_hypr() {
    let harness = Harness::new("tmux-precedence");
    let nvim_socket = harness.runtime_dir.join("nvim.sock");
    let _nvim_listener = UnixListener::bind(&nvim_socket).expect("nvim socket should bind");

    let pid_file = harness.runtime_dir.join("terminal.pid");
    let nvim_socket_str = nvim_socket.display().to_string();
    let pty = PtyProcess::spawn(
        &pid_file,
        &[
            ("NVIM", &nvim_socket_str),
            ("TMUX", "/tmp/fake-tmux,4242,0"),
        ],
    );
    let hypr = HyprServer::start(&harness.runtime_dir, &harness.hypr_sig, "termstub", pty.pid);

    let tty = fs::read_link(format!("/proc/{}/fd/0", pty.pid))
        .expect("pty tty should be readable")
        .display()
        .to_string();

    let mut envs = harness.envs();
    envs.push(("TERMINAL".to_string(), "termstub".to_string()));
    envs.push(("TEST_TTY".to_string(), tty));
    envs.push(("TEST_NVIM_AT_EDGE".to_string(), "1".to_string()));
    envs.push(("TEST_TMUX_AT_EDGE".to_string(), "0".to_string()));
    envs.push(("TEST_TMUX_SELECT_OK".to_string(), "1".to_string()));

    run_binary("hypr-tmux-nav", &["right"], &envs);

    let log = harness.log_contents();
    assert!(
        log.contains("tmux select-pane -t %1 -R"),
        "expected tmux navigation, got {log}"
    );
    let requests = hypr.requests();
    assert!(
        !requests
            .iter()
            .any(|request| request.starts_with("dispatch ")),
        "expected no Hypr fallback dispatch, got {requests:?}"
    );
}

#[test]
fn hypr_tmux_nav_falls_back_to_hypr_when_tmux_cannot_move() {
    let harness = Harness::new("hypr-fallback");
    let pid_file = harness.runtime_dir.join("terminal.pid");
    let pty = PtyProcess::spawn(&pid_file, &[("TMUX", "/tmp/fake-tmux,4242,0")]);
    let hypr = HyprServer::start(&harness.runtime_dir, &harness.hypr_sig, "termstub", pty.pid);

    let tty = fs::read_link(format!("/proc/{}/fd/0", pty.pid))
        .expect("pty tty should be readable")
        .display()
        .to_string();

    let mut envs = harness.envs();
    envs.push(("TERMINAL".to_string(), "termstub".to_string()));
    envs.push(("TEST_TTY".to_string(), tty));
    envs.push(("TEST_TMUX_AT_EDGE".to_string(), "1".to_string()));

    run_binary("hypr-tmux-nav", &["down"], &envs);

    let requests = wait_for_request(&hypr, "dispatch movefocus d");
    assert!(
        requests
            .iter()
            .any(|request| request == "dispatch movefocus d"),
        "expected Hypr fallback dispatch, got {requests:?}"
    );
}

#[test]
fn hypr_tmux_nav_exits_nonzero_when_hypr_fallback_dispatch_fails() {
    let harness = Harness::new("tmux-dispatch-fail");
    let pid_file = harness.runtime_dir.join("terminal.pid");
    let pty = PtyProcess::spawn(&pid_file, &[("TMUX", "/tmp/fake-tmux,4242,0")]);
    let hypr = HyprServer::start_with_response_then_stop(
        &harness.runtime_dir,
        &harness.hypr_sig,
        &format!(
            "Window abc123 -> test window:\nclass: termstub\npid: {}\n",
            pty.pid
        ),
    );

    let tty = fs::read_link(format!("/proc/{}/fd/0", pty.pid))
        .expect("pty tty should be readable")
        .display()
        .to_string();

    let mut envs = harness.envs();
    envs.push(("TERMINAL".to_string(), "termstub".to_string()));
    envs.push(("TEST_TTY".to_string(), tty));
    envs.push(("TEST_TMUX_AT_EDGE".to_string(), "1".to_string()));

    let status = run_binary_status("hypr-tmux-nav", &["down"], &envs);

    assert!(
        !status.success(),
        "failed Hypr dispatch should exit non-zero"
    );
    assert_eq!(hypr.requests(), vec!["activewindow".to_string()]);
    let nav_state_exists = fs::read_dir(&harness.runtime_dir)
        .expect("runtime dir should be readable")
        .flatten()
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("hypr-nav-navstate")
        });
    assert!(
        !nav_state_exists,
        "failed Hypr fallback should not record successful navigation state"
    );
}
