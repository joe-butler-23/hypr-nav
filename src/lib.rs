use serde_json::Value;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Known terminal emulator window classes
pub const KNOWN_TERMINALS: &[&str] = &["kitty"];

pub struct TmuxRuntime {
    pub tty: String,
    pub socket_path: Option<String>,
}

enum KittyRuntimeProbe {
    Found(TmuxRuntime),
    NoTmux,
    Unavailable,
}

pub fn debug_enabled() -> bool {
    match env::var("HYPR_NAV_DEBUG") {
        Ok(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            !normalized.is_empty()
                && normalized != "0"
                && normalized != "false"
                && normalized != "off"
                && normalized != "no"
        }
        Err(_) => false,
    }
}

pub fn debug_log(component: &str, message: &str) {
    if debug_enabled() {
        eprintln!("[hypr-nav][{}] {}", component, message);
    }
}

/// Check if the window class represents a terminal emulator
pub fn is_terminal_class(class: &str) -> bool {
    // First, check $TERMINAL environment variable
    if let Ok(terminal) = env::var("TERMINAL") {
        // Extract binary name from path (e.g., /usr/bin/kitty -> kitty)
        let terminal_name = terminal
            .rsplit('/')
            .next()
            .unwrap_or(&terminal)
            .to_lowercase();
        if class.to_lowercase().contains(&terminal_name) {
            return true;
        }
    }

    // Fall back to known terminal list
    let class_lower = class.to_lowercase();
    KNOWN_TERMINALS
        .iter()
        .any(|t| class_lower.contains(&t.to_lowercase()))
}

fn read_process_comm(pid: u32) -> Option<String> {
    let comm = fs::read_to_string(format!("/proc/{}/comm", pid)).ok()?;
    Some(comm.trim().to_ascii_lowercase())
}

fn process_matches_terminal_name(pid: u32, terminal: &str) -> bool {
    if let Some(comm) = read_process_comm(pid) {
        if comm == terminal {
            return true;
        }
    }

    if let Ok(path) = fs::read_link(format!("/proc/{}/exe", pid)) {
        if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            if name.eq_ignore_ascii_case(terminal) {
                return true;
            }
        }
    }

    false
}

/// Check whether the active window is a terminal using both Hypr class and PID metadata.
pub fn is_terminal_window(class: &str, pid: u32) -> bool {
    if is_terminal_class(class) {
        return true;
    }

    KNOWN_TERMINALS
        .iter()
        .any(|terminal| process_matches_terminal_name(pid, terminal))
}

/// Find the Hyprland socket path
pub fn find_hyprland_socket() -> Option<PathBuf> {
    let xdg = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let sig = env::var("HYPRLAND_INSTANCE_SIGNATURE").ok()?;

    if sig.is_empty() {
        return None;
    }

    let hypr_dir = PathBuf::from(&xdg).join("hypr").join(&sig);
    let socket_names = [".socket.sock", "socket.sock"];

    for name in &socket_names {
        let path = hypr_dir.join(name);
        if path.exists() {
            if let Ok(meta) = fs::metadata(&path) {
                if meta.file_type().is_socket() {
                    debug_log("lib", &format!("hypr socket selected: {}", path.display()));
                    return Some(path);
                }
            }
        }
    }

    debug_log("lib", "no usable hypr socket found");
    None
}

/// Get active window class and PID in a single Hyprland query
pub fn get_active_window_info(socket_path: &PathBuf) -> Option<(String, u32)> {
    let mut stream = UnixStream::connect(socket_path).ok()?;
    stream.write_all(b"activewindow").ok()?;
    stream.shutdown(std::net::Shutdown::Write).ok()?;

    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;

    let mut class = None;
    let mut pid = None;

    for line in response.lines() {
        let trimmed = line.trim();
        if let Some(c) = trimmed.strip_prefix("class: ") {
            class = Some(c.trim().to_string());
        } else if let Some(p) = trimmed.strip_prefix("pid: ") {
            pid = p.trim().parse::<u32>().ok();
        }
        // Early exit if we have both
        if class.is_some() && pid.is_some() {
            break;
        }
    }

    match (class, pid) {
        (Some(c), Some(p)) => {
            debug_log("lib", &format!("active window class={} pid={}", c, p));
            Some((c, p))
        }
        _ => {
            debug_log("lib", "active window query returned incomplete data");
            None
        }
    }
}

fn parse_tmux_socket_from_value(tmux_value: &str) -> Option<String> {
    // TMUX format: "<socket_path>,<server_pid>,<session_id>"
    let mut parts = tmux_value.rsplitn(3, ',');
    let _session_id = parts.next()?;
    let _server_pid = parts.next()?;
    let socket_path = parts.next()?.trim();
    if socket_path.is_empty() {
        None
    } else {
        Some(socket_path.to_string())
    }
}

fn parse_tmux_socket_from_environ(environ: &[u8]) -> Option<String> {
    for entry in environ.split(|b| *b == 0) {
        if let Some(value) = entry.strip_prefix(b"TMUX=") {
            if let Ok(tmux_value) = std::str::from_utf8(value) {
                if let Some(socket_path) = parse_tmux_socket_from_value(tmux_value) {
                    return Some(socket_path);
                }
            }
        }
    }
    None
}

fn read_tmux_socket_from_environ(pid: u32) -> Option<String> {
    let environ = fs::read(format!("/proc/{}/environ", pid)).ok()?;
    parse_tmux_socket_from_environ(&environ)
}

fn read_process_tty(pid: u32) -> Option<String> {
    let link = fs::read_link(format!("/proc/{}/fd/0", pid)).ok()?;
    let tty = link.to_str()?.to_string();
    if tty.starts_with("/dev/pts/") {
        Some(tty)
    } else {
        None
    }
}

fn process_has_tmux(pid: u32) -> bool {
    if let Ok(cmdline) = fs::read_to_string(format!("/proc/{}/cmdline", pid)) {
        let cmd = cmdline.replace('\0', " ");
        return cmd.contains("tmux") && !cmd.contains("hypr-tmux-nav");
    }
    false
}

fn kitty_socket_path() -> PathBuf {
    let xdg = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(xdg).join("kitty")
}

fn find_focused_index(items: &[Value]) -> usize {
    items
        .iter()
        .position(|item| {
            item.get("is_focused")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .unwrap_or(0)
}

fn read_pids_from_kitty_window(window: &Value) -> Vec<u32> {
    let mut pids = Vec::new();
    let mut seen = HashSet::new();

    if let Some(procs) = window.get("foreground_processes").and_then(Value::as_array) {
        for proc_info in procs {
            if let Some(pid) = proc_info.get("pid").and_then(Value::as_u64) {
                if let Ok(pid_u32) = u32::try_from(pid) {
                    if seen.insert(pid_u32) {
                        pids.push(pid_u32);
                    }
                }
            }
        }
    }

    if let Some(pid) = window.get("pid").and_then(Value::as_u64) {
        if let Ok(pid_u32) = u32::try_from(pid) {
            if seen.insert(pid_u32) {
                pids.push(pid_u32);
            }
        }
    }

    pids
}

fn parse_focused_kitty_pids(json: &str) -> Vec<u32> {
    let parsed: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let os_windows = match parsed.as_array() {
        Some(v) if !v.is_empty() => v,
        _ => return Vec::new(),
    };
    let os_window = &os_windows[find_focused_index(os_windows)];

    let tabs = match os_window.get("tabs").and_then(Value::as_array) {
        Some(v) if !v.is_empty() => v,
        _ => return Vec::new(),
    };
    let tab = &tabs[find_focused_index(tabs)];

    let windows = match tab.get("windows").and_then(Value::as_array) {
        Some(v) if !v.is_empty() => v,
        _ => return Vec::new(),
    };
    let window = &windows[find_focused_index(windows)];

    read_pids_from_kitty_window(window)
}

fn detect_tmux_runtime_from_kitty() -> KittyRuntimeProbe {
    let kitty_socket = kitty_socket_path();
    if !kitty_socket.exists() {
        return KittyRuntimeProbe::Unavailable;
    }

    let kitty_uri = format!("unix:{}", kitty_socket.display());
    let output = Command::new("kitty")
        .args(["@", "--to", &kitty_uri, "ls"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok();

    let output = match output {
        Some(out) => out,
        None => {
            debug_log(
                "lib",
                "kitty ls failed while resolving focused kitty context",
            );
            return KittyRuntimeProbe::Unavailable;
        }
    };

    if !output.status.success() {
        debug_log(
            "lib",
            "kitty ls failed while resolving focused kitty context",
        );
        return KittyRuntimeProbe::Unavailable;
    }

    let parsed = String::from_utf8_lossy(&output.stdout);
    let candidate_pids = parse_focused_kitty_pids(&parsed);
    if candidate_pids.is_empty() {
        debug_log(
            "lib",
            "kitty ls returned no focused foreground pid candidates",
        );
        return KittyRuntimeProbe::Unavailable;
    }

    for pid in candidate_pids {
        let tty = read_process_tty(pid);
        let tmux_socket = read_tmux_socket_from_environ(pid);
        let has_tmux = tmux_socket.is_some() || process_has_tmux(pid);
        debug_log(
            "lib",
            &format!(
                "kitty-focused candidate pid={} tty={} tmux_socket={} has_tmux={}",
                pid,
                tty.as_deref().unwrap_or("<none>"),
                tmux_socket.as_deref().unwrap_or("<none>"),
                has_tmux
            ),
        );

        if has_tmux {
            if let Some(tty) = tty {
                return KittyRuntimeProbe::Found(TmuxRuntime {
                    tty,
                    socket_path: tmux_socket,
                });
            }
        }
    }

    debug_log(
        "lib",
        "kitty-focused context found but no tmux in focused window",
    );
    KittyRuntimeProbe::NoTmux
}

/// Combined detection: find TTY, tmux presence, and tmux socket from process tree.
pub fn detect_tmux_runtime(pid: u32, class: &str) -> Option<TmuxRuntime> {
    let kitty_by_class = class.to_ascii_lowercase().contains("kitty");
    let kitty_by_pid = process_matches_terminal_name(pid, "kitty");
    if kitty_by_class || kitty_by_pid {
        if kitty_by_pid && !kitty_by_class {
            debug_log(
                "lib",
                &format!(
                    "active pid={} is kitty with custom class={} ; using kitty-focused probe",
                    pid, class
                ),
            );
        }
        match detect_tmux_runtime_from_kitty() {
            KittyRuntimeProbe::Found(runtime) => {
                debug_log(
                    "lib",
                    &format!(
                        "tmux runtime from kitty tty={} socket={}",
                        runtime.tty,
                        runtime.socket_path.as_deref().unwrap_or("<default>")
                    ),
                );
                return Some(runtime);
            }
            KittyRuntimeProbe::NoTmux => {
                debug_log("lib", "kitty-focused probe confirms no tmux");
                return None;
            }
            KittyRuntimeProbe::Unavailable => {}
        }
    }

    let mut tty: Option<String> = None;
    let mut has_tmux = false;
    let mut socket_path: Option<String> = None;

    // BFS through process tree (downward) to find both TTY and tmux
    const MAX_DEPTH: usize = 10;
    let mut to_check: Vec<(u32, usize)> = vec![(pid, 0)];
    let mut checked: HashSet<u32> = HashSet::new();

    while let Some((current_pid, depth)) = to_check.pop() {
        if checked.contains(&current_pid) || depth > MAX_DEPTH {
            continue;
        }
        checked.insert(current_pid);

        let current_tty = read_process_tty(current_pid);

        // Check for TTY on this process
        if tty.is_none() {
            tty = current_tty.clone();
        }

        // Check if this process is tmux
        if !has_tmux {
            has_tmux = process_has_tmux(current_pid);
        }

        if socket_path.is_none() {
            socket_path = read_tmux_socket_from_environ(current_pid);
            if socket_path.is_some() {
                has_tmux = true;
                if current_tty.is_some() {
                    tty = current_tty.clone();
                }
            }
        }

        // Early exit if we found everything useful
        if tty.is_some() && has_tmux && socket_path.is_some() {
            break;
        }

        // Get children - try fast path first
        let children_path = format!("/proc/{}/task/{}/children", current_pid, current_pid);
        if let Ok(children) = fs::read_to_string(&children_path) {
            for child_str in children.split_whitespace() {
                if let Ok(child_pid) = child_str.parse::<u32>() {
                    to_check.push((child_pid, depth + 1));
                }
            }
        }
    }

    if !has_tmux {
        debug_log("lib", &format!("no tmux runtime under pid {}", pid));
        return None;
    }

    let runtime = tty.map(|tty| TmuxRuntime { tty, socket_path });
    if let Some(r) = runtime.as_ref() {
        debug_log(
            "lib",
            &format!(
                "tmux runtime tty={} socket={}",
                r.tty,
                r.socket_path.as_deref().unwrap_or("<default>")
            ),
        );
    } else {
        debug_log("lib", "tmux detected but tty missing");
    }
    runtime
}

fn tmux_command(socket_path: Option<&str>) -> Command {
    let mut command = Command::new("tmux");
    if let Some(path) = socket_path.filter(|path| !path.is_empty()) {
        command.args(["-S", path]);
    }
    command
}

/// Find the tmux session for a given TTY
pub fn find_tmux_session(tty: &str, socket_path: Option<&str>) -> Option<String> {
    // Single tmux call to get all client info
    let output = tmux_command(socket_path)
        .args(["list-clients", "-F", "#{client_session} #{client_tty}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        debug_log(
            "lib",
            &format!(
                "find_tmux_session tty={} socket={} -> <none> (tmux error)",
                tty,
                socket_path.unwrap_or("<default>")
            ),
        );
        return None;
    }

    let clients = String::from_utf8_lossy(&output.stdout);
    let session = parse_tmux_client_session(&clients, tty);
    debug_log(
        "lib",
        &format!(
            "find_tmux_session tty={} socket={} -> {}",
            tty,
            socket_path.unwrap_or("<default>"),
            session.as_deref().unwrap_or("<none>")
        ),
    );
    session
}

fn parse_tmux_client_session(clients: &str, tty: &str) -> Option<String> {
    for line in clients.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let session = parts[0];
            let client_tty = parts[1];

            // Exact TTY match
            if tty == client_tty {
                return Some(session.to_string());
            }
        }
    }

    None
}

fn parse_tmux_client_pane(clients: &str, tty: &str) -> Option<String> {
    for line in clients.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let client_tty = parts[0];
        let pane_id = parts[1];
        if client_tty == tty {
            return Some(pane_id.to_string());
        }
    }
    None
}

fn parse_tmux_pane_by_tty(panes: &str, tty: &str) -> Option<String> {
    for line in panes.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let pane_tty = parts[0];
        let pane_id = parts[1];
        if pane_tty == tty {
            return Some(pane_id.to_string());
        }
    }
    None
}

fn parse_tmux_session_by_pane_tty(panes: &str, tty: &str) -> Option<String> {
    for line in panes.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let pane_tty = parts[0];
        let session_id = parts[1];
        if pane_tty == tty {
            return Some(session_id.to_string());
        }
    }
    None
}

/// Find the active tmux pane for a given client TTY
pub fn find_tmux_client_pane(tty: &str, socket_path: Option<&str>) -> Option<String> {
    let output = tmux_command(socket_path)
        .args(["list-clients", "-F", "#{client_tty} #{pane_id}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        debug_log(
            "lib",
            &format!(
                "find_tmux_client_pane tty={} socket={} -> <none> (tmux error)",
                tty,
                socket_path.unwrap_or("<default>")
            ),
        );
        return None;
    }

    let clients = String::from_utf8_lossy(&output.stdout);
    let pane = parse_tmux_client_pane(&clients, tty);
    debug_log(
        "lib",
        &format!(
            "find_tmux_client_pane tty={} socket={} -> {}",
            tty,
            socket_path.unwrap_or("<default>"),
            pane.as_deref().unwrap_or("<none>")
        ),
    );
    pane
}

/// Find pane by pane tty when we discovered a pane PTY rather than client TTY.
pub fn find_tmux_pane_by_tty(tty: &str, socket_path: Option<&str>) -> Option<String> {
    let output = tmux_command(socket_path)
        .args(["list-panes", "-a", "-F", "#{pane_tty} #{pane_id}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        debug_log(
            "lib",
            &format!(
                "find_tmux_pane_by_tty tty={} socket={} -> <none> (tmux error)",
                tty,
                socket_path.unwrap_or("<default>")
            ),
        );
        return None;
    }

    let panes = String::from_utf8_lossy(&output.stdout);
    let pane = parse_tmux_pane_by_tty(&panes, tty);
    debug_log(
        "lib",
        &format!(
            "find_tmux_pane_by_tty tty={} socket={} -> {}",
            tty,
            socket_path.unwrap_or("<default>"),
            pane.as_deref().unwrap_or("<none>")
        ),
    );
    pane
}

/// Find session by pane tty when we discovered a pane PTY rather than client TTY.
pub fn find_tmux_session_by_pane_tty(tty: &str, socket_path: Option<&str>) -> Option<String> {
    let output = tmux_command(socket_path)
        .args(["list-panes", "-a", "-F", "#{pane_tty} #{session_id}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        debug_log(
            "lib",
            &format!(
                "find_tmux_session_by_pane_tty tty={} socket={} -> <none> (tmux error)",
                tty,
                socket_path.unwrap_or("<default>")
            ),
        );
        return None;
    }

    let panes = String::from_utf8_lossy(&output.stdout);
    let session = parse_tmux_session_by_pane_tty(&panes, tty);
    debug_log(
        "lib",
        &format!(
            "find_tmux_session_by_pane_tty tty={} socket={} -> {}",
            tty,
            socket_path.unwrap_or("<default>"),
            session.as_deref().unwrap_or("<none>")
        ),
    );
    session
}

/// Check if the active pane in the session is at the edge in the given direction
pub fn is_pane_at_edge(session: &str, direction: &str, socket_path: Option<&str>) -> bool {
    let flag = match direction {
        "L" => "#{pane_at_left}",
        "R" => "#{pane_at_right}",
        "U" => "#{pane_at_top}",
        "D" => "#{pane_at_bottom}",
        _ => return false,
    };

    let output = tmux_command(socket_path)
        .args(["display-message", "-t", session, "-p", flag])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let result = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let at_edge = result == "1";
            debug_log(
                "lib",
                &format!(
                    "is_pane_at_edge target={} dir={} socket={} -> {}",
                    session,
                    direction,
                    socket_path.unwrap_or("<default>"),
                    at_edge
                ),
            );
            return at_edge;
        }
    }
    debug_log(
        "lib",
        &format!(
            "is_pane_at_edge target={} dir={} socket={} -> false (tmux error)",
            session,
            direction,
            socket_path.unwrap_or("<default>")
        ),
    );
    false
}

pub struct TmuxSessionInfo {
    pub name: String,
    pub is_named: bool,
    pub window_count: usize,
    pub pane_count: usize,
}

pub fn get_tmux_session_info(session: &str, socket_path: Option<&str>) -> Option<TmuxSessionInfo> {
    // Format: #{session_name} #{window_panes} #{session_windows}
    let output = tmux_command(socket_path)
        .args([
            "display-message",
            "-t",
            session,
            "-p",
            "#{session_name} #{window_panes} #{session_windows}",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        debug_log(
            "lib",
            &format!(
                "get_tmux_session_info target={} socket={} -> <none> (tmux error)",
                session,
                socket_path.unwrap_or("<default>")
            ),
        );
        return None;
    }

    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let parts: Vec<&str> = result.split_whitespace().collect();
    if parts.len() >= 3 {
        let name = parts[0].to_string();
        let pane_count = parts[1].parse().unwrap_or(1);
        let window_count = parts[2].parse().unwrap_or(1);

        let is_named = name.parse::<u32>().is_err();

        let info = TmuxSessionInfo {
            name,
            is_named,
            window_count,
            pane_count,
        };
        debug_log(
            "lib",
            &format!(
                "session_info target={} socket={} name={} named={} panes={} windows={}",
                session,
                socket_path.unwrap_or("<default>"),
                info.name,
                info.is_named,
                info.pane_count,
                info.window_count
            ),
        );
        Some(info)
    } else {
        debug_log(
            "lib",
            &format!(
                "get_tmux_session_info target={} socket={} -> <none> (parse error)",
                session,
                socket_path.unwrap_or("<default>")
            ),
        );
        None
    }
}

pub fn hypr_dispatch(socket_path: &PathBuf, dispatcher: &str) {
    if let Ok(mut stream) = UnixStream::connect(socket_path) {
        let cmd = format!("dispatch {}", dispatcher);
        debug_log("lib", &format!("hypr dispatch: {}", cmd));
        let _ = stream.write_all(cmd.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tmux_client_pane_matches_exact_tty() {
        let data = "/dev/pts/2 %11\n/dev/pts/9 %42\n";
        assert_eq!(
            parse_tmux_client_pane(data, "/dev/pts/9"),
            Some("%42".to_string())
        );
    }

    #[test]
    fn parse_tmux_client_pane_ignores_malformed_lines() {
        let data = "invalid-line\n/dev/pts/5 %7\n";
        assert_eq!(
            parse_tmux_client_pane(data, "/dev/pts/5"),
            Some("%7".to_string())
        );
    }

    #[test]
    fn parse_tmux_client_pane_returns_none_when_tty_missing() {
        let data = "/dev/pts/2 %11\n/dev/pts/9 %42\n";
        assert_eq!(parse_tmux_client_pane(data, "/dev/pts/4"), None);
    }

    #[test]
    fn parse_tmux_client_session_prefers_exact_tty_match() {
        let data = "$0 /dev/pts/2\n$1 /dev/pts/9\n";
        assert_eq!(
            parse_tmux_client_session(data, "/dev/pts/9"),
            Some("$1".to_string())
        );
    }

    #[test]
    fn parse_tmux_client_session_returns_none_without_exact_tty_match() {
        let data = "$3 /dev/pts/1\n$3 /dev/pts/5\n";
        assert_eq!(parse_tmux_client_session(data, "/dev/pts/99"), None);
    }

    #[test]
    fn parse_tmux_socket_from_value_extracts_socket_path() {
        let value = "/tmp/tmux-1000/custom,41204,7";
        assert_eq!(
            parse_tmux_socket_from_value(value),
            Some("/tmp/tmux-1000/custom".to_string())
        );
    }

    #[test]
    fn parse_tmux_socket_from_environ_finds_tmux_entry() {
        let env = b"SHELL=/bin/zsh\0TMUX=/tmp/tmux-1000/default,1234,0\0";
        assert_eq!(
            parse_tmux_socket_from_environ(env),
            Some("/tmp/tmux-1000/default".to_string())
        );
    }

    #[test]
    fn parse_tmux_socket_from_environ_ignores_missing_tmux_entry() {
        let env = b"SHELL=/bin/zsh\0PATH=/usr/bin\0";
        assert_eq!(parse_tmux_socket_from_environ(env), None);
    }

    #[test]
    fn parse_tmux_pane_by_tty_matches_exact_tty() {
        let data = "/dev/pts/12 %3\n/dev/pts/13 %4\n";
        assert_eq!(
            parse_tmux_pane_by_tty(data, "/dev/pts/13"),
            Some("%4".to_string())
        );
    }

    #[test]
    fn parse_tmux_session_by_pane_tty_matches_exact_tty() {
        let data = "/dev/pts/12 $3\n/dev/pts/13 $4\n";
        assert_eq!(
            parse_tmux_session_by_pane_tty(data, "/dev/pts/12"),
            Some("$3".to_string())
        );
    }

    #[test]
    fn parse_focused_kitty_pids_prefers_focused_os_window_tab_and_window() {
        let data = r#"
[
  {
    "is_focused": false,
    "tabs": [
      {"is_focused": true, "windows": [{"is_focused": true, "pid": 999}]}
    ]
  },
  {
    "is_focused": true,
    "tabs": [
      {
        "is_focused": true,
        "windows": [
          {
            "is_focused": false,
            "pid": 1000
          },
          {
            "is_focused": true,
            "pid": 2000,
            "foreground_processes": [{"pid": 2001}, {"pid": 2002}]
          }
        ]
      }
    ]
  }
]
"#;

        assert_eq!(parse_focused_kitty_pids(data), vec![2001, 2002, 2000]);
    }

    #[test]
    fn parse_focused_kitty_pids_returns_empty_on_invalid_json() {
        assert!(parse_focused_kitty_pids("not-json").is_empty());
    }
}
