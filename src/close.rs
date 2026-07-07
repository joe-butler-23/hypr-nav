use hypr_nav_lib::debug_log;
use hypr_nav_lib::*;
use serde_json::{json, Value};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

const CLOSE_LOG_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
enum TmuxCloseAction {
    DetachClient(String),
    KillPane(String),
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 1 {
        eprintln!("usage: hypr-smart-close");
        std::process::exit(2);
    }

    log_close_event("invoked", json!({ "argv": args }));
    let hypr_socket = match find_hyprland_socket() {
        Some(path) => path,
        None => {
            log_close_event("no_hypr_socket", json!({}));
            std::process::exit(1);
        }
    };
    debug_log!("smart-close", "invoked");

    let active = match get_active_window_snapshot(&hypr_socket) {
        Some(info) => info,
        None => {
            log_close_event("active_window_unavailable", json!({}));
            std::process::exit(1);
        }
    };
    log_close_event("active_captured", active_window_json(&active));

    if let Some(runtime) = active_herdr_runtime(&active) {
        match herdr_host_close(&runtime) {
            Some(HerdrCloseOutcome::ClosePane | HerdrCloseOutcome::CloseTab) => {
                debug_log!("smart-close", "herdr host close handled");
                log_close_event(
                    "herdr_close_handled",
                    json!({
                        "active": active_window_json(&active),
                        "socket": runtime.socket_path,
                        "session": runtime.session,
                    }),
                );
                return;
            }
            Some(HerdrCloseOutcome::CloseHost) => {
                debug_log!("smart-close", "herdr host requested outer window close");
                log_close_event(
                    "herdr_close_host",
                    json!({
                        "active": active_window_json(&active),
                        "socket": runtime.socket_path,
                        "session": runtime.session,
                    }),
                );
            }
            Some(HerdrCloseOutcome::Noop) => {
                debug_log!("smart-close", "herdr host close returned noop");
                log_close_event(
                    "herdr_close_noop",
                    json!({
                        "active": active_window_json(&active),
                        "socket": runtime.socket_path,
                        "session": runtime.session,
                    }),
                );
                return;
            }
            None => {
                debug_log!(
                    "smart-close",
                    "herdr runtime detected but host.close failed"
                );
                log_close_event(
                    "herdr_close_failed",
                    json!({
                        "active": active_window_json(&active),
                        "socket": runtime.socket_path,
                        "session": runtime.session,
                    }),
                );
                std::process::exit(1);
            }
        }
    }

    if is_terminal_window(&active.class, active.pid) {
        if is_kitty_window(&active.class, active.pid) {
            debug_log!(
                "smart-close",
                "kitty active class={} pid={}; closing captured hypr address={}",
                active.class,
                active.pid,
                active.address
            );
        } else {
            debug_log!(
                "smart-close",
                "terminal active class={} pid={}",
                active.class,
                active.pid
            );
            if let Some(runtime) = detect_tmux_runtime(active.pid, &active.class) {
                let socket_path = runtime.socket_path.as_deref();
                let pane = find_tmux_client_pane(&runtime.tty, socket_path)
                    .or_else(|| find_tmux_pane_by_tty(&runtime.tty, socket_path));
                if let Some(session) = find_tmux_session(&runtime.tty, socket_path)
                    .or_else(|| find_tmux_session_by_pane_tty(&runtime.tty, socket_path))
                {
                    debug_log!(
                        "smart-close",
                        "resolved tmux session target={} pane={}",
                        session,
                        pane.as_deref().unwrap_or("<none>")
                    );
                    if handle_tmux_close(&session, pane.as_deref(), &runtime.tty, socket_path) {
                        debug_log!("smart-close", "tmux close handled");
                        log_close_event(
                            "tmux_close_handled",
                            json!({
                                "active": active_window_json(&active),
                                "session": session,
                                "pane": pane,
                                "tty": runtime.tty,
                                "socket": socket_path,
                            }),
                        );
                        return;
                    }
                    debug_log!(
                        "smart-close",
                        "tmux close handling failed; refusing unsafe window fallback"
                    );
                    log_close_event(
                        "tmux_close_failed",
                        json!({
                            "active": active_window_json(&active),
                            "session": session,
                            "pane": pane,
                            "tty": runtime.tty,
                            "socket": socket_path,
                        }),
                    );
                    std::process::exit(1);
                } else {
                    debug_log!("smart-close", "tmux runtime detected but no session target resolved; refusing unsafe window fallback");
                    log_close_event(
                        "tmux_target_unresolved",
                        json!({
                            "active": active_window_json(&active),
                            "tty": runtime.tty,
                            "socket": runtime.socket_path,
                        }),
                    );
                    std::process::exit(1);
                }
            } else {
                debug_log!(
                    "smart-close",
                    "terminal active but no tmux runtime detected"
                );
            }
        }
    } else {
        debug_log!("smart-close", "non-terminal active class={}", active.class);
    }

    debug_log!(
        "smart-close",
        "closing captured hypr address={}",
        active.address
    );
    let action = HyprDispatch::CloseWindow(active.address.clone());
    let dispatcher = action.lua_payload();
    if hypr_dispatch_action(&hypr_socket, &action) {
        log_close_event(
            "dispatch_closewindow",
            json!({
                "active": active_window_json(&active),
                "dispatcher": dispatcher,
            }),
        );
    } else {
        log_close_event(
            "dispatch_closewindow_failed",
            json!({
                "active": active_window_json(&active),
                "dispatcher": dispatcher,
            }),
        );
        std::process::exit(1);
    }
}

fn active_window_json(active: &ActiveWindowInfo) -> serde_json::Value {
    json!({
        "address": &active.address,
        "class": &active.class,
        "pid": active.pid,
        "title": &active.title,
        "focus_history_id": active.focus_history_id,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HerdrCloseOutcome {
    ClosePane,
    CloseTab,
    CloseHost,
    Noop,
}

fn active_herdr_runtime(active: &ActiveWindowInfo) -> Option<HerdrRuntime> {
    detect_herdr_runtime(active.pid, &active.class)
}

fn herdr_host_close(runtime: &HerdrRuntime) -> Option<HerdrCloseOutcome> {
    let response = herdr_request(runtime, "hypr-close:host:close", "host.close", json!({}))?;
    parse_herdr_host_close_response(&response)
}

fn parse_herdr_host_close_response(value: &Value) -> Option<HerdrCloseOutcome> {
    match value.pointer("/result/close/action")?.as_str()? {
        "close_pane" => Some(HerdrCloseOutcome::ClosePane),
        "close_tab" => Some(HerdrCloseOutcome::CloseTab),
        "close_host" => Some(HerdrCloseOutcome::CloseHost),
        "noop" => Some(HerdrCloseOutcome::Noop),
        _ => None,
    }
}

fn log_close_event(event: &str, detail: serde_json::Value) {
    let Some(path) = close_log_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        if fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    if close_log_exceeds_limit(&path)
        && OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .is_err()
    {
        return;
    }
    let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
    else {
        return;
    };
    let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    let payload = json!({
        "ts_unix_ms": unix_millis(),
        "component": "hypr-smart-close",
        "event": event,
        "pid": process::id(),
        "ppid": parent_pid(),
        "parent_comm": parent_comm(),
        "detail": detail,
    });
    let _ = writeln!(file, "{payload}");
}

fn close_log_exceeds_limit(path: &PathBuf) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.len() > CLOSE_LOG_MAX_BYTES)
        .unwrap_or(false)
}

fn close_log_path() -> Option<PathBuf> {
    if let Some(path) = env::var_os("HYPR_CLOSE_LOG") {
        let normalized = path.to_string_lossy().trim().to_ascii_lowercase();
        if normalized.is_empty()
            || normalized == "0"
            || normalized == "false"
            || normalized == "off"
            || normalized == "no"
        {
            return None;
        }
        return Some(PathBuf::from(path));
    }
    None
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn parent_pid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

fn parent_comm() -> Option<String> {
    let ppid = parent_pid()?;
    fs::read_to_string(format!("/proc/{ppid}/comm"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn handle_tmux_close(
    session: &str,
    pane: Option<&str>,
    client_tty: &str,
    socket_path: Option<&str>,
) -> bool {
    if let Some(info) = get_tmux_session_info(session, socket_path) {
        match choose_tmux_close_action(&info, pane, client_tty) {
            Some(TmuxCloseAction::DetachClient(target_tty)) => {
                let detached =
                    tmux_status(["detach-client", "-t", &target_tty].as_ref(), socket_path);
                debug_log!(
                    "smart-close",
                    "tmux detach client_tty={} session={} socket={} -> {}",
                    target_tty,
                    session,
                    socket_path.unwrap_or("<default>"),
                    detached
                );
                return detached;
            }
            Some(TmuxCloseAction::KillPane(target_pane)) => {
                return try_tmux_close_pane(&target_pane, socket_path);
            }
            None => {
                debug_log!(
                    "smart-close",
                    "tmux pane target unavailable; cannot safely kill pane"
                );
            }
        }
    }
    false
}

fn try_tmux_close_pane(pane: &str, socket_path: Option<&str>) -> bool {
    let killed = tmux_status(["kill-pane", "-t", pane].as_ref(), socket_path);
    debug_log!(
        "smart-close",
        "tmux kill-pane target={} socket={} -> {}",
        pane,
        socket_path.unwrap_or("<default>"),
        killed
    );
    killed
}

fn choose_tmux_close_action(
    info: &TmuxSessionInfo,
    pane: Option<&str>,
    client_tty: &str,
) -> Option<TmuxCloseAction> {
    if info.is_named || (info.window_count == 1 && info.pane_count == 1) {
        return Some(TmuxCloseAction::DetachClient(client_tty.to_string()));
    }
    pane.map(|p| TmuxCloseAction::KillPane(p.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_info(is_named: bool, panes: usize, windows: usize) -> TmuxSessionInfo {
        TmuxSessionInfo {
            name: "s".to_string(),
            is_named,
            window_count: windows,
            pane_count: panes,
        }
    }

    #[test]
    fn chooses_detach_client_for_named_session() {
        let info = session_info(true, 4, 2);
        assert_eq!(
            choose_tmux_close_action(&info, Some("%2"), "/dev/pts/7"),
            Some(TmuxCloseAction::DetachClient("/dev/pts/7".to_string()))
        );
    }

    #[test]
    fn chooses_detach_client_for_single_pane_single_window() {
        let info = session_info(false, 1, 1);
        assert_eq!(
            choose_tmux_close_action(&info, Some("%2"), "/dev/pts/9"),
            Some(TmuxCloseAction::DetachClient("/dev/pts/9".to_string()))
        );
    }

    #[test]
    fn chooses_kill_pane_for_multi_pane_session() {
        let info = session_info(false, 3, 1);
        assert_eq!(
            choose_tmux_close_action(&info, Some("%42"), "/dev/pts/3"),
            Some(TmuxCloseAction::KillPane("%42".to_string()))
        );
    }

    #[test]
    fn returns_none_when_kill_pane_target_missing() {
        let info = session_info(false, 3, 1);
        assert_eq!(choose_tmux_close_action(&info, None, "/dev/pts/3"), None);
    }

    #[test]
    fn parses_herdr_host_close_pane_action() {
        let response = json!({
            "result": {
                "type": "host_close",
                "close": {
                    "action": "close_pane"
                }
            }
        });

        assert_eq!(
            parse_herdr_host_close_response(&response),
            Some(HerdrCloseOutcome::ClosePane)
        );
    }

    #[test]
    fn parses_herdr_host_close_host_action() {
        let response = json!({
            "result": {
                "type": "host_close",
                "close": {
                    "action": "close_host"
                }
            }
        });

        assert_eq!(
            parse_herdr_host_close_response(&response),
            Some(HerdrCloseOutcome::CloseHost)
        );
    }

    #[test]
    fn rejects_missing_herdr_host_close_contract() {
        let response = json!({
            "result": {
                "type": "ok"
            }
        });

        assert_eq!(parse_herdr_host_close_response(&response), None);
    }
}
