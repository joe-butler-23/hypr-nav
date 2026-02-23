use hypr_nav_lib::*;
use std::process::{Command, Stdio};

#[derive(Debug, PartialEq, Eq)]
enum TmuxCloseAction {
    DetachClient(String),
    KillPane(String),
}

fn main() {
    let hypr_socket = match find_hyprland_socket() {
        Some(path) => path,
        None => std::process::exit(1),
    };
    debug_log("smart-close", "invoked");

    if let Some((class, pid)) = get_active_window_info(&hypr_socket) {
        if is_terminal_window(&class, pid) {
            debug_log(
                "smart-close",
                &format!("terminal active class={} pid={}", class, pid),
            );
            if let Some(runtime) = detect_tmux_runtime(pid, &class) {
                let socket_path = runtime.socket_path.as_deref();
                let pane = find_tmux_client_pane(&runtime.tty, socket_path)
                    .or_else(|| find_tmux_pane_by_tty(&runtime.tty, socket_path));
                if let Some(session) = find_tmux_session(&runtime.tty, socket_path)
                    .or_else(|| find_tmux_session_by_pane_tty(&runtime.tty, socket_path))
                {
                    debug_log(
                        "smart-close",
                        &format!(
                            "resolved tmux session target={} pane={}",
                            session,
                            pane.as_deref().unwrap_or("<none>")
                        ),
                    );
                    if handle_tmux_close(&session, pane.as_deref(), &runtime.tty, socket_path) {
                        debug_log("smart-close", "tmux close handled");
                        return;
                    }
                    debug_log(
                        "smart-close",
                        "tmux close handling failed, fallback to hypr killactive",
                    );
                }
            } else {
                debug_log(
                    "smart-close",
                    "terminal active but no tmux runtime detected",
                );
            }
        } else {
            debug_log(
                "smart-close",
                &format!("non-terminal active class={}", class),
            );
        }
    } else {
        debug_log("smart-close", "active window info unavailable");
    }

    debug_log("smart-close", "fallback to hypr killactive");
    hypr_dispatch(&hypr_socket, "killactive");
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
                let mut command = Command::new("tmux");
                if let Some(path) = socket_path {
                    command.args(["-S", path]);
                }
                let detached = command
                    .args(["detach-client", "-t", &target_tty])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|status| status.success())
                    .unwrap_or(false);
                debug_log(
                    "smart-close",
                    &format!(
                        "tmux detach client_tty={} session={} socket={} -> {}",
                        target_tty,
                        session,
                        socket_path.unwrap_or("<default>"),
                        detached
                    ),
                );
                return detached;
            }
            Some(TmuxCloseAction::KillPane(target_pane)) => {
                return try_tmux_close_pane(&target_pane, socket_path);
            }
            None => {
                debug_log(
                    "smart-close",
                    "tmux pane target unavailable; cannot safely kill pane",
                );
            }
        }
    }
    false
}

fn try_tmux_close_pane(pane: &str, socket_path: Option<&str>) -> bool {
    let mut command = Command::new("tmux");
    if let Some(path) = socket_path {
        command.args(["-S", path]);
    }

    let output = command
        .args(["kill-pane", "-t", pane])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output();

    let killed = match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    };
    debug_log(
        "smart-close",
        &format!(
            "tmux kill-pane target={} socket={} -> {}",
            pane,
            socket_path.unwrap_or("<default>"),
            killed
        ),
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
}
