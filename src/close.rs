use hypr_nav_lib::*;
use std::env;

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

    let hypr_socket = match find_hyprland_socket() {
        Some(path) => path,
        None => std::process::exit(1),
    };
    debug_log("smart-close", "invoked");

    let active = match get_active_window_snapshot(&hypr_socket) {
        Some(info) => info,
        None => std::process::exit(1),
    };

    if is_terminal_window(&active.class, active.pid) {
        if is_kitty_window(&active.class, active.pid) {
            debug_log(
                "smart-close",
                &format!(
                    "kitty active class={} pid={}; closing captured hypr address={}",
                    active.class, active.pid, active.address
                ),
            );
        } else {
            debug_log(
                "smart-close",
                &format!("terminal active class={} pid={}", active.class, active.pid),
            );
            if let Some(runtime) = detect_tmux_runtime(active.pid, &active.class) {
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
                        "tmux close handling failed; refusing unsafe window fallback",
                    );
                    std::process::exit(1);
                } else {
                    debug_log(
                        "smart-close",
                        "tmux runtime detected but no session target resolved; refusing unsafe window fallback",
                    );
                    std::process::exit(1);
                }
            } else {
                debug_log(
                    "smart-close",
                    "terminal active but no tmux runtime detected",
                );
            }
        }
    } else {
        debug_log(
            "smart-close",
            &format!("non-terminal active class={}", active.class),
        );
    }

    debug_log(
        "smart-close",
        &format!("closing captured hypr address={}", active.address),
    );
    hypr_dispatch(
        &hypr_socket,
        &format!("closewindow address:{}", active.address),
    );
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
    let killed = tmux_status(["kill-pane", "-t", pane].as_ref(), socket_path);
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
