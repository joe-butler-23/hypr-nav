use std::process::{Command, Stdio};
use hypr_nav_lib::*;

fn main() {
    let hypr_socket = match find_hyprland_socket() {
        Some(path) => path,
        None => std::process::exit(1),
    };

    if let Some((class, pid)) = get_active_window_info(&hypr_socket) {
        if is_terminal_class(&class) {
            if let Some((tty, has_tmux)) = detect_tmux_and_tty(pid) {
                if has_tmux {
                    if let Some(session) = find_tmux_session(&tty) {
                        if handle_tmux_close(&session, &hypr_socket) {
                            return;
                        }
                    }
                }
            }
        }
    }

    hypr_dispatch(&hypr_socket, "killactive");
}

fn handle_tmux_close(session: &str, _hypr_socket: &std::path::PathBuf) -> bool {
    if let Some(info) = get_tmux_session_info(session) {
        if info.is_named {
             let _ = Command::new("tmux")
                .args(&["detach-client", "-t", session])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output();
             return true;
        }

        if info.window_count == 1 && info.pane_count == 1 {
            return false;
        }

        return try_tmux_close_pane(session);
    }
    false
}

fn try_tmux_close_pane(session: &str) -> bool {
    let output = Command::new("tmux")
        .args(&[
            "kill-pane",
            "-t",
            session,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output();
        
    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}
