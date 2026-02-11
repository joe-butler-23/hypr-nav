use hypr_nav_lib::*;
use std::process::{Command, Stdio};

fn main() {
    let hypr_socket = match find_hyprland_socket() {
        Some(path) => path,
        None => std::process::exit(1),
    };

    if let Some((class, pid)) = get_active_window_info(&hypr_socket) {
        if is_terminal_class(&class) {
            if let Some(runtime) = detect_tmux_runtime(pid) {
                let socket_path = runtime.socket_path.as_deref();
                if let Some(session) = find_tmux_session(&runtime.tty, socket_path)
                    .or_else(|| find_tmux_session_by_pane_tty(&runtime.tty, socket_path))
                {
                    if handle_tmux_close(&session, socket_path) {
                        return;
                    }
                }
            }
        }
    }

    hypr_dispatch(&hypr_socket, "killactive");
}

fn handle_tmux_close(session: &str, socket_path: Option<&str>) -> bool {
    if let Some(info) = get_tmux_session_info(session, socket_path) {
        if info.is_named || (info.window_count == 1 && info.pane_count == 1) {
            let mut command = Command::new("tmux");
            if let Some(path) = socket_path {
                command.args(["-S", path]);
            }
            return command
                .args(["detach-client", "-t", session])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
        }

        return try_tmux_close_pane(session, socket_path);
    }
    false
}

fn try_tmux_close_pane(session: &str, socket_path: Option<&str>) -> bool {
    let mut command = Command::new("tmux");
    if let Some(path) = socket_path {
        command.args(["-S", path]);
    }

    let output = command
        .args(["kill-pane", "-t", session])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output();

    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}
