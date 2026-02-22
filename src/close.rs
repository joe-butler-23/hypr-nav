use hypr_nav_lib::*;
use std::process::{Command, Stdio};

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
        if info.is_named || (info.window_count == 1 && info.pane_count == 1) {
            let mut command = Command::new("tmux");
            if let Some(path) = socket_path {
                command.args(["-S", path]);
            }
            let detached = command
                .args(["detach-client", "-t", client_tty])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
            debug_log(
                "smart-close",
                &format!(
                    "tmux detach target={} socket={} -> {}",
                    session,
                    socket_path.unwrap_or("<default>"),
                    detached
                ),
            );
            return detached;
        }

        if let Some(pane) = pane {
            return try_tmux_close_pane(pane, socket_path);
        }
        debug_log(
            "smart-close",
            "tmux pane target unavailable; cannot safely kill pane",
        );
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
