use hypr_nav_lib::*;
use std::env;
use std::process::{Command, Stdio};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: hypr-tmux-nav <h|j|k|l|left|right|up|down>");
        std::process::exit(1);
    }

    let (move_dir, tmux_dir) = match args[1].as_str() {
        "h" | "left" => ("l", "L"),
        "l" | "right" | "r" => ("r", "R"),
        "k" | "up" | "u" => ("u", "U"),
        "j" | "down" | "d" => ("d", "D"),
        _ => std::process::exit(2),
    };

    let hypr_socket = match find_hyprland_socket() {
        Some(path) => path,
        None => std::process::exit(1),
    };

    if let Some((class, pid)) = get_active_window_info(&hypr_socket) {
        if is_terminal_class(&class) {
            if let Some(runtime) = detect_tmux_runtime(pid) {
                let socket_path = runtime.socket_path.as_deref();
                if let Some(pane) = find_tmux_client_pane(&runtime.tty, socket_path)
                    .or_else(|| find_tmux_pane_by_tty(&runtime.tty, socket_path))
                {
                    if !is_pane_at_edge(&pane, tmux_dir, socket_path)
                        && try_tmux_navigate(&pane, tmux_dir, socket_path)
                    {
                        return;
                    }
                } else if let Some(session) = find_tmux_session(&runtime.tty, socket_path)
                    .or_else(|| find_tmux_session_by_pane_tty(&runtime.tty, socket_path))
                {
                    if !is_pane_at_edge(&session, tmux_dir, socket_path)
                        && try_tmux_navigate(&session, tmux_dir, socket_path)
                    {
                        return;
                    }
                }
            }
        }
    }

    hypr_dispatch(&hypr_socket, &format!("movefocus {}", move_dir));
}

fn try_tmux_navigate(target: &str, direction: &str, socket_path: Option<&str>) -> bool {
    let direction_flag = format!("-{}", direction);
    let mut command = Command::new("tmux");
    if let Some(path) = socket_path {
        command.args(["-S", path]);
    }

    command
        .args(["select-pane", "-t", target, &direction_flag])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
