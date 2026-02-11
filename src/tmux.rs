use std::env;
use std::process::{Command, Stdio};
use hypr_nav_lib::*;

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
            if let Some((tty, has_tmux)) = detect_tmux_and_tty(pid) {
                if has_tmux {
                    if let Some(pane) = find_tmux_client_pane(&tty) {
                        if !is_pane_at_edge(&pane, tmux_dir) && try_tmux_navigate(&pane, tmux_dir) {
                            return;
                        }
                    } else if let Some(session) = find_tmux_session(&tty) {
                        if !is_pane_at_edge(&session, tmux_dir) && try_tmux_navigate(&session, tmux_dir) {
                            return;
                        }
                    }
                }
            }
        }
    }

    hypr_dispatch(&hypr_socket, &format!("movefocus {}", move_dir));
}

fn try_tmux_navigate(target: &str, direction: &str) -> bool {
    Command::new("tmux")
        .args(&["select-pane", "-t", target, &format!("-{}", direction)])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
