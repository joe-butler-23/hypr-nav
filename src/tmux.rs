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
                    if let Some(session) = find_tmux_session(&tty) {
                        if !is_pane_at_edge(&session, tmux_dir) {
                             if try_tmux_navigate(&session, tmux_dir) {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    hypr_dispatch(&hypr_socket, &format!("movefocus {}", move_dir));
}

fn try_tmux_navigate(session: &str, direction: &str) -> bool {
    let output = Command::new("tmux")
        .args(&[
            "display-message",
            "-t",
            session,
            "-p",
            "#{pane_id}",
            ";",
            "select-pane",
            "-t",
            session,
            &format!("-{}", direction),
            ";",
            "display-message",
            "-t",
            session,
            "-p",
            "#{pane_id}",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let result = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = result.lines().collect();
            if lines.len() >= 2 {
                return lines[0] != lines[1];
            }
        }
    }

    false
}
