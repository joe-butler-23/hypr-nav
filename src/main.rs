use hypr_nav_lib::debug_log;
use hypr_nav_lib::*;
use std::env;
use std::process::{Command, Stdio};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: hypr-nav <h|j|k|l|left|right|up|down>");
        std::process::exit(1);
    }

    let direction = match Direction::parse(&args[1]) {
        Some(direction) => direction,
        None => std::process::exit(2),
    };
    let move_dir = direction.hypr_movefocus_arg();
    let kitty_dir = direction.kitty_neighbor();

    let hypr_socket = match find_hyprland_socket() {
        Some(path) => path,
        None => std::process::exit(1),
    };
    debug_log!(
        "kitty-nav",
        "input={} move_dir={} kitty_dir={}",
        args[1],
        move_dir,
        kitty_dir
    );

    // Check if active window is Kitty
    if is_kitty_active(&hypr_socket) {
        debug_log!(
            "kitty-nav",
            "kitty is active, trying kitty neighbor navigation"
        );
        if let Some(kitty_socket_uri) = kitty_control_socket_uri() {
            let neighbor_match = format!("neighbor:{}", kitty_dir);
            let status = Command::new("kitty")
                .args([
                    "@",
                    "--to",
                    &kitty_socket_uri,
                    "focus-window",
                    "--match",
                    &neighbor_match,
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            if let Ok(s) = status {
                if s.success() {
                    debug_log!("kitty-nav", "kitty neighbor navigation succeeded");
                    return;
                }
            }
            debug_log!("kitty-nav", "kitty command did not succeed");
        } else {
            debug_log!("kitty-nav", "kitty socket unavailable");
        }
    } else {
        debug_log!("kitty-nav", "kitty not active");
    }

    debug_log!("kitty-nav", "fallback to hypr movefocus {}", move_dir);
    if !hypr_dispatch(&hypr_socket, &format!("movefocus {}", move_dir)) {
        std::process::exit(1);
    }
}

fn is_kitty_active(socket_path: &std::path::PathBuf) -> bool {
    if let Some((class, pid)) = get_active_window_info(socket_path) {
        let is_kitty = is_kitty_window(&class, pid);
        debug_log!(
            "kitty-nav",
            "activewindow class={} pid={} kitty={}",
            class,
            pid,
            is_kitty
        );
        return is_kitty;
    }
    false
}
