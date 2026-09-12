use hypr_nav_lib::debug_log;
use hypr_nav_lib::*;
use std::env;
use std::process::{Command, Stdio};

fn main() {
    start_watchdog();
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

    let hypr_socket = match find_hyprland_socket() {
        Some(path) => path,
        None => std::process::exit(1),
    };
    debug_log!("kitty-nav", "input={} move_dir={}", args[1], move_dir);

    if let Some(active) = get_active_window_snapshot(&hypr_socket) {
        if is_kitty_window(&active.class, active.pid) {
            if let Some(context) = kitty_context(&active) {
                if let Some(neighbor) = context.neighbor_id(direction) {
                    if !active_window_is_current(&hypr_socket, &active) {
                        return;
                    }
                    let target = format!("id:{neighbor}");
                    let status = Command::new("kitty")
                        .args([
                            "@",
                            "--to",
                            &context.socket_uri,
                            "focus-window",
                            "--match",
                            &target,
                        ])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .watched_status();
                    if status.is_ok_and(|status| status.success()) {
                        return;
                    }
                }
            }
        }
    }

    debug_log!("kitty-nav", "fallback to hypr movefocus {}", move_dir);
    let action = HyprDispatch::MoveFocus(direction);
    if !hypr_dispatch_action(&hypr_socket, &action) {
        std::process::exit(1);
    }
}
