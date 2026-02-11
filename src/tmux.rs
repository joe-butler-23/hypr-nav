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
    debug_log(
        "tmux-nav",
        &format!(
            "input={} move_dir={} tmux_dir={}",
            args[1], move_dir, tmux_dir
        ),
    );

    if let Some((class, pid)) = get_active_window_info(&hypr_socket) {
        if is_terminal_class(&class) {
            debug_log(
                "tmux-nav",
                &format!("terminal active class={} pid={}", class, pid),
            );
            if let Some(runtime) = detect_tmux_runtime(pid) {
                let socket_path = runtime.socket_path.as_deref();
                if let Some(pane) = find_tmux_client_pane(&runtime.tty, socket_path)
                    .or_else(|| find_tmux_pane_by_tty(&runtime.tty, socket_path))
                {
                    debug_log("tmux-nav", &format!("resolved tmux pane target={}", pane));
                    if !is_pane_at_edge(&pane, tmux_dir, socket_path)
                        && try_tmux_navigate(&pane, tmux_dir, socket_path)
                    {
                        debug_log("tmux-nav", "tmux pane navigation succeeded");
                        return;
                    }
                } else if let Some(session) = find_tmux_session(&runtime.tty, socket_path)
                    .or_else(|| find_tmux_session_by_pane_tty(&runtime.tty, socket_path))
                {
                    debug_log(
                        "tmux-nav",
                        &format!("resolved tmux session fallback target={}", session),
                    );
                    if !is_pane_at_edge(&session, tmux_dir, socket_path)
                        && try_tmux_navigate(&session, tmux_dir, socket_path)
                    {
                        debug_log("tmux-nav", "tmux session navigation succeeded");
                        return;
                    }
                } else {
                    debug_log("tmux-nav", "no tmux pane/session target resolved");
                }
            } else {
                debug_log("tmux-nav", "terminal active but no tmux runtime detected");
            }
        } else {
            debug_log("tmux-nav", &format!("non-terminal active class={}", class));
        }
    } else {
        debug_log("tmux-nav", "active window info unavailable");
    }

    debug_log(
        "tmux-nav",
        &format!("fallback to hypr movefocus {}", move_dir),
    );
    hypr_dispatch(&hypr_socket, &format!("movefocus {}", move_dir));
}

fn try_tmux_navigate(target: &str, direction: &str, socket_path: Option<&str>) -> bool {
    let direction_flag = format!("-{}", direction);
    let mut command = Command::new("tmux");
    if let Some(path) = socket_path {
        command.args(["-S", path]);
    }

    let result = command
        .args(["select-pane", "-t", target, &direction_flag])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    debug_log(
        "tmux-nav",
        &format!(
            "tmux select-pane target={} dir={} socket={} -> {}",
            target,
            direction,
            socket_path.unwrap_or("<default>"),
            result
        ),
    );
    result
}
