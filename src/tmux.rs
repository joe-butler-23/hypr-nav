use hypr_nav_lib::*;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const NAV_STATE_PATH: &str = "/tmp/hypr-nav-navstate";
const ENTRY_ASSIST_WINDOW_MS: u128 = 1500;

struct NavState {
    ts_ms: u128,
    action: String,
    dir: String,
    tty: Option<String>,
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn nav_state_path() -> PathBuf {
    PathBuf::from(NAV_STATE_PATH)
}

fn load_nav_state() -> Option<NavState> {
    let data = fs::read_to_string(nav_state_path()).ok()?;
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parts: Vec<&str> = trimmed.splitn(4, '|').collect();
    if parts.len() != 4 {
        return None;
    }

    let ts_ms = parts[0].parse::<u128>().ok()?;
    let action = parts[1].to_string();
    let dir = parts[2].to_string();
    let tty = if parts[3] == "-" {
        None
    } else {
        Some(parts[3].to_string())
    };

    Some(NavState {
        ts_ms,
        action,
        dir,
        tty,
    })
}

fn save_nav_state(action: &str, dir: &str, tty: Option<&str>) {
    let line = format!(
        "{}|{}|{}|{}\n",
        now_millis(),
        action,
        dir,
        tty.unwrap_or("-")
    );
    let _ = fs::write(nav_state_path(), line);
}

fn should_apply_entry_assist(state: Option<&NavState>, move_dir: &str, current_tty: &str) -> bool {
    let state = match state {
        Some(s) => s,
        None => return false,
    };

    if state.action != "hypr_movefocus" || state.dir != move_dir {
        return false;
    }

    if now_millis().saturating_sub(state.ts_ms) > ENTRY_ASSIST_WINDOW_MS {
        return false;
    }

    match state.tty.as_deref() {
        Some(previous_tty) => previous_tty != current_tty,
        None => true,
    }
}

fn tmux_capture(args: &[&str], socket_path: Option<&str>) -> Option<String> {
    let mut command = Command::new("tmux");
    if let Some(path) = socket_path {
        command.args(["-S", path]);
    }

    let output = command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn select_tmux_pane(target: &str, socket_path: Option<&str>) -> bool {
    let mut command = Command::new("tmux");
    if let Some(path) = socket_path {
        command.args(["-S", path]);
    }

    command
        .args(["select-pane", "-t", target])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn find_entry_assist_pane(
    target: &str,
    direction: &str,
    socket_path: Option<&str>,
) -> Option<String> {
    let window_id = tmux_capture(
        &["display-message", "-t", target, "-p", "#{window_id}"],
        socket_path,
    )?;

    let pane_rows = tmux_capture(
        &[
            "list-panes",
            "-t",
            &window_id,
            "-F",
            "#{pane_id} #{pane_at_left} #{pane_at_right} #{pane_at_top} #{pane_at_bottom} #{pane_active}",
        ],
        socket_path,
    )?;

    choose_entry_assist_pane(&pane_rows, direction)
}

fn choose_entry_assist_pane(pane_rows: &str, direction: &str) -> Option<String> {
    let target_flag_index = match direction {
        "L" => 2, // moving left -> prefer right-edge pane on entry
        "R" => 1, // moving right -> prefer left-edge pane on entry
        "U" => 4, // moving up -> prefer bottom-edge pane on entry
        "D" => 3, // moving down -> prefer top-edge pane on entry
        _ => return None,
    };

    let mut pane_count = 0usize;
    let mut inactive_candidate: Option<String> = None;
    let mut active_candidate: Option<String> = None;

    for row in pane_rows.lines() {
        let parts: Vec<&str> = row.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        pane_count += 1;
        if parts[target_flag_index] != "1" {
            continue;
        }
        let pane_id = parts[0].to_string();
        let pane_active = parts[5] == "1";
        if !pane_active && inactive_candidate.is_none() {
            inactive_candidate = Some(pane_id);
        } else if pane_active && active_candidate.is_none() {
            active_candidate = Some(pane_id);
        }
    }

    // Option 2: only apply entry assist when there is more than one pane.
    if pane_count <= 1 {
        return None;
    }

    // Prefer changing panes when possible, but allow selecting the current edge pane
    // to keep cross-window entry deterministic and avoid accidental directional jumps.
    inactive_candidate.or(active_candidate)
}

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
    let previous_state = load_nav_state();
    let mut current_tty: Option<String> = None;

    if let Some((class, pid)) = get_active_window_info(&hypr_socket) {
        if is_terminal_class(&class) {
            debug_log(
                "tmux-nav",
                &format!("terminal active class={} pid={}", class, pid),
            );
            if let Some(runtime) = detect_tmux_runtime(pid, &class) {
                let socket_path = runtime.socket_path.as_deref();
                current_tty = Some(runtime.tty.clone());
                if let Some(pane) = find_tmux_client_pane(&runtime.tty, socket_path)
                    .or_else(|| find_tmux_pane_by_tty(&runtime.tty, socket_path))
                {
                    debug_log("tmux-nav", &format!("resolved tmux pane target={}", pane));
                    let should_entry_assist =
                        should_apply_entry_assist(previous_state.as_ref(), move_dir, &runtime.tty);
                    if should_entry_assist {
                        if let Some(entry_pane) =
                            find_entry_assist_pane(&pane, tmux_dir, socket_path)
                        {
                            if entry_pane == pane {
                                debug_log(
                                    "tmux-nav",
                                    &format!(
                                        "entry assist target {} already active; continuing",
                                        entry_pane
                                    ),
                                );
                            } else if select_tmux_pane(&entry_pane, socket_path) {
                                debug_log(
                                    "tmux-nav",
                                    &format!(
                                        "entry assist selected opposite-edge pane target={}",
                                        entry_pane
                                    ),
                                );
                                save_nav_state("tmux_entry_assist", move_dir, Some(&runtime.tty));
                                return;
                            }
                        } else {
                            debug_log("tmux-nav", "entry assist active but no edge pane found");
                        }
                    }

                    let at_edge = is_pane_at_edge(&pane, tmux_dir, socket_path);
                    if !at_edge && try_tmux_navigate(&pane, tmux_dir, socket_path) {
                        debug_log("tmux-nav", "tmux pane navigation succeeded");
                        save_nav_state("tmux_select", move_dir, Some(&runtime.tty));
                        return;
                    }
                } else if let Some(session) = find_tmux_session(&runtime.tty, socket_path)
                    .or_else(|| find_tmux_session_by_pane_tty(&runtime.tty, socket_path))
                {
                    debug_log(
                        "tmux-nav",
                        &format!("resolved tmux session fallback target={}", session),
                    );
                    let should_entry_assist =
                        should_apply_entry_assist(previous_state.as_ref(), move_dir, &runtime.tty);
                    if should_entry_assist {
                        if let Some(entry_pane) =
                            find_entry_assist_pane(&session, tmux_dir, socket_path)
                        {
                            let current_pane = tmux_capture(
                                &["display-message", "-t", &session, "-p", "#{pane_id}"],
                                socket_path,
                            );
                            if current_pane.as_deref() == Some(entry_pane.as_str()) {
                                debug_log(
                                    "tmux-nav",
                                    &format!(
                                        "entry assist target {} already active; continuing",
                                        entry_pane
                                    ),
                                );
                            } else if select_tmux_pane(&entry_pane, socket_path) {
                                debug_log(
                                    "tmux-nav",
                                    &format!(
                                        "entry assist selected opposite-edge pane target={}",
                                        entry_pane
                                    ),
                                );
                                save_nav_state("tmux_entry_assist", move_dir, Some(&runtime.tty));
                                return;
                            }
                        } else {
                            debug_log("tmux-nav", "entry assist active but no edge pane found");
                        }
                    }

                    let at_edge = is_pane_at_edge(&session, tmux_dir, socket_path);
                    if !at_edge && try_tmux_navigate(&session, tmux_dir, socket_path) {
                        debug_log("tmux-nav", "tmux session navigation succeeded");
                        save_nav_state("tmux_select", move_dir, Some(&runtime.tty));
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
    save_nav_state("hypr_movefocus", move_dir, current_tty.as_deref());
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

#[cfg(test)]
mod tests {
    use super::choose_entry_assist_pane;

    #[test]
    fn choose_entry_assist_pane_prefers_inactive_opposite_edge() {
        let rows = "\
%0 1 0 1 1 1
%1 0 1 1 1 0
";
        assert_eq!(choose_entry_assist_pane(rows, "L"), Some("%1".to_string()));
    }

    #[test]
    fn choose_entry_assist_pane_requires_multiple_panes() {
        let rows = "%0 1 1 1 1 1\n";
        assert_eq!(choose_entry_assist_pane(rows, "L"), None);
    }

    #[test]
    fn choose_entry_assist_pane_can_fallback_to_active_edge_pane() {
        let rows = "\
%0 0 1 1 1 1
%1 1 0 1 1 0
";
        assert_eq!(choose_entry_assist_pane(rows, "L"), Some("%0".to_string()));
    }

    #[test]
    fn choose_entry_assist_pane_uses_active_edge_when_no_inactive_edge_exists() {
        let rows = "\
%0 1 0 1 1 1
%1 0 1 1 1 0
";
        assert_eq!(choose_entry_assist_pane(rows, "R"), Some("%0".to_string()));
    }
}
