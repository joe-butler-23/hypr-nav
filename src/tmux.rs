use hypr_nav_lib::debug_log;
use hypr_nav_lib::*;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const NAV_STATE_FILE: &str = "hypr-nav-navstate";
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
    let base = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let uid = current_uid_string();
    PathBuf::from(base).join(format!("{}-{}", NAV_STATE_FILE, uid))
}

fn current_uid_string() -> String {
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    return parts[1].to_string();
                }
            }
        }
    }
    env::var("UID").unwrap_or_else(|_| "unknown".to_string())
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
    let path = nav_state_path();
    let mut tmp_path = path.clone();
    tmp_path.set_extension(format!("tmp-{}", std::process::id()));

    if fs::write(&tmp_path, line).is_ok() {
        let _ = fs::rename(tmp_path, path);
    }
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

fn select_tmux_pane(target: &str, socket_path: Option<&str>) -> bool {
    tmux_status(["select-pane", "-t", target].as_ref(), socket_path)
}

fn find_entry_assist_pane(
    target: &str,
    direction: Direction,
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

fn choose_entry_assist_pane(pane_rows: &str, direction: Direction) -> Option<String> {
    let target_flag_index = match direction {
        Direction::Left => 2,  // moving left -> prefer right-edge pane on entry
        Direction::Right => 1, // moving right -> prefer left-edge pane on entry
        Direction::Up => 4,    // moving up -> prefer bottom-edge pane on entry
        Direction::Down => 3,  // moving down -> prefer top-edge pane on entry
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

/// Try to navigate within a resolved tmux pane/session `target`: apply entry
/// assist when appropriate, then fall through to edge-checked pane
/// navigation. Returns true when navigation was handled (nav state saved),
/// so the caller can `return` immediately.
fn navigate_tmux_target(
    target: &str,
    direction: Direction,
    move_dir: &str,
    tty: &str,
    socket_path: Option<&str>,
    previous_state: Option<&NavState>,
) -> bool {
    debug_log!("tmux-nav", "resolved tmux navigation target={}", target);

    let should_entry_assist = should_apply_entry_assist(previous_state, move_dir, tty);
    if should_entry_assist {
        if let Some(entry_pane) = find_entry_assist_pane(target, direction, socket_path) {
            let current_pane = tmux_capture(
                &["display-message", "-t", target, "-p", "#{pane_id}"],
                socket_path,
            );
            if current_pane.as_deref() == Some(entry_pane.as_str()) {
                debug_log!(
                    "tmux-nav",
                    "entry assist target {} already active; continuing",
                    entry_pane
                );
            } else if select_tmux_pane(&entry_pane, socket_path) {
                debug_log!(
                    "tmux-nav",
                    "entry assist selected opposite-edge pane target={}",
                    entry_pane
                );
                save_nav_state("tmux_entry_assist", move_dir, Some(tty));
                return true;
            }
        } else {
            debug_log!("tmux-nav", "entry assist active but no edge pane found");
        }
    }

    let at_edge = is_pane_at_edge(target, direction, socket_path);
    if !at_edge && try_tmux_navigate(target, direction, socket_path) {
        debug_log!("tmux-nav", "tmux navigation succeeded");
        save_nav_state("tmux_select", move_dir, Some(tty));
        return true;
    }

    false
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: hypr-tmux-nav <h|j|k|l|left|right|up|down>");
        std::process::exit(1);
    }

    let direction = match Direction::parse(&args[1]) {
        Some(direction) => direction,
        None => std::process::exit(2),
    };
    let move_dir = direction.hypr_movefocus_arg();
    let tmux_dir = direction.tmux_flag();

    let hypr_socket = match find_hyprland_socket() {
        Some(path) => path,
        None => std::process::exit(1),
    };
    debug_log!(
        "tmux-nav",
        "input={} move_dir={} tmux_dir={}",
        args[1],
        move_dir,
        tmux_dir
    );
    let previous_state = load_nav_state();
    let mut current_tty: Option<String> = None;

    if let Some((class, pid)) = get_active_window_info(&hypr_socket) {
        if is_terminal_window(&class, pid) {
            debug_log!("tmux-nav", "terminal active class={} pid={}", class, pid);
            let terminal = detect_terminal_runtime(pid, &class);
            current_tty = terminal.tty.clone();

            // Layer 1: Try nvim split navigation first
            if let Some(ref nvim) = terminal.nvim {
                debug_log!("tmux-nav", "nvim detected socket={}", nvim.socket_path);

                // Nvim entry assist: on cross-window entry, jump to opposite edge
                let nvim_tty = current_tty.as_deref().unwrap_or("");
                if !nvim_tty.is_empty()
                    && should_apply_entry_assist(previous_state.as_ref(), move_dir, nvim_tty)
                {
                    if try_nvim_entry_assist(&nvim.socket_path, direction) {
                        debug_log!("tmux-nav", "nvim entry assist applied");
                        save_nav_state("nvim_entry_assist", move_dir, current_tty.as_deref());
                        return;
                    } else {
                        debug_log!(
                            "tmux-nav",
                            "nvim entry assist not applicable (single window or failed)"
                        );
                    }
                }

                match nvim_navigate_or_edge(&nvim.socket_path, direction) {
                    NvimNavOutcome::Moved => {
                        debug_log!("tmux-nav", "nvim split navigation succeeded");
                        save_nav_state("nvim_wincmd", move_dir, current_tty.as_deref());
                        return;
                    }
                    NvimNavOutcome::AtEdge => {
                        debug_log!("tmux-nav", "nvim at edge, falling through");
                    }
                    NvimNavOutcome::Error => {
                        debug_log!("tmux-nav", "nvim navigate error, falling through");
                    }
                }
            }

            // Layer 2: Try tmux pane navigation
            if let Some(runtime) = terminal.tmux {
                let socket_path = runtime.socket_path.as_deref();
                if let Some(pane) = find_tmux_client_pane(&runtime.tty, socket_path)
                    .or_else(|| find_tmux_pane_by_tty(&runtime.tty, socket_path))
                {
                    if navigate_tmux_target(
                        &pane,
                        direction,
                        move_dir,
                        &runtime.tty,
                        socket_path,
                        previous_state.as_ref(),
                    ) {
                        return;
                    }
                } else if let Some(session) = find_tmux_session(&runtime.tty, socket_path)
                    .or_else(|| find_tmux_session_by_pane_tty(&runtime.tty, socket_path))
                {
                    if navigate_tmux_target(
                        &session,
                        direction,
                        move_dir,
                        &runtime.tty,
                        socket_path,
                        previous_state.as_ref(),
                    ) {
                        return;
                    }
                } else {
                    debug_log!("tmux-nav", "no tmux pane/session target resolved");
                }
            } else {
                debug_log!("tmux-nav", "terminal active but no tmux runtime detected");
            }
        } else {
            debug_log!("tmux-nav", "non-terminal active class={}", class);
        }
    } else {
        debug_log!("tmux-nav", "active window info unavailable");
    }

    debug_log!("tmux-nav", "fallback to hypr movefocus {}", move_dir);
    if hypr_dispatch(&hypr_socket, &format!("movefocus {}", move_dir)) {
        save_nav_state("hypr_movefocus", move_dir, current_tty.as_deref());
    } else {
        std::process::exit(1);
    }
}

fn try_tmux_navigate(target: &str, direction: Direction, socket_path: Option<&str>) -> bool {
    let direction_flag = format!("-{}", direction.tmux_flag());
    let result = tmux_status(
        ["select-pane", "-t", target, &direction_flag].as_ref(),
        socket_path,
    );
    debug_log!(
        "tmux-nav",
        "tmux select-pane target={} dir={} socket={} -> {}",
        target,
        direction.tmux_flag(),
        socket_path.unwrap_or("<default>"),
        result
    );
    result
}

#[cfg(test)]
mod tests {
    use hypr_nav_lib::Direction;

    use super::choose_entry_assist_pane;

    #[test]
    fn choose_entry_assist_pane_prefers_inactive_opposite_edge() {
        let rows = "\
%0 1 0 1 1 1
%1 0 1 1 1 0
";
        assert_eq!(
            choose_entry_assist_pane(rows, Direction::Left),
            Some("%1".to_string())
        );
    }

    #[test]
    fn choose_entry_assist_pane_requires_multiple_panes() {
        let rows = "%0 1 1 1 1 1\n";
        assert_eq!(choose_entry_assist_pane(rows, Direction::Left), None);
    }

    #[test]
    fn choose_entry_assist_pane_can_fallback_to_active_edge_pane() {
        let rows = "\
%0 0 1 1 1 1
%1 1 0 1 1 0
";
        assert_eq!(
            choose_entry_assist_pane(rows, Direction::Left),
            Some("%0".to_string())
        );
    }

    #[test]
    fn choose_entry_assist_pane_uses_active_edge_when_no_inactive_edge_exists() {
        let rows = "\
%0 1 0 1 1 1
%1 0 1 1 1 0
";
        assert_eq!(
            choose_entry_assist_pane(rows, Direction::Right),
            Some("%0".to_string())
        );
    }
}
