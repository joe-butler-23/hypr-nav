use hypr_nav_lib::debug_log;
use hypr_nav_lib::*;
use serde_json::{json, Value};
use std::env;
use std::path::PathBuf;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HerdrNavigateOutcome {
    Moved,
    AtEdge,
}

fn parse_herdr_host_navigate_response(value: &Value) -> Option<HerdrNavigateOutcome> {
    if value.pointer("/result/type")?.as_str()? != "pane_focus_direction" {
        return None;
    }
    let focus = value.pointer("/result/focus")?;
    if focus.get("changed")?.as_bool()? {
        Some(HerdrNavigateOutcome::Moved)
    } else if focus.get("reason").and_then(Value::as_str) == Some("no_neighbor") {
        Some(HerdrNavigateOutcome::AtEdge)
    } else {
        None
    }
}

fn herdr_host_navigate(
    direction: Direction,
    runtime: &HerdrRuntime,
) -> Option<HerdrNavigateOutcome> {
    let response = herdr_request(
        runtime,
        "hypr-nav:pane:focus-direction",
        "pane.focus_direction",
        json!({ "direction": direction.herdr_direction() }),
    )?;
    parse_herdr_host_navigate_response(&response)
}

fn herdr_entry_pane(response: &Value, direction: Direction) -> Option<String> {
    if response.pointer("/result/type")?.as_str()? != "pane_layout" {
        return None;
    }
    let layout = response.pointer("/result/layout")?;
    if layout.get("zoomed")?.as_bool()? {
        return None;
    }
    let panes = layout.get("panes")?.as_array()?;
    if panes.len() < 2 {
        return None;
    }
    let area = layout.get("area")?;
    let (axis, extent, far_edge) = match direction {
        Direction::Left => ("x", "width", true),
        Direction::Right => ("x", "width", false),
        Direction::Up => ("y", "height", true),
        Direction::Down => ("y", "height", false),
    };
    let boundary = area.get(axis)?.as_u64()?.checked_add(if far_edge {
        area.get(extent)?.as_u64()?
    } else {
        0
    })?;
    let focused = layout.get("focused_pane_id")?.as_str()?;
    let mut candidates = Vec::new();
    let mut ids = std::collections::HashSet::new();
    for pane in panes {
        let id = pane.get("pane_id")?.as_str()?;
        if id.is_empty() || !ids.insert(id) {
            return None;
        }
        let rect = pane.get("rect")?;
        let edge = rect.get(axis)?.as_u64()?.checked_add(if far_edge {
            rect.get(extent)?.as_u64()?
        } else {
            0
        })?;
        if edge == boundary {
            candidates.push(id);
        }
    }
    // Keep the current pane when already on the entering edge. Otherwise the
    // first pane in the server's layout order provides deterministic entry.
    if candidates.contains(&focused) {
        return None;
    }
    candidates.first().map(|id| id.to_string())
}

fn enter_herdr_destination(
    socket: &PathBuf,
    destination: &ActiveWindowInfo,
    runtime: &HerdrRuntime,
    direction: Direction,
) -> bool {
    let Some(layout) = herdr_request(runtime, "hypr-nav:pane:layout", "pane.layout", json!({}))
    else {
        return false;
    };
    let Some(pane_id) = herdr_entry_pane(&layout, direction) else {
        return true;
    };
    if !active_window_is_current(socket, destination) {
        return false;
    }
    herdr_request(
        runtime,
        "hypr-nav:pane:entry",
        "pane.focus",
        json!({ "pane_id": pane_id }),
    )
    .is_some_and(|response| response.pointer("/result/type").and_then(Value::as_str) == Some("ok"))
}

// Entry belongs to this acknowledged outer move, never a later keypress.
fn enter_destination(
    socket: &PathBuf,
    previous: Option<&ActiveWindowInfo>,
    direction: Direction,
) -> bool {
    let Some(destination) = get_active_window_snapshot(socket) else {
        return false;
    };
    if previous.is_none_or(|window| window.address == destination.address) {
        return true;
    }
    if is_terminal_window(&destination.class, destination.pid) {
        let Some(terminal) = detect_terminal_runtime(&destination) else {
            return true;
        };
        if !active_window_is_current(socket, &destination) {
            return false;
        }
        if let Some(nvim) = terminal.nvim {
            match nvim_enter_edge(&nvim.socket_path, direction) {
                NvimNavOutcome::Moved => return true,
                NvimNavOutcome::AtEdge => {}
                NvimNavOutcome::Error => return false,
            }
        }
        if !active_window_is_current(socket, &destination) {
            return false;
        }
        if let Some(runtime) = terminal.herdr {
            return enter_herdr_destination(socket, &destination, &runtime, direction);
        }
        if let Some(runtime) = terminal.tmux {
            let socket_path = runtime.socket_path.as_deref();
            let Some(target) = find_tmux_client_target(&runtime.tty, socket_path)
                .or_else(|| find_tmux_pane_target(&runtime.tty, socket_path))
            else {
                return true;
            };
            if let Some(pane) = find_entry_assist_pane(&target.pane, direction, socket_path) {
                return active_window_is_current(socket, &destination)
                    && select_tmux_pane(&pane, socket_path);
            }
        }
    } else if let Some(runtime) = detect_herdr_runtime(destination.pid, &destination.class) {
        return active_window_is_current(socket, &destination)
            && enter_herdr_destination(socket, &destination, &runtime, direction);
    }
    true
}

fn main() {
    start_watchdog();
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
    let captured = get_active_window_snapshot(&hypr_socket);

    if let Some(ref active) = captured {
        let class = &active.class;
        let pid = active.pid;
        if is_terminal_window(class, pid) {
            debug_log!("tmux-nav", "terminal active class={} pid={}", class, pid);
            let terminal = detect_terminal_runtime(active).unwrap_or_default();
            if !active_window_is_current(&hypr_socket, active) {
                std::process::exit(1);
            }

            // Layer 1: Try nvim split navigation first
            if let Some(ref nvim) = terminal.nvim {
                debug_log!("tmux-nav", "nvim detected socket={}", nvim.socket_path);

                match nvim_navigate_or_edge(&nvim.socket_path, direction) {
                    NvimNavOutcome::Moved => {
                        debug_log!("tmux-nav", "nvim split navigation succeeded");
                        return;
                    }
                    NvimNavOutcome::AtEdge => {
                        debug_log!("tmux-nav", "nvim at edge, falling through");
                    }
                    NvimNavOutcome::Error => {
                        eprintln!("hypr-tmux-nav: nvim navigation unacknowledged");
                        std::process::exit(1);
                    }
                }
            }

            // Layer 2: Try Herdr pane navigation for a Herdr client running in the terminal
            if let Some(ref runtime) = terminal.herdr {
                if !active_window_is_current(&hypr_socket, active) {
                    std::process::exit(1);
                }
                debug_log!(
                    "tmux-nav",
                    "herdr runtime socket={:?} session={:?} detected in terminal class={}",
                    runtime.socket_path,
                    runtime.session,
                    class
                );
                match herdr_host_navigate(direction, runtime) {
                    Some(HerdrNavigateOutcome::Moved) => {
                        debug_log!("tmux-nav", "herdr host navigation applied");
                        return;
                    }
                    Some(HerdrNavigateOutcome::AtEdge) => {
                        debug_log!("tmux-nav", "herdr host at edge; falling through");
                    }
                    None => {
                        eprintln!("hypr-tmux-nav: Herdr navigation unacknowledged");
                        std::process::exit(1);
                    }
                }
            }

            // Layer 3: Try tmux pane navigation
            if let Some(runtime) = terminal.tmux {
                let socket_path = runtime.socket_path.as_deref();
                if let Some(target) = find_tmux_client_target(&runtime.tty, socket_path)
                    .or_else(|| find_tmux_pane_target(&runtime.tty, socket_path))
                {
                    if !active_window_is_current(&hypr_socket, active) {
                        std::process::exit(1);
                    }
                    if !target.at_edge(direction) {
                        if try_tmux_navigate(&target.pane, direction, socket_path) {
                            return;
                        }
                        eprintln!("hypr-tmux-nav: tmux navigation unacknowledged");
                        std::process::exit(1);
                    }
                } else {
                    debug_log!("tmux-nav", "no tmux pane/session target resolved");
                }
            } else {
                debug_log!("tmux-nav", "terminal active but no tmux runtime detected");
            }
        } else if let Some(runtime) = detect_herdr_runtime(pid, class) {
            debug_log!(
                "tmux-nav",
                "herdr runtime socket={:?} session={:?} detected for class={}",
                runtime.socket_path,
                runtime.session,
                class
            );
            match herdr_host_navigate(direction, &runtime) {
                Some(HerdrNavigateOutcome::Moved) => {
                    debug_log!("tmux-nav", "herdr host navigation applied");
                    return;
                }
                Some(HerdrNavigateOutcome::AtEdge) => {
                    debug_log!("tmux-nav", "herdr host at edge; falling through");
                }
                None => {
                    eprintln!("hypr-tmux-nav: Herdr navigation unacknowledged");
                    std::process::exit(1);
                }
            }
        } else {
            debug_log!("tmux-nav", "non-terminal active class={}", class);
        }
    } else {
        debug_log!("tmux-nav", "active window info unavailable");
    }

    if captured
        .as_ref()
        .is_some_and(|active| !active_window_is_current(&hypr_socket, active))
    {
        eprintln!("hypr-tmux-nav: source window changed before outer navigation");
        std::process::exit(1);
    }
    debug_log!("tmux-nav", "fallback to hypr movefocus {}", move_dir);
    let action = HyprDispatch::MoveFocus(direction);
    if hypr_dispatch_action(&hypr_socket, &action) {
        if !enter_destination(&hypr_socket, captured.as_ref(), direction) {
            eprintln!("hypr-tmux-nav: destination entry failed or target changed");
            std::process::exit(1);
        }
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

    use super::{
        choose_entry_assist_pane, parse_herdr_host_navigate_response, HerdrNavigateOutcome,
    };

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

    #[test]
    fn herdr_host_navigate_response_reports_moved() {
        let response = serde_json::json!({
            "result": {
                "type": "pane_focus_direction",
                "focus": {
                    "changed": true,
                    "reason": null,
                    "focused_pane_id": "w1:p2"
                }
            }
        });

        assert_eq!(
            parse_herdr_host_navigate_response(&response),
            Some(HerdrNavigateOutcome::Moved)
        );
    }

    #[test]
    fn herdr_host_navigate_response_reports_at_edge() {
        let response = serde_json::json!({
            "result": {
                "type": "pane_focus_direction",
                "focus": {
                    "changed": false,
                    "reason": "no_neighbor",
                    "focused_pane_id": "w1:p1"
                }
            }
        });

        assert_eq!(
            parse_herdr_host_navigate_response(&response),
            Some(HerdrNavigateOutcome::AtEdge)
        );
    }

    #[test]
    fn herdr_host_navigate_response_rejects_missing_contract() {
        let response = serde_json::json!({
            "result": {
                "type": "ok"
            }
        });

        assert_eq!(parse_herdr_host_navigate_response(&response), None);
    }
}
