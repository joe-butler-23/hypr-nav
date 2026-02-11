use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Known terminal emulator window classes
pub const KNOWN_TERMINALS: &[&str] = &["kitty"];

/// Check if the window class represents a terminal emulator
pub fn is_terminal_class(class: &str) -> bool {
    // First, check $TERMINAL environment variable
    if let Ok(terminal) = env::var("TERMINAL") {
        // Extract binary name from path (e.g., /usr/bin/kitty -> kitty)
        let terminal_name = terminal
            .rsplit('/')
            .next()
            .unwrap_or(&terminal)
            .to_lowercase();
        if class.to_lowercase().contains(&terminal_name) {
            return true;
        }
    }

    // Fall back to known terminal list
    let class_lower = class.to_lowercase();
    KNOWN_TERMINALS
        .iter()
        .any(|t| class_lower.contains(&t.to_lowercase()))
}

/// Find the Hyprland socket path
pub fn find_hyprland_socket() -> Option<PathBuf> {
    let xdg = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let sig = env::var("HYPRLAND_INSTANCE_SIGNATURE").ok()?;

    if sig.is_empty() {
        return None;
    }

    let hypr_dir = PathBuf::from(&xdg).join("hypr").join(&sig);
    let socket_names = [".socket.sock", ".socket2.sock", "socket.sock"];

    for name in &socket_names {
        let path = hypr_dir.join(name);
        if path.exists() {
            return Some(path);
        }
    }

    Some(hypr_dir.join(".socket.sock"))
}

/// Get active window class and PID in a single Hyprland query
pub fn get_active_window_info(socket_path: &PathBuf) -> Option<(String, u32)> {
    let mut stream = UnixStream::connect(socket_path).ok()?;
    stream.write_all(b"activewindow").ok()?;
    stream.shutdown(std::net::Shutdown::Write).ok()?;

    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;

    let mut class = None;
    let mut pid = None;

    for line in response.lines() {
        let trimmed = line.trim();
        if let Some(c) = trimmed.strip_prefix("class: ") {
            class = Some(c.trim().to_string());
        } else if let Some(p) = trimmed.strip_prefix("pid: ") {
            pid = p.trim().parse::<u32>().ok();
        }
        // Early exit if we have both
        if class.is_some() && pid.is_some() {
            break;
        }
    }

    match (class, pid) {
        (Some(c), Some(p)) => Some((c, p)),
        _ => None,
    }
}

/// Combined detection: find TTY and check for tmux in process tree
/// Returns (tty_path, has_tmux)
pub fn detect_tmux_and_tty(pid: u32) -> Option<(String, bool)> {
    let mut tty: Option<String> = None;
    let mut has_tmux = false;

    // BFS through process tree (downward) to find both TTY and tmux
    const MAX_DEPTH: usize = 10;
    let mut to_check: Vec<(u32, usize)> = vec![(pid, 0)];
    let mut checked: HashSet<u32> = HashSet::new();

    while let Some((current_pid, depth)) = to_check.pop() {
        if checked.contains(&current_pid) || depth > MAX_DEPTH {
            continue;
        }
        checked.insert(current_pid);

        // Check for TTY on this process
        if tty.is_none() {
            if let Ok(link) = fs::read_link(format!("/proc/{}/fd/0", current_pid)) {
                if let Some(tty_str) = link.to_str() {
                    if tty_str.starts_with("/dev/pts/") {
                        tty = Some(tty_str.to_string());
                    }
                }
            }
        }

        // Check if this process is tmux
        if !has_tmux {
            if let Ok(cmdline) = fs::read_to_string(format!("/proc/{}/cmdline", current_pid)) {
                let cmd = cmdline.replace('\0', " ");
                if cmd.contains("tmux") && !cmd.contains("hypr-tmux-nav") {
                    has_tmux = true;
                }
            }
        }

        // Early exit if we found both
        if tty.is_some() && has_tmux {
            break;
        }

        // Get children - try fast path first
        let children_path = format!("/proc/{}/task/{}/children", current_pid, current_pid);
        if let Ok(children) = fs::read_to_string(&children_path) {
            for child_str in children.split_whitespace() {
                if let Ok(child_pid) = child_str.parse::<u32>() {
                    to_check.push((child_pid, depth + 1));
                }
            }
        }
    }

    tty.map(|t| (t, has_tmux))
}

/// Find the tmux session for a given TTY
pub fn find_tmux_session(tty: &str) -> Option<String> {
    // Single tmux call to get all client info
    let output = Command::new("tmux")
        .args(&["list-clients", "-F", "#{client_session} #{client_tty}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let clients = String::from_utf8_lossy(&output.stdout);
    parse_tmux_client_session(&clients, tty)
}

fn parse_tmux_client_session(clients: &str, tty: &str) -> Option<String> {
    let mut sessions: HashSet<String> = HashSet::new();

    for line in clients.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let session = parts[0];
            let client_tty = parts[1];

            // Exact TTY match
            if tty == client_tty {
                return Some(session.to_string());
            }
            sessions.insert(session.to_string());
        }
    }

    // If only one session exists, use it (common case)
    if sessions.len() == 1 {
        return sessions.into_iter().next();
    }

    None
}

fn parse_tmux_client_pane(clients: &str, tty: &str) -> Option<String> {
    for line in clients.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let client_tty = parts[0];
        let pane_id = parts[1];
        if client_tty == tty {
            return Some(pane_id.to_string());
        }
    }
    None
}

/// Find the active tmux pane for a given client TTY
pub fn find_tmux_client_pane(tty: &str) -> Option<String> {
    let output = Command::new("tmux")
        .args(&["list-clients", "-F", "#{client_tty} #{pane_id}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let clients = String::from_utf8_lossy(&output.stdout);
    parse_tmux_client_pane(&clients, tty)
}

/// Check if the active pane in the session is at the edge in the given direction
pub fn is_pane_at_edge(session: &str, direction: &str) -> bool {
    let flag = match direction {
        "L" => "#{pane_at_left}",
        "R" => "#{pane_at_right}",
        "U" => "#{pane_at_top}",
        "D" => "#{pane_at_bottom}",
        _ => return false,
    };

    let output = Command::new("tmux")
        .args(&["display-message", "-t", session, "-p", flag])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let result = String::from_utf8_lossy(&out.stdout).trim().to_string();
            return result == "1";
        }
    }
    false
}

pub struct TmuxSessionInfo {
    pub name: String,
    pub is_named: bool,
    pub window_count: usize,
    pub pane_count: usize,
}

pub fn get_tmux_session_info(session: &str) -> Option<TmuxSessionInfo> {
    // Format: #{session_name} #{window_panes} #{session_windows}
    let output = Command::new("tmux")
        .args(&[
            "display-message",
            "-t",
            session,
            "-p",
            "#{session_name} #{window_panes} #{session_windows}",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let parts: Vec<&str> = result.split_whitespace().collect();
    if parts.len() >= 3 {
        let name = parts[0].to_string();
        let pane_count = parts[1].parse().unwrap_or(1);
        let window_count = parts[2].parse().unwrap_or(1);

        let is_named = name.parse::<u32>().is_err();

        Some(TmuxSessionInfo {
            name,
            is_named,
            window_count,
            pane_count,
        })
    } else {
        None
    }
}

pub fn hypr_dispatch(socket_path: &PathBuf, dispatcher: &str) {
    if let Ok(mut stream) = UnixStream::connect(socket_path) {
        let cmd = format!("dispatch {}", dispatcher);
        let _ = stream.write_all(cmd.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tmux_client_pane_matches_exact_tty() {
        let data = "/dev/pts/2 %11\n/dev/pts/9 %42\n";
        assert_eq!(
            parse_tmux_client_pane(data, "/dev/pts/9"),
            Some("%42".to_string())
        );
    }

    #[test]
    fn parse_tmux_client_pane_ignores_malformed_lines() {
        let data = "invalid-line\n/dev/pts/5 %7\n";
        assert_eq!(
            parse_tmux_client_pane(data, "/dev/pts/5"),
            Some("%7".to_string())
        );
    }

    #[test]
    fn parse_tmux_client_pane_returns_none_when_tty_missing() {
        let data = "/dev/pts/2 %11\n/dev/pts/9 %42\n";
        assert_eq!(parse_tmux_client_pane(data, "/dev/pts/4"), None);
    }

    #[test]
    fn parse_tmux_client_session_prefers_exact_tty_match() {
        let data = "$0 /dev/pts/2\n$1 /dev/pts/9\n";
        assert_eq!(
            parse_tmux_client_session(data, "/dev/pts/9"),
            Some("$1".to_string())
        );
    }

    #[test]
    fn parse_tmux_client_session_accepts_single_unique_session() {
        let data = "$3 /dev/pts/1\n$3 /dev/pts/5\n";
        assert_eq!(
            parse_tmux_client_session(data, "/dev/pts/99"),
            Some("$3".to_string())
        );
    }
}
