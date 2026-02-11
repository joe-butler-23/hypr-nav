use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Known terminal emulator window classes
pub const KNOWN_TERMINALS: &[&str] = &["kitty"];

pub struct TmuxRuntime {
    pub tty: String,
    pub socket_path: Option<String>,
}

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
    let socket_names = [".socket.sock", "socket.sock"];

    for name in &socket_names {
        let path = hypr_dir.join(name);
        if path.exists() {
            if let Ok(meta) = fs::metadata(&path) {
                if meta.file_type().is_socket() {
                    return Some(path);
                }
            }
        }
    }

    None
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

fn parse_tmux_socket_from_value(tmux_value: &str) -> Option<String> {
    // TMUX format: "<socket_path>,<server_pid>,<session_id>"
    let mut parts = tmux_value.rsplitn(3, ',');
    let _session_id = parts.next()?;
    let _server_pid = parts.next()?;
    let socket_path = parts.next()?.trim();
    if socket_path.is_empty() {
        None
    } else {
        Some(socket_path.to_string())
    }
}

fn parse_tmux_socket_from_environ(environ: &[u8]) -> Option<String> {
    for entry in environ.split(|b| *b == 0) {
        if let Some(value) = entry.strip_prefix(b"TMUX=") {
            if let Ok(tmux_value) = std::str::from_utf8(value) {
                if let Some(socket_path) = parse_tmux_socket_from_value(tmux_value) {
                    return Some(socket_path);
                }
            }
        }
    }
    None
}

fn read_tmux_socket_from_environ(pid: u32) -> Option<String> {
    let environ = fs::read(format!("/proc/{}/environ", pid)).ok()?;
    parse_tmux_socket_from_environ(&environ)
}

fn read_process_tty(pid: u32) -> Option<String> {
    let link = fs::read_link(format!("/proc/{}/fd/0", pid)).ok()?;
    let tty = link.to_str()?.to_string();
    if tty.starts_with("/dev/pts/") {
        Some(tty)
    } else {
        None
    }
}

/// Combined detection: find TTY, tmux presence, and tmux socket from process tree.
pub fn detect_tmux_runtime(pid: u32) -> Option<TmuxRuntime> {
    let mut tty: Option<String> = None;
    let mut has_tmux = false;
    let mut socket_path: Option<String> = None;

    // BFS through process tree (downward) to find both TTY and tmux
    const MAX_DEPTH: usize = 10;
    let mut to_check: Vec<(u32, usize)> = vec![(pid, 0)];
    let mut checked: HashSet<u32> = HashSet::new();

    while let Some((current_pid, depth)) = to_check.pop() {
        if checked.contains(&current_pid) || depth > MAX_DEPTH {
            continue;
        }
        checked.insert(current_pid);

        let current_tty = read_process_tty(current_pid);

        // Check for TTY on this process
        if tty.is_none() {
            tty = current_tty.clone();
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

        if socket_path.is_none() {
            socket_path = read_tmux_socket_from_environ(current_pid);
            if socket_path.is_some() {
                has_tmux = true;
                if current_tty.is_some() {
                    tty = current_tty.clone();
                }
            }
        }

        // Early exit if we found everything useful
        if tty.is_some() && has_tmux && socket_path.is_some() {
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

    if !has_tmux {
        return None;
    }

    tty.map(|tty| TmuxRuntime { tty, socket_path })
}

fn tmux_command(socket_path: Option<&str>) -> Command {
    let mut command = Command::new("tmux");
    if let Some(path) = socket_path.filter(|path| !path.is_empty()) {
        command.args(["-S", path]);
    }
    command
}

/// Find the tmux session for a given TTY
pub fn find_tmux_session(tty: &str, socket_path: Option<&str>) -> Option<String> {
    // Single tmux call to get all client info
    let output = tmux_command(socket_path)
        .args(["list-clients", "-F", "#{client_session} #{client_tty}"])
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
    for line in clients.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let session = parts[0];
            let client_tty = parts[1];

            // Exact TTY match
            if tty == client_tty {
                return Some(session.to_string());
            }
        }
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

fn parse_tmux_pane_by_tty(panes: &str, tty: &str) -> Option<String> {
    for line in panes.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let pane_tty = parts[0];
        let pane_id = parts[1];
        if pane_tty == tty {
            return Some(pane_id.to_string());
        }
    }
    None
}

fn parse_tmux_session_by_pane_tty(panes: &str, tty: &str) -> Option<String> {
    for line in panes.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let pane_tty = parts[0];
        let session_id = parts[1];
        if pane_tty == tty {
            return Some(session_id.to_string());
        }
    }
    None
}

/// Find the active tmux pane for a given client TTY
pub fn find_tmux_client_pane(tty: &str, socket_path: Option<&str>) -> Option<String> {
    let output = tmux_command(socket_path)
        .args(["list-clients", "-F", "#{client_tty} #{pane_id}"])
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

/// Find pane by pane tty when we discovered a pane PTY rather than client TTY.
pub fn find_tmux_pane_by_tty(tty: &str, socket_path: Option<&str>) -> Option<String> {
    let output = tmux_command(socket_path)
        .args(["list-panes", "-a", "-F", "#{pane_tty} #{pane_id}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let panes = String::from_utf8_lossy(&output.stdout);
    parse_tmux_pane_by_tty(&panes, tty)
}

/// Find session by pane tty when we discovered a pane PTY rather than client TTY.
pub fn find_tmux_session_by_pane_tty(tty: &str, socket_path: Option<&str>) -> Option<String> {
    let output = tmux_command(socket_path)
        .args(["list-panes", "-a", "-F", "#{pane_tty} #{session_id}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let panes = String::from_utf8_lossy(&output.stdout);
    parse_tmux_session_by_pane_tty(&panes, tty)
}

/// Check if the active pane in the session is at the edge in the given direction
pub fn is_pane_at_edge(session: &str, direction: &str, socket_path: Option<&str>) -> bool {
    let flag = match direction {
        "L" => "#{pane_at_left}",
        "R" => "#{pane_at_right}",
        "U" => "#{pane_at_top}",
        "D" => "#{pane_at_bottom}",
        _ => return false,
    };

    let output = tmux_command(socket_path)
        .args(["display-message", "-t", session, "-p", flag])
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

pub fn get_tmux_session_info(session: &str, socket_path: Option<&str>) -> Option<TmuxSessionInfo> {
    // Format: #{session_name} #{window_panes} #{session_windows}
    let output = tmux_command(socket_path)
        .args([
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
    fn parse_tmux_client_session_returns_none_without_exact_tty_match() {
        let data = "$3 /dev/pts/1\n$3 /dev/pts/5\n";
        assert_eq!(parse_tmux_client_session(data, "/dev/pts/99"), None);
    }

    #[test]
    fn parse_tmux_socket_from_value_extracts_socket_path() {
        let value = "/tmp/tmux-1000/custom,41204,7";
        assert_eq!(
            parse_tmux_socket_from_value(value),
            Some("/tmp/tmux-1000/custom".to_string())
        );
    }

    #[test]
    fn parse_tmux_socket_from_environ_finds_tmux_entry() {
        let env = b"SHELL=/bin/zsh\0TMUX=/tmp/tmux-1000/default,1234,0\0";
        assert_eq!(
            parse_tmux_socket_from_environ(env),
            Some("/tmp/tmux-1000/default".to_string())
        );
    }

    #[test]
    fn parse_tmux_socket_from_environ_ignores_missing_tmux_entry() {
        let env = b"SHELL=/bin/zsh\0PATH=/usr/bin\0";
        assert_eq!(parse_tmux_socket_from_environ(env), None);
    }

    #[test]
    fn parse_tmux_pane_by_tty_matches_exact_tty() {
        let data = "/dev/pts/12 %3\n/dev/pts/13 %4\n";
        assert_eq!(
            parse_tmux_pane_by_tty(data, "/dev/pts/13"),
            Some("%4".to_string())
        );
    }

    #[test]
    fn parse_tmux_session_by_pane_tty_matches_exact_tty() {
        let data = "/dev/pts/12 $3\n/dev/pts/13 $4\n";
        assert_eq!(
            parse_tmux_session_by_pane_tty(data, "/dev/pts/12"),
            Some("$3".to_string())
        );
    }
}
