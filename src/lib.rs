use serde_json::Value;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Known terminal emulator window classes
pub const KNOWN_TERMINALS: &[&str] = &["kitty"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Left,
    Right,
    Up,
    Down,
}

impl Direction {
    pub fn parse(arg: &str) -> Option<Self> {
        match arg {
            "h" | "left" => Some(Self::Left),
            "l" | "right" | "r" => Some(Self::Right),
            "k" | "up" | "u" => Some(Self::Up),
            "j" | "down" | "d" => Some(Self::Down),
            _ => None,
        }
    }

    pub fn hypr_movefocus_arg(self) -> &'static str {
        match self {
            Self::Left => "l",
            Self::Right => "r",
            Self::Up => "u",
            Self::Down => "d",
        }
    }

    pub fn kitty_neighbor(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
            Self::Up => "top",
            Self::Down => "bottom",
        }
    }

    pub fn tmux_flag(self) -> &'static str {
        match self {
            Self::Left => "L",
            Self::Right => "R",
            Self::Up => "U",
            Self::Down => "D",
        }
    }

    fn nvim_wincmd_char(self) -> &'static str {
        match self {
            Self::Left => "h",
            Self::Right => "l",
            Self::Up => "k",
            Self::Down => "j",
        }
    }

    fn nvim_entry_assist_char(self) -> &'static str {
        match self {
            Self::Left => "l",
            Self::Right => "h",
            Self::Up => "j",
            Self::Down => "k",
        }
    }

    fn tmux_edge_flag(self) -> &'static str {
        match self {
            Self::Left => "#{pane_at_left}",
            Self::Right => "#{pane_at_right}",
            Self::Up => "#{pane_at_top}",
            Self::Down => "#{pane_at_bottom}",
        }
    }
}

pub struct TmuxRuntime {
    pub tty: String,
    pub socket_path: Option<String>,
}

pub struct NvimRuntime {
    pub socket_path: String,
}

pub struct TerminalRuntime {
    pub tty: Option<String>,
    pub tmux: Option<TmuxRuntime>,
    pub nvim: Option<NvimRuntime>,
}

struct KittyProbeResult {
    tmux: Option<TmuxRuntime>,
    nvim_socket: Option<String>,
}

enum KittyRuntimeProbe {
    Found(KittyProbeResult),
    NothingFound,
    Unavailable,
}

pub fn debug_enabled() -> bool {
    match env::var("HYPR_NAV_DEBUG") {
        Ok(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            !normalized.is_empty()
                && normalized != "0"
                && normalized != "false"
                && normalized != "off"
                && normalized != "no"
        }
        Err(_) => false,
    }
}

pub fn debug_log(component: &str, message: &str) {
    if debug_enabled() {
        eprintln!("[hypr-nav][{}] {}", component, message);
    }
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

fn read_process_comm(pid: u32) -> Option<String> {
    let comm = fs::read_to_string(format!("/proc/{}/comm", pid)).ok()?;
    Some(comm.trim().to_ascii_lowercase())
}

fn process_matches_terminal_name(pid: u32, terminal: &str) -> bool {
    let terminal_lower = terminal.to_ascii_lowercase();

    if let Some(comm) = read_process_comm(pid) {
        if comm == terminal_lower || comm.contains(&terminal_lower) {
            return true;
        }
    }

    if let Ok(cmdline) = fs::read(format!("/proc/{}/cmdline", pid)) {
        if let Some(arg0) = cmdline.split(|b| *b == 0).next() {
            if let Ok(arg0_str) = std::str::from_utf8(arg0) {
                let arg0_name = std::path::Path::new(arg0_str)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(arg0_str)
                    .to_ascii_lowercase();
                if arg0_name == terminal_lower {
                    return true;
                }
            }
        }
    }

    if let Ok(path) = fs::read_link(format!("/proc/{}/exe", pid)) {
        if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            if name.eq_ignore_ascii_case(&terminal_lower) {
                return true;
            }
        }
    }

    false
}

/// Check whether the active window is a terminal using both Hypr class and PID metadata.
pub fn is_terminal_window(class: &str, pid: u32) -> bool {
    if is_terminal_class(class) {
        return true;
    }

    KNOWN_TERMINALS
        .iter()
        .any(|terminal| process_matches_terminal_name(pid, terminal))
}

pub fn is_kitty_window(class: &str, pid: u32) -> bool {
    class.to_ascii_lowercase().contains("kitty") || process_matches_terminal_name(pid, "kitty")
}

fn hypr_socket_names() -> [&'static str; 2] {
    [".socket.sock", "socket.sock"]
}

fn valid_hypr_socket_paths(dir: &Path) -> Vec<PathBuf> {
    hypr_socket_names()
        .into_iter()
        .map(|name| dir.join(name))
        .filter(|path| {
            fs::metadata(path)
                .map(|meta| meta.file_type().is_socket())
                .unwrap_or(false)
        })
        .collect()
}

fn find_hyprland_socket_with(
    xdg_runtime_dir: &str,
    instance_signature: Option<&str>,
) -> Option<PathBuf> {
    let hypr_root = Path::new(xdg_runtime_dir).join("hypr");

    if let Some(sig) = instance_signature.filter(|sig| !sig.trim().is_empty()) {
        return valid_hypr_socket_paths(&hypr_root.join(sig))
            .into_iter()
            .next();
    }

    let mut candidates = Vec::new();
    let entries = fs::read_dir(&hypr_root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            candidates.extend(valid_hypr_socket_paths(&path));
        }
    }

    if candidates.len() == 1 {
        return candidates.pop();
    }

    if candidates.len() > 1 {
        debug_log(
            "lib",
            &format!(
                "multiple hypr sockets found under {}; refusing ambiguous fallback",
                hypr_root.display()
            ),
        );
    }

    None
}

/// Find the Hyprland socket path
pub fn find_hyprland_socket() -> Option<PathBuf> {
    let xdg = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let sig = env::var("HYPRLAND_INSTANCE_SIGNATURE").ok();
    let socket = find_hyprland_socket_with(&xdg, sig.as_deref());

    if let Some(ref path) = socket {
        debug_log("lib", &format!("hypr socket selected: {}", path.display()));
    } else {
        debug_log("lib", "no usable hypr socket found");
    }

    socket
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
        (Some(c), Some(p)) => {
            debug_log("lib", &format!("active window class={} pid={}", c, p));
            Some((c, p))
        }
        _ => {
            debug_log("lib", "active window query returned incomplete data");
            None
        }
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

fn parse_nvim_socket_from_environ(environ: &[u8]) -> Option<String> {
    for entry in environ.split(|b| *b == 0) {
        if let Some(value) = entry.strip_prefix(b"NVIM=") {
            if let Ok(s) = std::str::from_utf8(value) {
                let s = s.trim();
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
        if let Some(value) = entry.strip_prefix(b"NVIM_LISTEN_ADDRESS=") {
            if let Ok(s) = std::str::from_utf8(value) {
                let s = s.trim();
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

fn read_nvim_socket_from_environ(pid: u32) -> Option<String> {
    let environ = fs::read(format!("/proc/{}/environ", pid)).ok()?;
    parse_nvim_socket_from_environ(&environ)
}

fn process_is_nvim(pid: u32) -> bool {
    if let Some(comm) = read_process_comm(pid) {
        return comm == "nvim";
    }
    false
}

fn find_nvim_listen_socket(pid: u32) -> Option<String> {
    // Check --listen argument in cmdline
    if let Ok(cmdline) = fs::read(format!("/proc/{}/cmdline", pid)) {
        let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
        for (i, arg) in args.iter().enumerate() {
            if let Ok(s) = std::str::from_utf8(arg) {
                if s == "--listen" {
                    if let Some(next) = args.get(i + 1) {
                        if let Ok(path) = std::str::from_utf8(next) {
                            let path = path.trim();
                            if !path.is_empty() {
                                return Some(path.to_string());
                            }
                        }
                    }
                }
                // Handle --listen=<path> form
                if let Some(path) = s.strip_prefix("--listen=") {
                    let path = path.trim();
                    if !path.is_empty() {
                        return Some(path.to_string());
                    }
                }
            }
        }
    }

    // Fallback: neovim >= 0.9 auto-creates sockets at $XDG_RUNTIME_DIR/nvim.<pid>.0
    if let Ok(xdg) = env::var("XDG_RUNTIME_DIR") {
        let auto_socket = format!("{}/nvim.{}.0", xdg, pid);
        if std::path::Path::new(&auto_socket).exists() {
            return Some(auto_socket);
        }
    }

    None
}

fn nvim_socket_is_live(socket: &str) -> bool {
    if std::path::Path::new(socket).exists() {
        return UnixStream::connect(socket).is_ok();
    }

    // Some setups expose nvim remote endpoints as host:port.
    // Let command execution decide in that case.
    socket.contains(':')
}

/// Check if the nvim window is at the edge in the given direction.
/// Returns true when at edge (no neighbor), or on error (fail-open to fall through).
pub fn is_nvim_at_edge(socket: &str, direction: Direction) -> bool {
    // winnr() == winnr('h') is true when there's no neighbor to the left
    let expr = format!("winnr()==winnr('{}')", direction.nvim_wincmd_char());
    let output = Command::new("nvim")
        .args(["--server", socket, "--remote-expr", &expr])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let result = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let at_edge = result == "1";
            debug_log(
                "lib",
                &format!(
                    "is_nvim_at_edge socket={} dir={} -> {}",
                    socket,
                    direction.tmux_flag(),
                    at_edge
                ),
            );
            at_edge
        }
        _ => {
            debug_log(
                "lib",
                &format!(
                    "is_nvim_at_edge socket={} dir={} -> true (error, fail-open)",
                    socket,
                    direction.tmux_flag()
                ),
            );
            true
        }
    }
}

/// Navigate to the nvim split in the given direction.
/// Returns true if the command was sent successfully.
pub fn try_nvim_navigate(socket: &str, direction: Direction) -> bool {
    // Send <C-w>{dir} keysequence
    let keys = format!("<C-w>{}", direction.nvim_wincmd_char());
    let result = Command::new("nvim")
        .args(["--server", socket, "--remote-send", &keys])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    debug_log(
        "lib",
        &format!(
            "try_nvim_navigate socket={} dir={} -> {}",
            socket,
            direction.tmux_flag(),
            result
        ),
    );
    result
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

fn process_has_tmux(pid: u32) -> bool {
    if let Some(comm) = read_process_comm(pid) {
        if comm == "tmux" || comm.starts_with("tmux:") {
            return true;
        }
    }

    if let Ok(cmdline) = fs::read(format!("/proc/{}/cmdline", pid)) {
        if let Some(arg0) = cmdline.split(|b| *b == 0).next() {
            let arg0 = String::from_utf8_lossy(arg0);
            let basename = std::path::Path::new(arg0.as_ref())
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(arg0.as_ref())
                .to_ascii_lowercase();
            return basename == "tmux";
        }
    }
    false
}

fn kitty_socket_path() -> PathBuf {
    let xdg = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(xdg).join("kitty")
}

pub fn kitty_control_socket_uri() -> Option<String> {
    if let Ok(listen_on) = env::var("KITTY_LISTEN_ON") {
        if let Some(uri) = normalize_kitty_listen_on(&listen_on) {
            return Some(uri);
        }
    }

    let kitty_socket = kitty_socket_path();
    if kitty_socket.exists() {
        Some(format!("unix:{}", kitty_socket.display()))
    } else {
        None
    }
}

fn normalize_kitty_listen_on(listen_on: &str) -> Option<String> {
    let listen_on = listen_on.trim();
    if listen_on.is_empty() {
        return None;
    }

    // Preserve explicit kitty endpoint schemes (e.g. unix:, tcp:).
    if listen_on.contains(':') {
        return Some(listen_on.to_string());
    }

    Some(format!("unix:{}", listen_on))
}

pub fn try_close_focused_kitty_window() -> bool {
    let kitty_uri = match kitty_control_socket_uri() {
        Some(uri) => uri,
        None => {
            debug_log("lib", "kitty socket unavailable for focused close");
            return false;
        }
    };

    let result = Command::new("kitty")
        .args([
            "@",
            "--to",
            &kitty_uri,
            "close-window",
            "--match",
            "state:focused",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);

    debug_log(
        "lib",
        &format!(
            "kitty focused close socket={} match=state:focused -> {}",
            kitty_uri, result
        ),
    );
    result
}

fn find_focused_index(items: &[Value]) -> Option<usize> {
    items.iter().position(|item| {
        item.get("is_focused")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    })
}

fn read_pids_from_kitty_window(window: &Value) -> Vec<u32> {
    let mut pids = Vec::new();
    let mut seen = HashSet::new();

    if let Some(procs) = window.get("foreground_processes").and_then(Value::as_array) {
        for proc_info in procs {
            if let Some(pid) = proc_info.get("pid").and_then(Value::as_u64) {
                if let Ok(pid_u32) = u32::try_from(pid) {
                    if seen.insert(pid_u32) {
                        pids.push(pid_u32);
                    }
                }
            }
        }
    }

    if let Some(pid) = window.get("pid").and_then(Value::as_u64) {
        if let Ok(pid_u32) = u32::try_from(pid) {
            if seen.insert(pid_u32) {
                pids.push(pid_u32);
            }
        }
    }

    pids
}

fn parse_focused_kitty_pids(json: &str) -> Option<Vec<u32>> {
    let parsed: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let os_windows = match parsed.as_array() {
        Some(v) if !v.is_empty() => v,
        _ => return None,
    };
    let os_window = &os_windows[find_focused_index(os_windows)?];

    let tabs = match os_window.get("tabs").and_then(Value::as_array) {
        Some(v) if !v.is_empty() => v,
        _ => return None,
    };
    let tab = &tabs[find_focused_index(tabs)?];

    let windows = match tab.get("windows").and_then(Value::as_array) {
        Some(v) if !v.is_empty() => v,
        _ => return None,
    };
    let window = &windows[find_focused_index(windows)?];

    Some(read_pids_from_kitty_window(window))
}

fn detect_terminal_runtime_from_kitty() -> KittyRuntimeProbe {
    let kitty_uri = match kitty_control_socket_uri() {
        Some(uri) => uri,
        None => return KittyRuntimeProbe::Unavailable,
    };

    let output = Command::new("kitty")
        .args(["@", "--to", &kitty_uri, "ls"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok();

    let output = match output {
        Some(out) => out,
        None => {
            debug_log(
                "lib",
                "kitty ls failed while resolving focused kitty context",
            );
            return KittyRuntimeProbe::Unavailable;
        }
    };

    if !output.status.success() {
        debug_log(
            "lib",
            "kitty ls failed while resolving focused kitty context",
        );
        return KittyRuntimeProbe::Unavailable;
    }

    let parsed = String::from_utf8_lossy(&output.stdout);
    let candidate_pids = parse_focused_kitty_pids(&parsed).unwrap_or_default();
    if candidate_pids.is_empty() {
        debug_log(
            "lib",
            "kitty ls returned no focused foreground pid candidates",
        );
        return KittyRuntimeProbe::Unavailable;
    }

    let mut tmux_runtime: Option<TmuxRuntime> = None;
    let mut nvim_socket: Option<String> = None;

    for pid in candidate_pids {
        let tty = read_process_tty(pid);
        let tmux_sock = read_tmux_socket_from_environ(pid);
        let has_tmux = tmux_sock.is_some() || process_has_tmux(pid);
        debug_log(
            "lib",
            &format!(
                "kitty-focused candidate pid={} tty={} tmux_socket={} has_tmux={}",
                pid,
                tty.as_deref().unwrap_or("<none>"),
                tmux_sock.as_deref().unwrap_or("<none>"),
                has_tmux
            ),
        );

        if tmux_runtime.is_none() && has_tmux {
            if let Some(ref tty) = tty {
                tmux_runtime = Some(TmuxRuntime {
                    tty: tty.clone(),
                    socket_path: tmux_sock,
                });
            }
        }

        // Check for nvim: is this process nvim itself?
        if nvim_socket.is_none() && process_is_nvim(pid) {
            nvim_socket = find_nvim_listen_socket(pid);
            debug_log(
                "lib",
                &format!(
                    "kitty-focused nvim process pid={} socket={}",
                    pid,
                    nvim_socket.as_deref().unwrap_or("<none>")
                ),
            );
        }

        // Check for nvim: is this a child of nvim (has $NVIM in environ)?
        if nvim_socket.is_none() {
            nvim_socket = read_nvim_socket_from_environ(pid);
            if nvim_socket.is_some() {
                debug_log(
                    "lib",
                    &format!(
                        "kitty-focused nvim socket from environ pid={} socket={}",
                        pid,
                        nvim_socket.as_deref().unwrap_or("<none>")
                    ),
                );
            }
        }

        if tmux_runtime.is_some() && nvim_socket.is_some() {
            break;
        }
    }

    if tmux_runtime.is_some() || nvim_socket.is_some() {
        KittyRuntimeProbe::Found(KittyProbeResult {
            tmux: tmux_runtime,
            nvim_socket,
        })
    } else {
        debug_log(
            "lib",
            "kitty-focused context found but no tmux or nvim in focused window",
        );
        KittyRuntimeProbe::NothingFound
    }
}

/// Combined detection: find TTY, tmux presence, tmux socket, and nvim socket from process tree.
pub fn detect_terminal_runtime(pid: u32, class: &str) -> TerminalRuntime {
    let mut tmux_result: Option<TmuxRuntime> = None;
    let mut nvim_result: Option<NvimRuntime> = None;
    let mut kitty_nvim_socket: Option<String> = None;

    // Kitty fast-path: check focused PIDs for both tmux and nvim
    let kitty_by_class = class.to_ascii_lowercase().contains("kitty");
    let kitty_by_pid = process_matches_terminal_name(pid, "kitty");
    let mut kitty_authoritative_nothing = false;
    if kitty_by_class || kitty_by_pid {
        let probe_authoritative = kitty_by_class;
        if kitty_by_pid && !kitty_by_class {
            debug_log(
                "lib",
                &format!(
                    "active pid={} is kitty with custom class={} ; using kitty-focused probe",
                    pid, class
                ),
            );
        }
        match detect_terminal_runtime_from_kitty() {
            KittyRuntimeProbe::Found(result) => {
                if let Some(ref tmux) = result.tmux {
                    debug_log(
                        "lib",
                        &format!(
                            "tmux runtime from kitty tty={} socket={}",
                            tmux.tty,
                            tmux.socket_path.as_deref().unwrap_or("<default>")
                        ),
                    );
                }
                if let Some(ref socket) = result.nvim_socket {
                    debug_log("lib", &format!("nvim socket from kitty: {}", socket));
                }
                tmux_result = result.tmux;
                kitty_nvim_socket = result.nvim_socket;
            }
            KittyRuntimeProbe::NothingFound => {
                if probe_authoritative {
                    debug_log("lib", "kitty-focused probe confirms no tmux or nvim");
                    kitty_authoritative_nothing = true;
                } else {
                    debug_log(
                        "lib",
                        "kitty-focused probe found nothing for custom class; trying process tree",
                    );
                }
            }
            KittyRuntimeProbe::Unavailable => {}
        }
    }

    // BFS through process tree to find TTY, tmux, and nvim
    let mut tty: Option<String> = None;
    let mut has_tmux = false;
    let mut tmux_socket_path: Option<String> = None;
    let mut nvim_socket: Option<String> = kitty_nvim_socket;

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
            has_tmux = process_has_tmux(current_pid);
        }

        if tmux_socket_path.is_none() {
            tmux_socket_path = read_tmux_socket_from_environ(current_pid);
            if tmux_socket_path.is_some() {
                has_tmux = true;
                if current_tty.is_some() {
                    tty = current_tty.clone();
                }
            }
        }

        // Check for nvim: is this process nvim itself?
        if nvim_socket.is_none() && process_is_nvim(current_pid) {
            nvim_socket = find_nvim_listen_socket(current_pid);
            debug_log(
                "lib",
                &format!(
                    "found nvim process pid={} socket={}",
                    current_pid,
                    nvim_socket.as_deref().unwrap_or("<none>")
                ),
            );
        }

        // Check for nvim: is this a child of nvim (has $NVIM in environ)?
        if nvim_socket.is_none() {
            if let Some(s) = read_nvim_socket_from_environ(current_pid) {
                nvim_socket = Some(s);
                debug_log(
                    "lib",
                    &format!(
                        "found nvim socket from environ of pid={} socket={}",
                        current_pid,
                        nvim_socket.as_deref().unwrap_or("<none>")
                    ),
                );
            }
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

    // Build tmux result from BFS if not already found via kitty
    if tmux_result.is_none() && !kitty_authoritative_nothing {
        if has_tmux {
            let runtime = tty.clone().map(|tty| TmuxRuntime {
                tty,
                socket_path: tmux_socket_path,
            });
            if let Some(r) = runtime.as_ref() {
                debug_log(
                    "lib",
                    &format!(
                        "tmux runtime tty={} socket={}",
                        r.tty,
                        r.socket_path.as_deref().unwrap_or("<default>")
                    ),
                );
            } else {
                debug_log("lib", "tmux detected but tty missing");
            }
            tmux_result = runtime;
        } else {
            debug_log("lib", &format!("no tmux runtime under pid {}", pid));
        }
    }

    // Build nvim result, validating socket liveness
    if !kitty_authoritative_nothing {
        if let Some(socket) = nvim_socket {
            if nvim_socket_is_live(&socket) {
                debug_log("lib", &format!("nvim runtime socket={} (live)", socket));
                nvim_result = Some(NvimRuntime {
                    socket_path: socket,
                });
            } else {
                debug_log("lib", &format!("nvim socket={} is stale, ignoring", socket));
            }
        }
    }

    TerminalRuntime {
        tty,
        tmux: tmux_result,
        nvim: nvim_result,
    }
}

/// Combined detection: find TTY, tmux presence, and tmux socket from process tree.
/// Delegates to detect_terminal_runtime and returns only the tmux portion.
pub fn detect_tmux_runtime(pid: u32, class: &str) -> Option<TmuxRuntime> {
    detect_terminal_runtime(pid, class).tmux
}

/// Attempt nvim entry assist: navigate to opposite-edge window on cross-window entry.
/// Returns true if entry assist was applied (multiple windows and navigation succeeded).
pub fn try_nvim_entry_assist(socket: &str, direction: Direction) -> bool {
    // Check if nvim has multiple windows
    let output = Command::new("nvim")
        .args(["--server", socket, "--remote-expr", "winnr('$')"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    let win_count: usize = match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .unwrap_or(1),
        _ => return false,
    };

    if win_count <= 1 {
        debug_log(
            "lib",
            &format!("nvim entry assist skip: single window socket={}", socket),
        );
        return false;
    }

    let opposite = direction.nvim_entry_assist_char();
    let keys = format!("999<C-w>{}", opposite);
    let result = Command::new("nvim")
        .args(["--server", socket, "--remote-send", &keys])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    debug_log(
        "lib",
        &format!(
            "try_nvim_entry_assist socket={} dir={} opposite={} -> {}",
            socket,
            direction.tmux_flag(),
            opposite,
            result
        ),
    );
    result
}

fn tmux_command(socket_path: Option<&str>) -> Command {
    let mut command = Command::new("tmux");
    if let Some(path) = socket_path.filter(|path| !path.is_empty()) {
        command.args(["-S", path]);
    }
    command
}

pub fn tmux_capture(args: &[&str], socket_path: Option<&str>) -> Option<String> {
    let output = tmux_command(socket_path)
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

pub fn tmux_status(args: &[&str], socket_path: Option<&str>) -> bool {
    tmux_command(socket_path)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
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
        debug_log(
            "lib",
            &format!(
                "find_tmux_session tty={} socket={} -> <none> (tmux error)",
                tty,
                socket_path.unwrap_or("<default>")
            ),
        );
        return None;
    }

    let clients = String::from_utf8_lossy(&output.stdout);
    let session = parse_tmux_client_session(&clients, tty);
    debug_log(
        "lib",
        &format!(
            "find_tmux_session tty={} socket={} -> {}",
            tty,
            socket_path.unwrap_or("<default>"),
            session.as_deref().unwrap_or("<none>")
        ),
    );
    session
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
        debug_log(
            "lib",
            &format!(
                "find_tmux_client_pane tty={} socket={} -> <none> (tmux error)",
                tty,
                socket_path.unwrap_or("<default>")
            ),
        );
        return None;
    }

    let clients = String::from_utf8_lossy(&output.stdout);
    let pane = parse_tmux_client_pane(&clients, tty);
    debug_log(
        "lib",
        &format!(
            "find_tmux_client_pane tty={} socket={} -> {}",
            tty,
            socket_path.unwrap_or("<default>"),
            pane.as_deref().unwrap_or("<none>")
        ),
    );
    pane
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
        debug_log(
            "lib",
            &format!(
                "find_tmux_pane_by_tty tty={} socket={} -> <none> (tmux error)",
                tty,
                socket_path.unwrap_or("<default>")
            ),
        );
        return None;
    }

    let panes = String::from_utf8_lossy(&output.stdout);
    let pane = parse_tmux_pane_by_tty(&panes, tty);
    debug_log(
        "lib",
        &format!(
            "find_tmux_pane_by_tty tty={} socket={} -> {}",
            tty,
            socket_path.unwrap_or("<default>"),
            pane.as_deref().unwrap_or("<none>")
        ),
    );
    pane
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
        debug_log(
            "lib",
            &format!(
                "find_tmux_session_by_pane_tty tty={} socket={} -> <none> (tmux error)",
                tty,
                socket_path.unwrap_or("<default>")
            ),
        );
        return None;
    }

    let panes = String::from_utf8_lossy(&output.stdout);
    let session = parse_tmux_session_by_pane_tty(&panes, tty);
    debug_log(
        "lib",
        &format!(
            "find_tmux_session_by_pane_tty tty={} socket={} -> {}",
            tty,
            socket_path.unwrap_or("<default>"),
            session.as_deref().unwrap_or("<none>")
        ),
    );
    session
}

/// Check if the active pane in the session is at the edge in the given direction
pub fn is_pane_at_edge(session: &str, direction: Direction, socket_path: Option<&str>) -> bool {
    let output = tmux_command(socket_path)
        .args([
            "display-message",
            "-t",
            session,
            "-p",
            direction.tmux_edge_flag(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let result = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let at_edge = result == "1";
            debug_log(
                "lib",
                &format!(
                    "is_pane_at_edge target={} dir={} socket={} -> {}",
                    session,
                    direction.tmux_flag(),
                    socket_path.unwrap_or("<default>"),
                    at_edge
                ),
            );
            return at_edge;
        }
    }
    debug_log(
        "lib",
        &format!(
            "is_pane_at_edge target={} dir={} socket={} -> false (tmux error)",
            session,
            direction.tmux_flag(),
            socket_path.unwrap_or("<default>")
        ),
    );
    false
}

pub struct TmuxSessionInfo {
    pub name: String,
    pub is_named: bool,
    pub window_count: usize,
    pub pane_count: usize,
}

fn parse_tmux_session_info_output(result: &str) -> Option<TmuxSessionInfo> {
    let mut parts = result.trim().splitn(3, '\t');
    let name = parts.next()?.trim().to_string();
    let pane_count = parts.next()?.trim().parse().ok()?;
    let window_count = parts.next()?.trim().parse().ok()?;

    let is_named = name.parse::<u32>().is_err();

    Some(TmuxSessionInfo {
        name,
        is_named,
        window_count,
        pane_count,
    })
}

pub fn get_tmux_session_info(session: &str, socket_path: Option<&str>) -> Option<TmuxSessionInfo> {
    // Use a stable delimiter because session names may contain spaces.
    // Format: #{session_name}\t#{window_panes}\t#{session_windows}
    let output = tmux_command(socket_path)
        .args([
            "display-message",
            "-t",
            session,
            "-p",
            "#{session_name}\t#{window_panes}\t#{session_windows}",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        debug_log(
            "lib",
            &format!(
                "get_tmux_session_info target={} socket={} -> <none> (tmux error)",
                session,
                socket_path.unwrap_or("<default>")
            ),
        );
        return None;
    }

    let result = String::from_utf8_lossy(&output.stdout);
    if let Some(info) = parse_tmux_session_info_output(&result) {
        debug_log(
            "lib",
            &format!(
                "session_info target={} socket={} name={} named={} panes={} windows={}",
                session,
                socket_path.unwrap_or("<default>"),
                info.name,
                info.is_named,
                info.pane_count,
                info.window_count
            ),
        );
        Some(info)
    } else {
        debug_log(
            "lib",
            &format!(
                "get_tmux_session_info target={} socket={} -> <none> (parse error)",
                session,
                socket_path.unwrap_or("<default>")
            ),
        );
        None
    }
}

pub fn hypr_dispatch(socket_path: &PathBuf, dispatcher: &str) {
    match UnixStream::connect(socket_path) {
        Ok(mut stream) => {
            let cmd = format!("dispatch {}", dispatcher);
            debug_log("lib", &format!("hypr dispatch: {}", cmd));
            if let Err(err) = stream.write_all(cmd.as_bytes()) {
                debug_log("lib", &format!("hypr dispatch write failed: {}", err));
                return;
            }
            if let Err(err) = stream.shutdown(std::net::Shutdown::Both) {
                debug_log("lib", &format!("hypr dispatch shutdown failed: {}", err));
            }
        }
        Err(err) => {
            debug_log("lib", &format!("hypr dispatch connect failed: {}", err));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::net::UnixListener;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_test_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "hypr-nav-{}-{}-{}",
            name,
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(&dir).expect("test temp dir should be created");
        dir
    }

    #[test]
    fn direction_parse_supports_aliases() {
        assert_eq!(Direction::parse("h"), Some(Direction::Left));
        assert_eq!(Direction::parse("right"), Some(Direction::Right));
        assert_eq!(Direction::parse("u"), Some(Direction::Up));
        assert_eq!(Direction::parse("down"), Some(Direction::Down));
        assert_eq!(Direction::parse("bogus"), None);
    }

    #[test]
    fn find_hyprland_socket_with_uses_unique_fallback_socket() {
        let runtime_dir = temp_test_dir("unique-socket");
        let hypr_dir = runtime_dir.join("hypr").join("instance-a");
        fs::create_dir_all(&hypr_dir).expect("hypr dir should exist");
        let socket_path = hypr_dir.join(".socket.sock");
        let _listener = UnixListener::bind(&socket_path).expect("socket should bind");

        let found = find_hyprland_socket_with(runtime_dir.to_str().unwrap(), None);
        assert_eq!(found, Some(socket_path));

        let _ = fs::remove_dir_all(runtime_dir);
    }

    #[test]
    fn find_hyprland_socket_with_rejects_ambiguous_fallback_sockets() {
        let runtime_dir = temp_test_dir("ambiguous-socket");
        let socket_a_dir = runtime_dir.join("hypr").join("instance-a");
        let socket_b_dir = runtime_dir.join("hypr").join("instance-b");
        fs::create_dir_all(&socket_a_dir).expect("first hypr dir should exist");
        fs::create_dir_all(&socket_b_dir).expect("second hypr dir should exist");
        let _listener_a = UnixListener::bind(socket_a_dir.join(".socket.sock"))
            .expect("first socket should bind");
        let _listener_b = UnixListener::bind(socket_b_dir.join("socket.sock"))
            .expect("second socket should bind");

        let found = find_hyprland_socket_with(runtime_dir.to_str().unwrap(), None);
        assert_eq!(found, None);

        let _ = fs::remove_dir_all(runtime_dir);
    }

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

    #[test]
    fn parse_focused_kitty_pids_prefers_focused_os_window_tab_and_window() {
        let data = r#"
[
  {
    "is_focused": false,
    "tabs": [
      {"is_focused": true, "windows": [{"is_focused": true, "pid": 999}]}
    ]
  },
  {
    "is_focused": true,
    "tabs": [
      {
        "is_focused": true,
        "windows": [
          {
            "is_focused": false,
            "pid": 1000
          },
          {
            "is_focused": true,
            "pid": 2000,
            "foreground_processes": [{"pid": 2001}, {"pid": 2002}]
          }
        ]
      }
    ]
  }
]
"#;

        assert_eq!(parse_focused_kitty_pids(data), Some(vec![2001, 2002, 2000]));
    }

    #[test]
    fn parse_focused_kitty_pids_returns_empty_on_invalid_json() {
        assert_eq!(parse_focused_kitty_pids("not-json"), None);
    }

    #[test]
    fn parse_focused_kitty_pids_returns_none_without_focus_markers() {
        let data = r#"
[
  {
    "tabs": [
      {
        "windows": [
          {"pid": 2000}
        ]
      }
    ]
  }
]
"#;
        assert_eq!(parse_focused_kitty_pids(data), None);
    }

    #[test]
    fn parse_nvim_socket_from_environ_finds_nvim_entry() {
        let env = b"SHELL=/bin/zsh\0NVIM=/run/user/1000/nvim.12345.0\0";
        assert_eq!(
            parse_nvim_socket_from_environ(env),
            Some("/run/user/1000/nvim.12345.0".to_string())
        );
    }

    #[test]
    fn parse_nvim_socket_from_environ_finds_legacy_listen_address() {
        let env = b"SHELL=/bin/zsh\0NVIM_LISTEN_ADDRESS=/tmp/nvimsocket\0";
        assert_eq!(
            parse_nvim_socket_from_environ(env),
            Some("/tmp/nvimsocket".to_string())
        );
    }

    #[test]
    fn parse_nvim_socket_from_environ_returns_none_when_absent() {
        let env = b"SHELL=/bin/zsh\0PATH=/usr/bin\0";
        assert_eq!(parse_nvim_socket_from_environ(env), None);
    }

    #[test]
    fn parse_nvim_socket_from_environ_ignores_empty_values() {
        let env = b"NVIM=\0NVIM_LISTEN_ADDRESS=\0";
        assert_eq!(parse_nvim_socket_from_environ(env), None);
    }

    #[test]
    fn parse_tmux_session_info_output_handles_named_session_with_spaces() {
        let info = parse_tmux_session_info_output("work session\t3\t2")
            .expect("session info should parse");
        assert_eq!(info.name, "work session");
        assert!(info.is_named);
        assert_eq!(info.pane_count, 3);
        assert_eq!(info.window_count, 2);
    }

    #[test]
    fn parse_tmux_session_info_output_detects_numeric_session_name() {
        let info = parse_tmux_session_info_output("3\t1\t1").expect("session info should parse");
        assert_eq!(info.name, "3");
        assert!(!info.is_named);
        assert_eq!(info.pane_count, 1);
        assert_eq!(info.window_count, 1);
    }

    #[test]
    fn normalize_kitty_listen_on_preserves_tcp_uri() {
        assert_eq!(
            normalize_kitty_listen_on("tcp:127.0.0.1:5000"),
            Some("tcp:127.0.0.1:5000".to_string())
        );
    }

    #[test]
    fn normalize_kitty_listen_on_preserves_unix_uri() {
        assert_eq!(
            normalize_kitty_listen_on("unix:/tmp/kitty"),
            Some("unix:/tmp/kitty".to_string())
        );
    }

    #[test]
    fn normalize_kitty_listen_on_normalizes_bare_path() {
        assert_eq!(
            normalize_kitty_listen_on("/tmp/kitty"),
            Some("unix:/tmp/kitty".to_string())
        );
    }
}
