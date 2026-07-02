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

pub struct ActiveWindowInfo {
    pub address: String,
    pub class: String,
    pub pid: u32,
    pub title: Option<String>,
    pub focus_history_id: Option<i64>,
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
    static DEBUG_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DEBUG_ENABLED.get_or_init(|| match env::var("HYPR_NAV_DEBUG") {
        Ok(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            !normalized.is_empty()
                && normalized != "0"
                && normalized != "false"
                && normalized != "off"
                && normalized != "no"
        }
        Err(_) => false,
    })
}

/// Log a debug message when `HYPR_NAV_DEBUG` is enabled. Formatting is
/// skipped entirely when debugging is off, avoiding per-callsite allocations
/// on the hot keypress path.
#[macro_export]
macro_rules! debug_log {
    ($component:expr, $($arg:tt)*) => {
        if $crate::debug_enabled() {
            eprintln!("[hypr-nav][{}] {}", $component, format!($($arg)*));
        }
    };
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
        if class.eq_ignore_ascii_case(&terminal_name) {
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
        debug_log!(
            "lib",
            "multiple hypr sockets found under {}; refusing ambiguous fallback",
            hypr_root.display()
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
        debug_log!("lib", "hypr socket selected: {}", path.display());
    } else {
        debug_log!("lib", "no usable hypr socket found");
    }

    socket
}

fn normalize_hypr_address(raw: &str) -> Option<String> {
    let address = raw.trim();
    let hex = address.strip_prefix("0x").unwrap_or(address);
    if hex.is_empty() || hex == "0" || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", hex.to_ascii_lowercase()))
}

fn parse_active_window_info(response: &str) -> Option<ActiveWindowInfo> {
    let mut address = None;
    let mut class = None;
    let mut pid = None;
    let mut title = None;
    let mut focus_history_id = None;

    for line in response.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Window ") {
            if let Some((raw_address, _)) = rest.split_once(" -> ") {
                address = normalize_hypr_address(raw_address);
            }
        } else if let Some(c) = trimmed.strip_prefix("class: ") {
            class = Some(c.trim().to_string());
        } else if let Some(t) = trimmed.strip_prefix("title: ") {
            title = Some(t.trim().to_string());
        } else if let Some(p) = trimmed.strip_prefix("pid: ") {
            pid = p.trim().parse::<u32>().ok();
        } else if let Some(id) = trimmed.strip_prefix("focusHistoryID: ") {
            focus_history_id = id.trim().parse::<i64>().ok();
        }
    }

    match (address, class, pid) {
        (Some(a), Some(c), Some(p)) => Some(ActiveWindowInfo {
            address: a,
            class: c,
            pid: p,
            title,
            focus_history_id,
        }),
        _ => None,
    }
}

/// Get active window address, class and PID in a single Hyprland query.
pub fn get_active_window_snapshot(socket_path: &PathBuf) -> Option<ActiveWindowInfo> {
    let mut stream = UnixStream::connect(socket_path).ok()?;
    stream.write_all(b"activewindow").ok()?;
    stream.shutdown(std::net::Shutdown::Write).ok()?;

    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;

    match parse_active_window_info(&response) {
        Some(info) => {
            debug_log!(
                "lib",
                "active window address={} class={} pid={}",
                info.address,
                info.class,
                info.pid
            );
            Some(info)
        }
        None => {
            debug_log!("lib", "active window query returned incomplete data");
            None
        }
    }
}

/// Get active window class and PID in a single Hyprland query.
pub fn get_active_window_info(socket_path: &PathBuf) -> Option<(String, u32)> {
    let info = get_active_window_snapshot(socket_path)?;
    Some((info.class, info.pid))
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

fn looks_like_host_port(socket: &str) -> bool {
    // Check if socket looks like "host:port" format by splitting on the last colon
    if let Some((host, port_str)) = socket.rsplit_once(':') {
        // Host must be non-empty
        if host.is_empty() {
            return false;
        }
        // Port must be a valid u16
        port_str.parse::<u16>().is_ok()
    } else {
        false
    }
}

fn nvim_socket_is_live(socket: &str) -> bool {
    if std::path::Path::new(socket).exists() {
        return UnixStream::connect(socket).is_ok();
    }

    // Some setups expose nvim remote endpoints as host:port.
    // Only accept strings that parse as valid host:port endpoints.
    looks_like_host_port(socket)
}

/// Outcome of a mode-safe nvim split navigation attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvimNavOutcome {
    /// The window command executed and moved focus to a neighboring split.
    Moved,
    /// There is no neighbor in that direction; nvim reported the edge sentinel.
    AtEdge,
    /// The nvim RPC call failed to spawn or exited non-zero.
    Error,
}

const NVIM_EDGE_SENTINEL: &str = "HYPRNAV_EDGE";
const NVIM_SINGLE_WINDOW_SENTINEL: &str = "HYPRNAV_SINGLE";

/// Navigate to the nvim split in the given direction using a single mode-safe
/// `--remote-expr` call. The expression uses `execute()` to run the `wincmd`
/// ex command, which works regardless of nvim's current mode (normal,
/// insert, visual, ...) and never types into the buffer the way
/// `--remote-send`-ing `<C-w>{dir}` keys would. Callers should treat `Error`
/// the same as `AtEdge` (fail-open, fall through to the next nav layer).
pub fn nvim_navigate_or_edge(socket: &str, direction: Direction) -> NvimNavOutcome {
    let wincmd = direction.nvim_wincmd_char();
    let expr = format!(
        "winnr() == winnr('{wincmd}') ? '{sentinel}' : execute('wincmd {wincmd}')",
        wincmd = wincmd,
        sentinel = NVIM_EDGE_SENTINEL,
    );
    let output = Command::new("nvim")
        .args(["--server", socket, "--remote-expr", &expr])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    let outcome = match output {
        Ok(out) if out.status.success() => {
            let result = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if result == NVIM_EDGE_SENTINEL {
                NvimNavOutcome::AtEdge
            } else {
                NvimNavOutcome::Moved
            }
        }
        _ => NvimNavOutcome::Error,
    };

    debug_log!(
        "lib",
        "nvim_navigate_or_edge socket={} dir={} -> {:?}",
        socket,
        direction.tmux_flag(),
        outcome
    );
    outcome
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

/// Walk `/proc/<pid>/status` `PPid:` lines to determine whether `ancestor` is
/// `pid` itself or one of its ancestors, within `max_hops` hops. Stops at
/// pid 1/0 (init/kthreadd) and treats unreadable `/proc` entries as a
/// negative result (fail closed: an unverifiable ancestry claim is not
/// trusted).
fn pid_has_ancestor(pid: u32, ancestor: u32, max_hops: usize) -> bool {
    if pid == ancestor {
        return true;
    }

    let mut current = pid;
    for _ in 0..max_hops {
        let status = match fs::read_to_string(format!("/proc/{}/status", current)) {
            Ok(status) => status,
            Err(_) => return false,
        };
        let ppid = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|rest| rest.trim().parse::<u32>().ok());
        let ppid = match ppid {
            Some(ppid) => ppid,
            None => return false,
        };
        if ppid == ancestor {
            return true;
        }
        if ppid == 0 || ppid == 1 {
            return false;
        }
        current = ppid;
    }

    false
}

/// Hop cap for `pid_has_ancestor` when validating that a kitty-reported
/// focused-window pid genuinely belongs to the Hyprland-active window's
/// process tree.
const KITTY_PROBE_ANCESTRY_MAX_HOPS: usize = 15;

fn detect_terminal_runtime_from_kitty(active_pid: u32) -> KittyRuntimeProbe {
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
            debug_log!(
                "lib",
                "kitty ls failed while resolving focused kitty context"
            );
            return KittyRuntimeProbe::Unavailable;
        }
    };

    if !output.status.success() {
        debug_log!(
            "lib",
            "kitty ls failed while resolving focused kitty context"
        );
        return KittyRuntimeProbe::Unavailable;
    }

    let parsed = String::from_utf8_lossy(&output.stdout);
    let candidate_pids = parse_focused_kitty_pids(&parsed).unwrap_or_default();
    if candidate_pids.is_empty() {
        debug_log!(
            "lib",
            "kitty ls returned no focused foreground pid candidates"
        );
        return KittyRuntimeProbe::Unavailable;
    }

    // With more than one kitty instance running, `kitty ls`'s notion of the
    // "focused" window belongs to whichever kitty process answered on the
    // resolved control socket, which may not be the Hyprland-active window
    // at all. Only trust candidate pids that are (or descend from) the
    // active window's pid; otherwise this probe result is meaningless and we
    // fall back to the process-tree BFS in the caller.
    let verified_pids: Vec<u32> = candidate_pids
        .iter()
        .copied()
        .filter(|&pid| pid_has_ancestor(pid, active_pid, KITTY_PROBE_ANCESTRY_MAX_HOPS))
        .collect();

    if verified_pids.is_empty() {
        debug_log!("lib",
                "kitty ls focused window does not belong to active window pid={}; ignoring probe (candidates={:?})",
                active_pid, candidate_pids
            );
        return KittyRuntimeProbe::Unavailable;
    }

    let mut tmux_runtime: Option<TmuxRuntime> = None;
    let mut nvim_socket: Option<String> = None;

    for pid in verified_pids {
        let tty = read_process_tty(pid);
        let tmux_sock = read_tmux_socket_from_environ(pid);
        let has_tmux = tmux_sock.is_some() || process_has_tmux(pid);
        debug_log!(
            "lib",
            "kitty-focused candidate pid={} tty={} tmux_socket={} has_tmux={}",
            pid,
            tty.as_deref().unwrap_or("<none>"),
            tmux_sock.as_deref().unwrap_or("<none>"),
            has_tmux
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
            debug_log!(
                "lib",
                "kitty-focused nvim process pid={} socket={}",
                pid,
                nvim_socket.as_deref().unwrap_or("<none>")
            );
        }

        // Check for nvim: is this a child of nvim (has $NVIM in environ)?
        if nvim_socket.is_none() {
            nvim_socket = read_nvim_socket_from_environ(pid);
            if nvim_socket.is_some() {
                debug_log!(
                    "lib",
                    "kitty-focused nvim socket from environ pid={} socket={}",
                    pid,
                    nvim_socket.as_deref().unwrap_or("<none>")
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
        debug_log!(
            "lib",
            "kitty-focused context found but no tmux or nvim in focused window"
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
            debug_log!(
                "lib",
                "active pid={} is kitty with custom class={} ; using kitty-focused probe",
                pid,
                class
            );
        }
        match detect_terminal_runtime_from_kitty(pid) {
            KittyRuntimeProbe::Found(result) => {
                if let Some(ref tmux) = result.tmux {
                    debug_log!(
                        "lib",
                        "tmux runtime from kitty tty={} socket={}",
                        tmux.tty,
                        tmux.socket_path.as_deref().unwrap_or("<default>")
                    );
                }
                if let Some(ref socket) = result.nvim_socket {
                    debug_log!("lib", "nvim socket from kitty: {}", socket);
                }
                tmux_result = result.tmux;
                kitty_nvim_socket = result.nvim_socket;
            }
            KittyRuntimeProbe::NothingFound => {
                if probe_authoritative {
                    debug_log!("lib", "kitty-focused probe confirms no tmux or nvim");
                    kitty_authoritative_nothing = true;
                } else {
                    debug_log!(
                        "lib",
                        "kitty-focused probe found nothing for custom class; trying process tree"
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

        if kitty_authoritative_nothing {
            // The kitty-focused probe already confirmed there is no tmux or
            // nvim in the focused window, so the tmux/nvim results this BFS
            // would otherwise compute are discarded below (guarded by
            // `!kitty_authoritative_nothing`). Only `tty` is still used in
            // this path, so skip the tmux/nvim probing work entirely and
            // stop as soon as `tty` resolves.
            if tty.is_some() {
                break;
            }
        } else {
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
                debug_log!(
                    "lib",
                    "found nvim process pid={} socket={}",
                    current_pid,
                    nvim_socket.as_deref().unwrap_or("<none>")
                );
            }

            // Check for nvim: is this a child of nvim (has $NVIM in environ)?
            if nvim_socket.is_none() {
                if let Some(s) = read_nvim_socket_from_environ(current_pid) {
                    nvim_socket = Some(s);
                    debug_log!(
                        "lib",
                        "found nvim socket from environ of pid={} socket={}",
                        current_pid,
                        nvim_socket.as_deref().unwrap_or("<none>")
                    );
                }
            }

            // Nothing left that can change the outcome: `tty` only changes
            // above while it is `None` or when `tmux_socket_path` is first
            // discovered (which only happens once, guarded by
            // `tmux_socket_path.is_none()`); `nvim_socket` only changes
            // while `None`. Once all four are resolved, no further pid can
            // alter any of them, so it's safe to stop walking.
            if tty.is_some() && has_tmux && tmux_socket_path.is_some() && nvim_socket.is_some() {
                break;
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
                debug_log!(
                    "lib",
                    "tmux runtime tty={} socket={}",
                    r.tty,
                    r.socket_path.as_deref().unwrap_or("<default>")
                );
            } else {
                debug_log!("lib", "tmux detected but tty missing");
            }
            tmux_result = runtime;
        } else {
            debug_log!("lib", "no tmux runtime under pid {}", pid);
        }
    }

    // Build nvim result, validating socket liveness
    if !kitty_authoritative_nothing {
        if let Some(socket) = nvim_socket {
            if nvim_socket_is_live(&socket) {
                debug_log!("lib", "nvim runtime socket={} (live)", socket);
                nvim_result = Some(NvimRuntime {
                    socket_path: socket,
                });
            } else {
                debug_log!("lib", "nvim socket={} is stale, ignoring", socket);
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
///
/// Mode-safe and single-spawn: one `--remote-expr` call checks the window count
/// and, when there is more than one window, runs `999wincmd {opposite}` via
/// `execute()` so it works regardless of nvim's current mode.
pub fn try_nvim_entry_assist(socket: &str, direction: Direction) -> bool {
    let opposite = direction.nvim_entry_assist_char();
    let expr = format!(
        "winnr('$') <= 1 ? '{sentinel}' : execute('999wincmd {opposite}')",
        sentinel = NVIM_SINGLE_WINDOW_SENTINEL,
        opposite = opposite,
    );
    let output = Command::new("nvim")
        .args(["--server", socket, "--remote-expr", &expr])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    let result = match output {
        Ok(out) if out.status.success() => {
            let result = String::from_utf8_lossy(&out.stdout).trim().to_string();
            result != NVIM_SINGLE_WINDOW_SENTINEL
        }
        _ => false,
    };

    debug_log!(
        "lib",
        "try_nvim_entry_assist socket={} dir={} opposite={} -> {}",
        socket,
        direction.tmux_flag(),
        opposite,
        result
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

/// Run a tmux `list-*` command whose `-F` format emits `<tty>\t<value>` rows,
/// and return the value for the row whose tty matches exactly.
///
/// `label` is used only for diagnostic logging, so each thin wrapper below
/// keeps its own name in `debug_log` output.
fn tmux_lookup_by_tty(
    label: &str,
    list_args: &[&str],
    tty: &str,
    socket_path: Option<&str>,
) -> Option<String> {
    let output = tmux_command(socket_path)
        .args(list_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        debug_log!(
            "lib",
            "{} tty={} socket={} -> <none> (tmux error)",
            label,
            tty,
            socket_path.unwrap_or("<default>")
        );
        return None;
    }

    let rows = String::from_utf8_lossy(&output.stdout);
    let value = parse_tmux_tty_keyed_value(&rows, tty);
    debug_log!(
        "lib",
        "{} tty={} socket={} -> {}",
        label,
        tty,
        socket_path.unwrap_or("<default>"),
        value.as_deref().unwrap_or("<none>")
    );
    value
}

/// Parse TAB-delimited `<tty>\t<value>` rows (tty first) and return the value
/// for the row whose tty matches exactly. Rows without a tab are malformed
/// and skipped; the value is returned verbatim (including internal spaces,
/// e.g. tmux session names) since only the tab is a field separator.
fn parse_tmux_tty_keyed_value(rows: &str, tty: &str) -> Option<String> {
    for line in rows.lines() {
        if let Some((key, value)) = line.split_once('\t') {
            let key = key.trim();
            let value = value.trim();
            if tty == key {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Find the tmux session for a given TTY
pub fn find_tmux_session(tty: &str, socket_path: Option<&str>) -> Option<String> {
    tmux_lookup_by_tty(
        "find_tmux_session",
        &["list-clients", "-F", "#{client_tty}\t#{client_session}"],
        tty,
        socket_path,
    )
}

/// Find the active tmux pane for a given client TTY
pub fn find_tmux_client_pane(tty: &str, socket_path: Option<&str>) -> Option<String> {
    tmux_lookup_by_tty(
        "find_tmux_client_pane",
        &["list-clients", "-F", "#{client_tty}\t#{pane_id}"],
        tty,
        socket_path,
    )
}

/// Find pane by pane tty when we discovered a pane PTY rather than client TTY.
pub fn find_tmux_pane_by_tty(tty: &str, socket_path: Option<&str>) -> Option<String> {
    tmux_lookup_by_tty(
        "find_tmux_pane_by_tty",
        &["list-panes", "-a", "-F", "#{pane_tty}\t#{pane_id}"],
        tty,
        socket_path,
    )
}

/// Find session by pane tty when we discovered a pane PTY rather than client TTY.
pub fn find_tmux_session_by_pane_tty(tty: &str, socket_path: Option<&str>) -> Option<String> {
    tmux_lookup_by_tty(
        "find_tmux_session_by_pane_tty",
        &["list-panes", "-a", "-F", "#{pane_tty}\t#{session_id}"],
        tty,
        socket_path,
    )
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
            debug_log!(
                "lib",
                "is_pane_at_edge target={} dir={} socket={} -> {}",
                session,
                direction.tmux_flag(),
                socket_path.unwrap_or("<default>"),
                at_edge
            );
            return at_edge;
        }
    }
    debug_log!(
        "lib",
        "is_pane_at_edge target={} dir={} socket={} -> false (tmux error)",
        session,
        direction.tmux_flag(),
        socket_path.unwrap_or("<default>")
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
        debug_log!(
            "lib",
            "get_tmux_session_info target={} socket={} -> <none> (tmux error)",
            session,
            socket_path.unwrap_or("<default>")
        );
        return None;
    }

    let result = String::from_utf8_lossy(&output.stdout);
    if let Some(info) = parse_tmux_session_info_output(&result) {
        debug_log!(
            "lib",
            "session_info target={} socket={} name={} named={} panes={} windows={}",
            session,
            socket_path.unwrap_or("<default>"),
            info.name,
            info.is_named,
            info.pane_count,
            info.window_count
        );
        Some(info)
    } else {
        debug_log!(
            "lib",
            "get_tmux_session_info target={} socket={} -> <none> (parse error)",
            session,
            socket_path.unwrap_or("<default>")
        );
        None
    }
}

/// Hyprland dispatcher action for Lua-IPC compatibility
pub enum HyprDispatch {
    /// Move focus in the given direction
    MoveFocus(Direction),
    /// Close a window at the given normalized address (e.g., "0xdeadbeef")
    CloseWindow(String),
}

impl HyprDispatch {
    /// Generate the Lua dispatcher payload for this action
    pub fn lua_payload(&self) -> String {
        match self {
            Self::MoveFocus(dir) => {
                format!(
                    "hl.dsp.focus({{direction = \"{}\"}})",
                    dir.hypr_movefocus_arg()
                )
            }
            Self::CloseWindow(address) => {
                format!("hl.dsp.window.close({{address = \"{}\"}})", address)
            }
        }
    }

    /// Generate the legacy (pre-Lua) dispatcher payload for this action
    pub fn legacy_payload(&self) -> String {
        match self {
            Self::MoveFocus(dir) => {
                format!("movefocus {}", dir.hypr_movefocus_arg())
            }
            Self::CloseWindow(address) => {
                format!("closewindow address:{}", address)
            }
        }
    }
}

pub fn hypr_dispatch(socket_path: &PathBuf, dispatcher: &str) -> bool {
    match UnixStream::connect(socket_path) {
        Ok(mut stream) => {
            let cmd = format!("dispatch {}", dispatcher);
            debug_log!("lib", "hypr dispatch: {}", cmd);
            if let Err(err) = stream.write_all(cmd.as_bytes()) {
                debug_log!("lib", "hypr dispatch write failed: {}", err);
                return false;
            }
            // The dispatch bytes are already written; a write-side shutdown
            // error should not make callers report a failed action, but we
            // still need to read Hyprland's reply to know whether it worked.
            if let Err(err) = stream.shutdown(std::net::Shutdown::Write) {
                debug_log!("lib", "hypr dispatch shutdown failed: {}", err);
            }
            let mut reply = String::new();
            if let Err(err) = stream.read_to_string(&mut reply) {
                debug_log!("lib", "hypr dispatch read failed: {}", err);
                return false;
            }
            let trimmed = reply.trim();
            if trimmed.to_lowercase().starts_with("ok") {
                true
            } else {
                debug_log!("lib", "hypr dispatch failed reply: {}", trimmed);
                false
            }
        }
        Err(err) => {
            debug_log!("lib", "hypr dispatch connect failed: {}", err);
            false
        }
    }
}

/// Send a dispatcher action via Lua-IPC, with automatic fallback to legacy syntax.
/// Attempts the Lua payload first; if that fails, retries with the legacy payload.
/// Returns true if either attempt succeeded, false if both failed.
pub fn hypr_dispatch_action(socket_path: &PathBuf, action: &HyprDispatch) -> bool {
    let lua_payload = action.lua_payload();
    if hypr_dispatch(socket_path, &lua_payload) {
        return true;
    }

    let legacy_payload = action.legacy_payload();
    debug_log!("lib", "lua dispatch failed, falling back to legacy syntax");
    hypr_dispatch(socket_path, &legacy_payload)
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
    fn parse_active_window_info_normalizes_address() {
        let response = "\
Window ABC123 -> terminal:
    class: kitty
    pid: 4242
";
        let info = parse_active_window_info(response).expect("active window should parse");
        assert_eq!(info.address, "0xabc123");
        assert_eq!(info.class, "kitty");
        assert_eq!(info.pid, 4242);
    }

    #[test]
    fn parse_active_window_info_preserves_prefixed_address() {
        let response = "\
Window 0xABC123 -> terminal:
    class: kitty
    pid: 4242
";
        let info = parse_active_window_info(response).expect("active window should parse");
        assert_eq!(info.address, "0xabc123");
    }

    #[test]
    fn parse_active_window_info_rejects_missing_or_invalid_address() {
        assert!(parse_active_window_info("class: kitty\npid: 4242\n").is_none());
        assert!(parse_active_window_info("Window 0 -> none:\nclass: kitty\npid: 4242\n").is_none());
        assert!(
            parse_active_window_info("Window abc;kill -> bad:\nclass: kitty\npid: 4242\n")
                .is_none()
        );
    }

    #[test]
    fn parse_tmux_tty_keyed_value_matches_exact_tty() {
        let data = "/dev/pts/2\t%11\n/dev/pts/9\t%42\n";
        assert_eq!(
            parse_tmux_tty_keyed_value(data, "/dev/pts/9"),
            Some("%42".to_string())
        );
    }

    #[test]
    fn parse_tmux_tty_keyed_value_ignores_malformed_rows_without_tab() {
        let data = "invalid-line\n/dev/pts/5\t%7\n";
        assert_eq!(
            parse_tmux_tty_keyed_value(data, "/dev/pts/5"),
            Some("%7".to_string())
        );
    }

    #[test]
    fn parse_tmux_tty_keyed_value_returns_none_when_tty_missing() {
        let data = "/dev/pts/2\t%11\n/dev/pts/9\t%42\n";
        assert_eq!(parse_tmux_tty_keyed_value(data, "/dev/pts/4"), None);
    }

    #[test]
    fn parse_tmux_tty_keyed_value_preserves_names_with_spaces() {
        let data = "/dev/pts/9\twork session\n";
        assert_eq!(
            parse_tmux_tty_keyed_value(data, "/dev/pts/9"),
            Some("work session".to_string())
        );
    }

    #[test]
    fn parse_tmux_tty_keyed_value_rejects_spaced_value_with_wrong_tty() {
        let data = "/dev/pts/9\twork session\n";
        assert_eq!(parse_tmux_tty_keyed_value(data, "/dev/pts/4"), None);
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

    #[test]
    fn looks_like_host_port_accepts_valid_ipv4_with_port() {
        assert!(looks_like_host_port("127.0.0.1:6666"));
    }

    #[test]
    fn looks_like_host_port_accepts_valid_hostname_with_port() {
        assert!(looks_like_host_port("localhost:8000"));
    }

    #[test]
    fn looks_like_host_port_rejects_empty_host() {
        assert!(!looks_like_host_port(":123"));
    }

    #[test]
    fn looks_like_host_port_rejects_empty_port() {
        assert!(!looks_like_host_port("foo:"));
    }

    #[test]
    fn looks_like_host_port_rejects_non_numeric_port() {
        assert!(!looks_like_host_port("foo:notaport"));
    }

    #[test]
    fn looks_like_host_port_rejects_port_out_of_range() {
        assert!(!looks_like_host_port("foo:99999"));
    }

    #[test]
    fn looks_like_host_port_rejects_socket_path() {
        assert!(!looks_like_host_port("/tmp/nvim.sock"));
    }

    #[test]
    fn pid_has_ancestor_true_for_identical_pid() {
        let me = std::process::id();
        assert!(pid_has_ancestor(me, me, KITTY_PROBE_ANCESTRY_MAX_HOPS));
    }

    #[test]
    fn pid_has_ancestor_true_for_real_parent() {
        // The current test process's real PPid is a genuine ancestor one
        // hop up; this mirrors the real-world case of a kitty ls foreground
        // pid (child) reporting Hyprland's active window pid (parent, kitty
        // itself) as an ancestor.
        let me = std::process::id();
        let status = fs::read_to_string("/proc/self/status")
            .expect("own /proc/self/status should be readable");
        let parent = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|rest| rest.trim().parse::<u32>().ok())
            .expect("own PPid should be parseable");

        assert!(pid_has_ancestor(me, parent, KITTY_PROBE_ANCESTRY_MAX_HOPS));
    }

    #[test]
    fn pid_has_ancestor_true_for_spawned_child() {
        // A freshly spawned child process should report this test process
        // as its ancestor.
        let mut child = Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("sleep should spawn");
        let child_pid = child.id();
        let me = std::process::id();

        assert!(pid_has_ancestor(
            child_pid,
            me,
            KITTY_PROBE_ANCESTRY_MAX_HOPS
        ));

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn pid_has_ancestor_false_for_unrelated_pid() {
        // pid 1 (init) does not have this test process as an ancestor: the
        // relationship only runs the other way.
        let me = std::process::id();
        assert!(!pid_has_ancestor(1, me, KITTY_PROBE_ANCESTRY_MAX_HOPS));
    }

    #[test]
    fn hypr_dispatch_lua_payload_movefocus_left() {
        let action = HyprDispatch::MoveFocus(Direction::Left);
        assert_eq!(action.lua_payload(), "hl.dsp.focus({direction = \"l\"})");
    }

    #[test]
    fn hypr_dispatch_lua_payload_movefocus_right() {
        let action = HyprDispatch::MoveFocus(Direction::Right);
        assert_eq!(action.lua_payload(), "hl.dsp.focus({direction = \"r\"})");
    }

    #[test]
    fn hypr_dispatch_lua_payload_movefocus_up() {
        let action = HyprDispatch::MoveFocus(Direction::Up);
        assert_eq!(action.lua_payload(), "hl.dsp.focus({direction = \"u\"})");
    }

    #[test]
    fn hypr_dispatch_lua_payload_movefocus_down() {
        let action = HyprDispatch::MoveFocus(Direction::Down);
        assert_eq!(action.lua_payload(), "hl.dsp.focus({direction = \"d\"})");
    }

    #[test]
    fn hypr_dispatch_legacy_payload_movefocus() {
        let action = HyprDispatch::MoveFocus(Direction::Left);
        assert_eq!(action.legacy_payload(), "movefocus l");
    }

    #[test]
    fn hypr_dispatch_lua_payload_closewindow() {
        let action = HyprDispatch::CloseWindow("0xdeadbeef".to_string());
        assert_eq!(
            action.lua_payload(),
            "hl.dsp.window.close({address = \"0xdeadbeef\"})"
        );
    }

    #[test]
    fn hypr_dispatch_legacy_payload_closewindow() {
        let action = HyprDispatch::CloseWindow("0xdeadbeef".to_string());
        assert_eq!(action.legacy_payload(), "closewindow address:0xdeadbeef");
    }
}
