#![forbid(unsafe_code)]

//! `hypr-nav` — Architecture 4A (`nav-v1` universal coalgebraic router).
//!
//! Layer 0 lives in Hyprland (`share/hypr-nav.lua`, sync fast path + monotone
//! `GEN` Epoch-CAS). Layer 1 lives in Kitty (`share/kitty_nav.py`, sync in-RAM
//! `no_ui` kitten). This binary owns the program-agnostic `nav-v1` recursive
//! core, Herdr/Neovim dialect shims, universal `$XDG_RUNTIME_DIR/nav-<pid>.sock`
//! routing, and stateless remote `mw` recursion (`--herdr`) over OpenSSH's
//! existing `ControlMaster`.

use rmpv::Value as Msg;
use serde_json::{Value as Json, json};
use std::collections::HashSet;
use std::io::{self, Cursor, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};
use std::{env, fs};

type R<T> = Result<T, String>;

const BUDGET: Duration = Duration::from_millis(1500);
const MAX_DEPTH: usize = 16;
const KITTY_PFX: &[u8] = b"\x1bP@kitty-cmd";
const KITTY_SFX: &[u8] = b"\x1b\\";

#[derive(Clone, Copy, Debug)]
pub(crate) struct Deadline(Instant);

impl Deadline {
    pub(crate) fn after(d: Duration) -> Self {
        Self(Instant::now() + d)
    }

    pub(crate) fn remaining(self) -> io::Result<Duration> {
        let left = self.0.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err(io::Error::new(io::ErrorKind::TimedOut, "budget elapsed"))
        } else {
            Ok(left)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dir {
    Left,
    Right,
    Up,
    Down,
}

impl Dir {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "left" => Some(Self::Left),
            "right" => Some(Self::Right),
            "up" => Some(Self::Up),
            "down" => Some(Self::Down),
            _ => None,
        }
    }
    pub(crate) fn name(self) -> &'static str {
        ["left", "right", "up", "down"][self as usize]
    }
    pub(crate) fn opposite(self) -> Self {
        [Self::Right, Self::Left, Self::Down, Self::Up][self as usize]
    }
    fn vim_key(self) -> char {
        ['h', 'l', 'k', 'j'][self as usize]
    }
}

// ---------------------------------------------------------------------------
// Universal program-agnostic `nav-v1` coalgebra & recursive router
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Nav(Dir),
    Enter(Dir),
    Close,
}

impl Op {
    pub(crate) fn format_wire(self) -> String {
        match self {
            Self::Nav(d) => format!("nav {}", d.name()),
            Self::Enter(d) => format!("enter {}", d.name()),
            Self::Close => "close".into(),
        }
    }

    fn parse_slice(args: &[&str]) -> Option<(Self, usize)> {
        match args {
            ["nav", d, ..] => Dir::parse(d).map(|d| (Self::Nav(d), 2)),
            ["enter", d, ..] => Dir::parse(d).map(|d| (Self::Enter(d), 2)),
            ["close", ..] => Some((Self::Close, 1)),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn parse_wire(line: &str) -> Option<Self> {
        let p: Vec<&str> = line.split_whitespace().collect();
        Self::parse_slice(&p)
            .filter(|&(_, n)| n == p.len())
            .map(|(o, _)| o)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Cap {
    NavSock(PathBuf),
    Kitty {
        pid: u32,
        class: String,
        tag: String,
    },
    Herdr(String),
    Remote {
        host: String,
        session: String,
    },
    Nvim {
        pid: u32,
        cwd: String,
        listen: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Done,
    Pass,
    Refuse(String),
    Delegate { token: String, child: Cap },
    Enter(Cap),
}

pub(crate) fn parse_nvim_listen(argv: &[&str]) -> String {
    let mut i = 1;
    while i < argv.len() && argv[i] != "--" {
        if argv[i] == "--listen" && i + 1 < argv.len() {
            return argv[i + 1].into();
        }
        if let Some(rest) = argv[i].strip_prefix("--listen=") {
            return rest.into();
        }
        i += 1;
    }
    String::new()
}

pub(crate) fn parse_cap_fields(f: &[&str]) -> R<Cap> {
    match f {
        ["nav", p] if !p.is_empty() => Ok(Cap::NavSock(PathBuf::from(p))),
        ["kitty", pid, c, t] => Ok(Cap::Kitty {
            pid: pid.parse().map_err(|_| format!("bad kitty pid: {pid}"))?,
            class: (*c).into(),
            tag: (*t).into(),
        }),
        ["herdr", s] if is_safe_ident(s) => Ok(Cap::Herdr((*s).into())),
        ["remote", h, s] if is_safe_ident(h) && is_safe_ident(s) => Ok(Cap::Remote {
            host: (*h).into(),
            session: (*s).into(),
        }),
        ["nvim", pid, cwd, argv @ ..] => Ok(Cap::Nvim {
            pid: pid.parse().map_err(|_| format!("bad nvim pid: {pid}"))?,
            cwd: (*cwd).into(),
            listen: parse_nvim_listen(argv),
        }),
        _ => Err(format!("malformed capability: {f:?}")),
    }
}

pub(crate) fn parse_outcome(raw: &str) -> Outcome {
    let line = raw.trim_end_matches(['\r', '\n']);
    let f: Vec<&str> = line.split('\t').collect();
    match f.as_slice() {
        ["done"] => Outcome::Done,
        ["pass"] => Outcome::Pass,
        ["refuse", r @ ..] => Outcome::Refuse(r.join(" ")),
        ["delegate", tok, cap @ ..] => parse_cap_fields(cap)
            .map(|child| Outcome::Delegate {
                token: (*tok).into(),
                child,
            })
            .unwrap_or_else(Outcome::Refuse),
        ["enter", cap @ ..] => parse_cap_fields(cap)
            .map(Outcome::Enter)
            .unwrap_or_else(Outcome::Refuse),
        _ => line
            .strip_prefix("refuse ")
            .map(|r| Outcome::Refuse(r.trim().into()))
            .unwrap_or_else(|| Outcome::Refuse(format!("malformed nav-v1 reply: {line:?}"))),
    }
}

pub(crate) fn format_outcome_line(out: &Outcome) -> String {
    match out {
        Outcome::Done => "done\n".into(),
        Outcome::Pass => "pass\n".into(),
        Outcome::Refuse(m) => format!("refuse\t{}\n", m.replace(['\t', '\r', '\n'], " ")),
        _ => "refuse\tunresolved intermediate outcome\n".into(),
    }
}

pub(crate) trait NavWorld {
    fn step(&mut self, cap: &Cap, op: Op) -> Outcome;
    fn commit(&mut self, cap: &Cap, op: Op, token: &str) -> Outcome;
    fn hypr_cas_focus(&mut self, addr: &str, epoch: u64, dir: Dir) -> Outcome;
    fn hypr_cas_close(&mut self, addr: &str, epoch: u64) -> Outcome;
}

/// Program-agnostic fixed-point router over any `NavWorld` coalgebra.
pub(crate) fn route_node<W: NavWorld>(world: &mut W, cap: &Cap, op: Op, depth: usize) -> Outcome {
    if depth >= MAX_DEPTH {
        return Outcome::Refuse("layers nest too deeply".into());
    }
    let descend_enter = |w: &mut W, next: Cap| match op {
        Op::Nav(d) => match route_node(w, &next, Op::Enter(d), depth + 1) {
            Outcome::Refuse(e) => Outcome::Refuse(e),
            _ => Outcome::Done,
        },
        Op::Enter(d) => route_node(w, &next, Op::Enter(d), depth + 1),
        Op::Close => Outcome::Refuse("unexpected enter during close".into()),
    };
    match world.step(cap, op) {
        Outcome::Delegate { token, child } => match route_node(world, &child, op, depth + 1) {
            Outcome::Pass => match world.commit(cap, op, &token) {
                Outcome::Enter(next) => descend_enter(world, next),
                other => other,
            },
            Outcome::Done => Outcome::Done,
            Outcome::Refuse(e) => Outcome::Refuse(e),
            _ => Outcome::Refuse("unresolved nested delegation".into()),
        },
        Outcome::Enter(next) => descend_enter(world, next),
        other => other,
    }
}

/// Entry from Layer 0 (`share/hypr-nav.lua`) with strict Epoch-CAS fallback.
pub(crate) fn route_from_hypr<W: NavWorld>(
    world: &mut W,
    addr: &str,
    epoch: u64,
    cap: &Cap,
    op: Op,
) -> R<()> {
    let settle = |o: Outcome| match o {
        Outcome::Refuse(m) if m != "stale" => Err(m),
        _ => Ok(()),
    };
    match route_node(world, cap, op, 0) {
        Outcome::Pass => match op {
            Op::Enter(_) => Ok(()),
            Op::Nav(d) => match world.hypr_cas_focus(addr, epoch, d) {
                Outcome::Enter(next) => settle(route_node(world, &next, Op::Enter(d), 0)),
                other => settle(other),
            },
            Op::Close => settle(world.hypr_cas_close(addr, epoch)),
        },
        other => settle(other),
    }
}

// ---------------------------------------------------------------------------
// Bounded Unix-socket I/O, validation & universal `nav-v1` client
// ---------------------------------------------------------------------------

pub(crate) fn is_safe_ident(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub(crate) fn is_hex_addr(s: &str) -> bool {
    s.strip_prefix("0x")
        .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn env_path(key: &str) -> Option<PathBuf> {
    env::var_os(key)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn runtime_dir() -> R<PathBuf> {
    env_path("XDG_RUNTIME_DIR").ok_or_else(|| "XDG_RUNTIME_DIR is unset".into())
}

fn config_dir() -> R<PathBuf> {
    env_path("XDG_CONFIG_HOME")
        .or_else(|| env_path("HOME").map(|h| h.join(".config")))
        .ok_or_else(|| "XDG_CONFIG_HOME and HOME are unset".into())
}

fn is_absent(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    )
}

fn read_until(
    stream: &mut UnixStream,
    deadline: Deadline,
    done: impl Fn(&[u8]) -> bool,
) -> io::Result<Vec<u8>> {
    let (mut buf, mut chunk) = (Vec::new(), [0u8; 8192]);
    while !done(&buf) {
        stream.set_read_timeout(Some(deadline.remaining()?))?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}

fn exchange_io(
    path: &Path,
    req: &[u8],
    deadline: Deadline,
    done: impl Fn(&[u8]) -> bool,
) -> io::Result<Vec<u8>> {
    let mut s = UnixStream::connect(path)?;
    s.set_write_timeout(Some(deadline.remaining()?))?;
    s.write_all(req)?;
    read_until(&mut s, deadline, done)
}

fn nav_v1_socket(path: &Path, op: Op, dl: Deadline) -> io::Result<Outcome> {
    let raw = exchange_io(
        path,
        format!("{}\n", op.format_wire()).as_bytes(),
        dl,
        |b| b.contains(&b'\n'),
    )?;
    if raw.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty nav-v1 reply",
        ));
    }
    Ok(parse_outcome(&String::from_utf8_lossy(&raw)))
}

// ---------------------------------------------------------------------------
// Dialect Shims: Hyprland (0), Kitty (1), Herdr (2), Neovim (3), Remote SSH
// ---------------------------------------------------------------------------

fn hypr_raw(req: &str, dl: Deadline) -> R<String> {
    let sig = env::var("HYPRLAND_INSTANCE_SIGNATURE")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("HYPRLAND_INSTANCE_SIGNATURE is unset")?;
    let sock = runtime_dir()?.join("hypr").join(sig).join(".socket.sock");
    let raw = exchange_io(&sock, req.as_bytes(), dl, |_| false)
        .map_err(|e| format!("{}: {e}", sock.display()))?;
    Ok(String::from_utf8_lossy(&raw).trim().to_string())
}

fn kitty_kitten_path() -> PathBuf {
    if let Some(p) = env_path("HYPR_NAV_KITTEN") {
        return p;
    }
    if let Ok(exe) = env::current_exe()
        && let Some(root) = exe.parent().and_then(Path::parent)
    {
        let p = root.join("share/hypr-nav/kitty_nav.py");
        if p.is_file() {
            return p;
        }
    }
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/share/kitty_nav.py"))
}

fn kitty_call(pid: u32, args: &[&str], dl: Deadline) -> R<Outcome> {
    let sock = runtime_dir()?.join(format!("kitty-{pid}"));
    let body = json!({
        "cmd": "kitten",
        "version": [0, 49, 0],
        "payload": { "kitten": kitty_kitten_path().to_string_lossy(), "args": args }
    });
    let req = [KITTY_PFX, body.to_string().as_bytes(), KITTY_SFX].concat();
    let raw = match exchange_io(&sock, &req, dl, |b| b.ends_with(KITTY_SFX)) {
        Ok(r) => r,
        Err(e) if is_absent(&e) => return Ok(Outcome::Pass),
        Err(e) => return Err(format!("kitty: {e}")),
    };
    let parsed: Json = raw
        .strip_prefix(KITTY_PFX)
        .and_then(|b| b.strip_suffix(KITTY_SFX))
        .and_then(|b| serde_json::from_slice(b).ok())
        .ok_or("kitty: malformed reply")?;
    if parsed["ok"].as_bool() != Some(true) {
        return Err(format!("kitty: {}", parsed["error"]));
    }
    parsed["data"]
        .as_str()
        .map(parse_outcome)
        .ok_or_else(|| "kitty: missing kitten result".into())
}

fn herdr_socket(session: &str) -> R<PathBuf> {
    if !is_safe_ident(session) {
        return Err(format!("invalid herdr session: {session:?}"));
    }
    if session == "default"
        && let Some(p) = env_path("HERDR_SOCKET_PATH")
    {
        return Ok(p);
    }
    let base = config_dir()?.join("herdr");
    Ok(if session == "default" {
        base.join("herdr.sock")
    } else {
        base.join("sessions").join(session).join("herdr.sock")
    })
}

fn herdr_call(sock: &Path, method: &str, params: Json, dl: Deadline) -> R<Json> {
    let req = format!(
        "{}\n",
        json!({"id": "hypr-nav", "method": method, "params": params})
    );
    let raw = exchange_io(sock, req.as_bytes(), dl, |b| b.ends_with(b"\n"))
        .map_err(|e| format!("herdr {method}: {e}"))?;
    let mut v: Json = serde_json::from_slice(&raw).map_err(|e| format!("herdr {method}: {e}"))?;
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        return Err(format!("herdr {method}: {err}"));
    }
    Ok(v["result"].take())
}

pub(crate) fn herdr_inner_from_info(info: &Json, rt: Option<&Path>) -> Option<Cap> {
    let fg = info["process_info"]["foreground_processes"].as_array()?;
    if let Some(dir) = rt {
        for p in fg {
            if let Some(pid) = p["pid"].as_u64().and_then(|v| u32::try_from(v).ok()) {
                let s = dir.join(format!("nav-{pid}.sock"));
                if s.exists() {
                    return Some(Cap::NavSock(s));
                }
            }
        }
    }
    for p in fg {
        let argv: Vec<&str> = p["argv"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Json::as_str)
            .collect();
        if p["name"].as_str() == Some("nvim")
            || argv.first().and_then(|a| a.rsplit('/').next()) == Some("nvim")
        {
            return Some(Cap::Nvim {
                pid: u32::try_from(p["pid"].as_u64()?).ok()?,
                cwd: p["cwd"].as_str().unwrap_or("").into(),
                listen: parse_nvim_listen(&argv),
            });
        }
    }
    None
}

pub(crate) fn herdr_entry_from_edges(edges: &Json, dir: Dir) -> R<Option<String>> {
    let opp = dir.opposite();
    if edges[opp.name()].as_bool() == Some(true)
        || edges["layout"]["zoomed"].as_bool() == Some(true)
    {
        return Ok(None);
    }
    let rect = |r: &Json| {
        Some((
            r["x"].as_u64()?,
            r["y"].as_u64()?,
            r["width"].as_u64()?,
            r["height"].as_u64()?,
        ))
    };
    let (ax, ay, aw, ah) = rect(&edges["layout"]["area"]).ok_or("herdr edges: bad area")?;
    for pane in edges["layout"]["panes"]
        .as_array()
        .ok_or("herdr edges: no panes")?
    {
        let id = pane["pane_id"].as_str().ok_or("herdr edges: no pane_id")?;
        let (x, y, w, h) = rect(&pane["rect"]).ok_or("herdr edges: bad rect")?;
        let on_edge = match opp {
            Dir::Left => x == ax,
            Dir::Right => x.checked_add(w) == ax.checked_add(aw),
            Dir::Up => y == ay,
            Dir::Down => y.checked_add(h) == ay.checked_add(ah),
        };
        if on_edge {
            return Ok((pane["focused"].as_bool() != Some(true)).then(|| id.to_string()));
        }
    }
    Ok(None)
}

pub(crate) fn herdr_close_target(snap: &Json) -> Option<Option<String>> {
    let focused_id = snap["focused_pane_id"].as_str()?;
    let panes = snap["panes"].as_array()?;
    let (mut ids, mut matches) = (HashSet::new(), 0usize);
    for p in panes {
        let id = p["pane_id"].as_str()?;
        if !ids.insert(id) {
            return None;
        }
        if p["focused"].as_bool() == Some(true) {
            if id != focused_id {
                return None;
            }
            matches += 1;
        }
    }
    (matches == 1 && ids.contains(focused_id))
        .then(|| (panes.len() > 1).then(|| focused_id.to_string()))
}

fn herdr_op(session: &str, op: Op, commit: bool, dl: Deadline) -> R<Outcome> {
    let sock = herdr_socket(session)?;
    let rt = runtime_dir().ok();
    match (op, commit) {
        (Op::Nav(dir), false) => {
            let info = herdr_call(&sock, "pane.process_info", json!({}), dl)?;
            if let Some(child) = herdr_inner_from_info(&info, rt.as_deref()) {
                return Ok(Outcome::Delegate {
                    token: String::new(),
                    child,
                });
            }
            herdr_op(session, Op::Nav(dir), true, dl)
        }
        (Op::Nav(dir), true) => {
            let r = herdr_call(
                &sock,
                "pane.focus_direction",
                json!({"direction": dir.name()}),
                dl,
            )?;
            match (&r["focus"]["changed"], &r["focus"]["reason"]) {
                (Json::Bool(true), _) => Ok(Outcome::Done),
                (Json::Bool(false), s) if s == "no_neighbor" => Ok(Outcome::Pass),
                _ => Err(format!("herdr focus_direction: {r}")),
            }
        }
        (Op::Enter(dir), false) => {
            let res = herdr_call(&sock, "pane.edges", json!({}), dl)?;
            if let Some(id) = herdr_entry_from_edges(&res["edges"], dir)? {
                herdr_call(&sock, "pane.focus", json!({"pane_id": id}), dl)?;
                return Ok(Outcome::Done);
            }
            let info = herdr_call(&sock, "pane.process_info", json!({}), dl)?;
            Ok(herdr_inner_from_info(&info, rt.as_deref()).map_or(Outcome::Pass, Outcome::Enter))
        }
        (Op::Enter(_), true) => Ok(Outcome::Pass),
        (Op::Close, false) => {
            let info = herdr_call(&sock, "pane.process_info", json!({}), dl)?;
            if let Some(child @ Cap::NavSock(_)) = herdr_inner_from_info(&info, rt.as_deref()) {
                return Ok(Outcome::Delegate {
                    token: String::new(),
                    child,
                });
            }
            herdr_op(session, Op::Close, true, dl)
        }
        (Op::Close, true) => {
            let snap = herdr_call(&sock, "session.snapshot", json!({}), dl)?;
            match herdr_close_target(&snap["snapshot"]) {
                Some(Some(id)) => {
                    herdr_call(&sock, "pane.close", json!({"pane_id": id}), dl)?;
                    Ok(Outcome::Done)
                }
                Some(None) => Ok(Outcome::Pass),
                None => Err("herdr snapshot is inconsistent".into()),
            }
        }
    }
}

fn nvim_socket(pid: u32, cwd: &str, listen: &str) -> R<Option<PathBuf>> {
    if !listen.is_empty() {
        let p = PathBuf::from(listen);
        return Ok(Some(if p.is_absolute() || cwd.is_empty() {
            p
        } else {
            Path::new(cwd).join(p)
        }));
    }
    let rt = runtime_dir()?;
    let direct = rt.join(format!("nvim.{pid}.0"));
    if direct.exists() {
        return Ok(Some(direct));
    }
    if let Ok(kids) = fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")) {
        for kid in kids.split_whitespace() {
            let c = rt.join(format!("nvim.{kid}.0"));
            if c.exists() {
                return Ok(Some(c));
            }
        }
    }
    Ok(None)
}

pub(crate) fn decode_nvim_response(buf: &[u8], msgid: u64) -> R<Option<Msg>> {
    let mut cur = Cursor::new(buf);
    while (cur.position() as usize) < buf.len() {
        let val = match rmpv::decode::read_value(&mut cur) {
            Ok(v) => v,
            Err(rmpv::decode::Error::InvalidMarkerRead(e))
            | Err(rmpv::decode::Error::InvalidDataRead(e))
                if e.kind() == io::ErrorKind::UnexpectedEof =>
            {
                return Ok(None);
            }
            Err(e) => return Err(format!("nvim msgpack decode: {e}")),
        };
        let arr = val.as_array().ok_or("nvim msgpack: non-array frame")?;
        match arr.first().and_then(Msg::as_u64) {
            Some(2) => continue,
            Some(1) if arr.len() == 4 && arr[1].as_u64() == Some(msgid) => {
                return if arr[2].is_nil() {
                    Ok(Some(arr[3].clone()))
                } else {
                    Err(format!("nvim rpc error: {}", arr[2]))
                };
            }
            _ => return Err(format!("nvim unexpected frame: {val}")),
        }
    }
    Ok(None)
}

fn nvim_eval(sock: &Path, expr: &str, dl: Deadline) -> R<bool> {
    let mut req = Vec::new();
    let msg = Msg::Array(vec![
        Msg::from(0u64),
        Msg::from(0u64),
        Msg::from("nvim_eval"),
        Msg::Array(vec![Msg::from(expr)]),
    ]);
    rmpv::encode::write_value(&mut req, &msg).map_err(|e| format!("nvim encode: {e}"))?;
    let raw = exchange_io(sock, &req, dl, |b| {
        matches!(decode_nvim_response(b, 0), Ok(Some(_)) | Err(_))
    })
    .map_err(|e| format!("nvim: {e}"))?;
    match decode_nvim_response(&raw, 0)?
        .ok_or("nvim: truncated reply")?
        .as_i64()
    {
        Some(1) => Ok(true),
        Some(0) => Ok(false),
        other => Err(format!("nvim: unexpected eval result {other:?}")),
    }
}

fn nvim_step(pid: u32, cwd: &str, listen: &str, op: Op, dl: Deadline) -> R<Outcome> {
    if matches!(op, Op::Close) {
        return Ok(Outcome::Pass);
    }
    let Some(sock) = nvim_socket(pid, cwd, listen)? else {
        return Ok(Outcome::Pass);
    };
    let expr = match op {
        Op::Nav(d) => format!(
            "winnr() == winnr('{k}') ? 0 : (empty(execute('wincmd {k}')) >= 0)",
            k = d.vim_key()
        ),
        Op::Enter(d) => format!(
            "winnr() == winnr('999{k}') ? 0 : (empty(execute('999wincmd {k}')) >= 0)",
            k = d.opposite().vim_key()
        ),
        Op::Close => unreachable!(),
    };
    Ok(if nvim_eval(&sock, &expr, dl)? {
        Outcome::Done
    } else {
        Outcome::Pass
    })
}

/// Stateless 1-RTT remote `mw` hop riding OpenSSH's existing `ControlMaster`
/// (`~/.ssh/cm-%C`). Bounded by kernel `SO_RCVTIMEO`; inherently fail-closed.
fn remote_call(host: &str, session: &str, op: Op, dl: Deadline) -> R<Outcome> {
    if !is_safe_ident(host) || !is_safe_ident(session) {
        return Err(format!("unsafe remote target: {host:?} {session:?}"));
    }
    let wire = op.format_wire();
    let op_parts: Vec<&str> = wire.split_whitespace().collect();
    let (mut rx, tx) = UnixStream::pair().map_err(|e| format!("remote pair: {e}"))?;
    let mut cmd = match env_path("HYPR_NAV_SSH") {
        Some(custom) => {
            let mut c = Command::new(custom);
            c.args([host, session]).args(&op_parts);
            c
        }
        None => {
            let mut c = Command::new("ssh");
            c.args([
                "-o",
                "BatchMode=yes",
                "-T",
                host,
                "hypr-nav",
                "--herdr",
                session,
            ])
            .args(&op_parts);
            c
        }
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(tx)))
        .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("remote ssh: {e}"))?;
    drop(cmd);
    let res = read_until(&mut rx, dl, |_| false);
    drop(rx);
    let raw = match res {
        Ok(b) => b,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("remote ssh: {e}"));
        }
    };
    let status = child.wait().map_err(|e| format!("remote ssh wait: {e}"))?;
    if !status.success() || raw.is_empty() {
        return Err(format!("remote ssh failed ({status})"));
    }
    Ok(parse_outcome(&String::from_utf8_lossy(&raw)))
}

// ---------------------------------------------------------------------------
// LiveWorld wiring & CLI entrypoints
// ---------------------------------------------------------------------------

struct LiveWorld(Deadline);

impl NavWorld for LiveWorld {
    fn step(&mut self, cap: &Cap, op: Op) -> Outcome {
        let dl = self.0;
        match cap {
            Cap::NavSock(p) => match nav_v1_socket(p, op, dl) {
                Ok(o) => Ok(o),
                Err(e) if is_absent(&e) => Ok(Outcome::Pass),
                Err(e) => Err(format!("nav socket: {e}")),
            },
            Cap::Kitty { pid, class, tag } => match op {
                Op::Nav(d) => kitty_call(*pid, &["nav", d.name(), class, tag], dl),
                Op::Enter(d) => kitty_call(*pid, &["enter", d.name(), class, tag], dl),
                Op::Close => kitty_call(*pid, &["close", class, tag], dl),
            },
            Cap::Herdr(s) => herdr_op(s, op, false, dl),
            Cap::Remote { host, session } => remote_call(host, session, op, dl),
            Cap::Nvim { pid, cwd, listen } => nvim_step(*pid, cwd, listen, op, dl),
        }
        .unwrap_or_else(Outcome::Refuse)
    }

    fn commit(&mut self, cap: &Cap, op: Op, token: &str) -> Outcome {
        let dl = self.0;
        match cap {
            Cap::Kitty { pid, class, tag } => match op {
                Op::Nav(d) => kitty_call(*pid, &["step_nav", d.name(), token, class, tag], dl),
                Op::Close => kitty_call(*pid, &["step_close", token, class, tag], dl),
                Op::Enter(_) => Ok(Outcome::Pass),
            },
            Cap::Herdr(s) => herdr_op(s, op, true, dl),
            _ => Ok(Outcome::Pass),
        }
        .unwrap_or_else(Outcome::Refuse)
    }

    fn hypr_cas_focus(&mut self, addr: &str, epoch: u64, dir: Dir) -> Outcome {
        if !is_hex_addr(addr) {
            return Outcome::Refuse(format!("invalid window address: {addr:?}"));
        }
        hypr_raw(
            &format!(
                "repl return hn_cas_focus(\"{addr}\", {epoch}, \"{}\")",
                dir.name()
            ),
            self.0,
        )
        .map(|r| parse_outcome(&r))
        .unwrap_or_else(Outcome::Refuse)
    }

    fn hypr_cas_close(&mut self, addr: &str, epoch: u64) -> Outcome {
        if !is_hex_addr(addr) {
            return Outcome::Refuse(format!("invalid window address: {addr:?}"));
        }
        hypr_raw(
            &format!("repl return hn_cas_close(\"{addr}\", {epoch})"),
            self.0,
        )
        .map(|r| parse_outcome(&r))
        .unwrap_or_else(Outcome::Refuse)
    }
}

fn dispatch_args(args: &[String]) -> R<()> {
    let dl = Deadline::after(BUDGET);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match refs.as_slice() {
        ["--herdr", session, op_args @ ..] => {
            if !is_safe_ident(session) {
                return Err(format!("invalid session: {session:?}"));
            }
            let (op, _) = Op::parse_slice(op_args)
                .filter(|&(_, n)| n == op_args.len())
                .ok_or("bad --herdr op")?;
            let out = route_node(&mut LiveWorld(dl), &Cap::Herdr((*session).into()), op, 0);
            io::stdout()
                .write_all(format_outcome_line(&out).as_bytes())
                .map_err(|e| format!("stdout: {e}"))
        }
        ["--from-hypr", rest @ ..] => {
            let (op, n) = Op::parse_slice(rest).ok_or("bad --from-hypr op")?;
            let [addr, epoch_s, cap @ ..] = &rest[n..] else {
                return Err("missing --from-hypr target".into());
            };
            let epoch: u64 = epoch_s.parse().map_err(|_| "bad epoch")?;
            route_from_hypr(&mut LiveWorld(dl), addr, epoch, &parse_cap_fields(cap)?, op)
        }
        [a] if *a == "close" || Dir::parse(a).is_some() => {
            let reply = hypr_raw(&format!("repl return hn_cli(\"{a}\")"), dl)?;
            if reply == "done" {
                Ok(())
            } else {
                Err(format!("hypr-nav.lua not loaded or refused: {reply}"))
            }
        }
        _ => Err("usage: hypr-nav <left|right|up|down|close>".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match dispatch_args(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let line = format!("hypr-nav {}: {err}", args.join(" ")).replace(['\r', '\n'], " ");
            eprintln!("{line}");
            if let Ok(sock) = UnixDatagram::unbound() {
                let msg = format!("SYSLOG_IDENTIFIER=hypr-nav\nPRIORITY=3\nMESSAGE={line}\n");
                let _ = sock.send_to(msg.as_bytes(), "/run/systemd/journal/socket");
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod bisim;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    static TMP_SEQ: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!(
            "hypr-nav-ut-{tag}-{}-{}",
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn nav_v1_wire_roundtrip_and_sanitization() {
        for op in [
            Op::Nav(Dir::Left),
            Op::Nav(Dir::Right),
            Op::Enter(Dir::Up),
            Op::Enter(Dir::Down),
            Op::Close,
        ] {
            assert_eq!(Op::parse_wire(&op.format_wire()), Some(op));
        }
        assert_eq!(Dir::parse("h"), None);
        assert_eq!(parse_outcome("done\n"), Outcome::Done);
        assert_eq!(parse_outcome("pass\n"), Outcome::Pass);
        assert_eq!(
            parse_outcome("refuse\tstale\n"),
            Outcome::Refuse("stale".into())
        );
        assert_eq!(
            parse_outcome("refuse custom reason\n"),
            Outcome::Refuse("custom reason".into())
        );
        assert_eq!(
            parse_outcome("delegate\t7\tremote\tminworker\tdevelopment\n"),
            Outcome::Delegate {
                token: "7".into(),
                child: Cap::Remote {
                    host: "minworker".into(),
                    session: "development".into(),
                },
            }
        );
        assert_eq!(
            parse_nvim_listen(&[
                "nvim",
                "--listen",
                "/tmp/a.sock",
                "--",
                "--listen",
                "/tmp/b"
            ]),
            "/tmp/a.sock"
        );
        assert!(!is_safe_ident("-oProxyCommand=bad"));
        assert!(!is_safe_ident("../etc"));
        assert!(is_safe_ident("minworker"));
        assert!(is_hex_addr("0x5bf419889c30"));
        assert!(!is_hex_addr("address:0x1"));
    }

    #[test]
    fn nvim_decoder_skips_rpcnotify_and_checks_type() {
        let mut stream = Vec::new();
        rmpv::encode::write_value(
            &mut stream,
            &Msg::Array(vec![
                Msg::from(2u64),
                Msg::from("redraw"),
                Msg::Array(vec![]),
            ]),
        )
        .unwrap();
        rmpv::encode::write_value(
            &mut stream,
            &Msg::Array(vec![
                Msg::from(1u64),
                Msg::from(0u64),
                Msg::Nil,
                Msg::from(1u64),
            ]),
        )
        .unwrap();
        assert_eq!(
            decode_nvim_response(&stream, 0).unwrap(),
            Some(Msg::from(1u64))
        );
    }

    #[test]
    fn herdr_parsers_handle_edges_and_last_pane_invariants() {
        let edges = json!({
            "left": false, "right": true, "up": true, "down": true,
            "layout": {
                "zoomed": false,
                "area": {"x": 0, "y": 0, "width": 120, "height": 40},
                "panes": [
                    {"pane_id": "w1:p1", "focused": false, "rect": {"x": 0, "y": 0, "width": 60, "height": 40}},
                    {"pane_id": "w1:p2", "focused": true, "rect": {"x": 60, "y": 0, "width": 60, "height": 40}}
                ]
            }
        });
        assert_eq!(
            herdr_entry_from_edges(&edges, Dir::Right).unwrap(),
            Some("w1:p1".into())
        );
        assert_eq!(herdr_entry_from_edges(&edges, Dir::Left).unwrap(), None);

        let snap_one = json!({
            "focused_pane_id": "w1:p1",
            "panes": [{"pane_id": "w1:p1", "focused": true}]
        });
        assert_eq!(herdr_close_target(&snap_one), Some(None));

        let snap_two = json!({
            "focused_pane_id": "w1:p2",
            "panes": [
                {"pane_id": "w1:p1", "focused": false},
                {"pane_id": "w1:p2", "focused": true}
            ]
        });
        assert_eq!(herdr_close_target(&snap_two), Some(Some("w1:p2".into())));
    }

    #[test]
    fn live_headless_nvim_handles_splits_rpcnotify_and_floats() {
        let dir = temp_dir("nvim");
        let sock = dir.join("nv.sock");
        let mut child = Command::new("nvim")
            .args([
                "--headless",
                "-u",
                "NONE",
                "--listen",
                sock.to_str().unwrap(),
                "-c",
                "vsplit",
                "-c",
                "autocmd WinEnter * call rpcnotify(0, 'hn_test', 'moved')",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("nvim spawns");
        let wait_dl = Deadline::after(Duration::from_secs(5));
        while !sock.exists() {
            assert!(wait_dl.remaining().is_ok(), "nvim socket never appeared");
            thread::sleep(Duration::from_millis(20));
        }
        let dl = Deadline::after(Duration::from_secs(5));
        let listen = sock.to_str().unwrap();
        assert_eq!(
            nvim_step(0, "", listen, Op::Nav(Dir::Right), dl).unwrap(),
            Outcome::Done
        );
        assert_eq!(
            nvim_step(0, "", listen, Op::Nav(Dir::Right), dl).unwrap(),
            Outcome::Pass
        );
        assert_eq!(
            nvim_step(0, "", listen, Op::Enter(Dir::Right), dl).unwrap(),
            Outcome::Done
        );
        assert_eq!(
            nvim_step(0, "", listen, Op::Enter(Dir::Right), dl).unwrap(),
            Outcome::Pass
        );
        assert_eq!(
            nvim_step(0, "", listen, Op::Close, dl).unwrap(),
            Outcome::Pass
        );

        let _ = nvim_eval(
            &sock,
            "empty(execute('only')) >= 0 && nvim_open_win(nvim_create_buf(0,1), 0, {'relative':'editor','width':5,'height':2,'row':0,'col':0}) > 0",
            dl,
        );
        assert_eq!(
            nvim_step(0, "", listen, Op::Nav(Dir::Left), dl).unwrap(),
            Outcome::Pass
        );
        assert_eq!(
            nvim_step(0, "", listen, Op::Nav(Dir::Right), dl).unwrap(),
            Outcome::Pass
        );

        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn universal_nav_v1_socket_app_routes_without_shims() {
        let dir = temp_dir("navv1");
        let sock = dir.join("nav-99999.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let srv = thread::spawn(move || {
            for expected in [
                ("nav left", "done\n"),
                ("nav left", "pass\n"),
                ("enter right", "done\n"),
                ("close", "refuse\tbusy\n"),
            ] {
                let (mut conn, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(&conn).read_line(&mut line).unwrap();
                assert_eq!(line.trim(), expected.0);
                conn.write_all(expected.1.as_bytes()).unwrap();
            }
        });
        let dl = Deadline::after(Duration::from_secs(5));
        assert_eq!(
            nav_v1_socket(&sock, Op::Nav(Dir::Left), dl).unwrap(),
            Outcome::Done
        );
        assert_eq!(
            nav_v1_socket(&sock, Op::Nav(Dir::Left), dl).unwrap(),
            Outcome::Pass
        );
        assert_eq!(
            nav_v1_socket(&sock, Op::Enter(Dir::Right), dl).unwrap(),
            Outcome::Done
        );
        assert_eq!(
            nav_v1_socket(&sock, Op::Close, dl).unwrap(),
            Outcome::Refuse("busy".into())
        );
        srv.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
