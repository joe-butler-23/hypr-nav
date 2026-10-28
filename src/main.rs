//! One keybinding surface for nested Hyprland, Kitty, tmux, Herdr and Neovim.
//!
//! A window is resolved into a chain of layers by following foreground
//! processes inward: Kitty names its focused pane, each pane's terminal names
//! its foreground process group, and that process's name selects the next
//! layer. Cost follows the nesting actually present, never the number of
//! supported layers. Actions run innermost first; a layer passes outward only
//! when it has nothing to do.

mod herdr;
mod hypr;
mod kitty;
mod nvim;
mod proc;
mod tmux;

use hypr::{Hypr, Window};
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

type R<T> = Result<T, String>;

/// Budget for a whole keypress; every socket and subprocess shares it.
#[cfg(not(test))]
const BUDGET: Duration = Duration::from_millis(1500);
#[cfg(test)]
const BUDGET: Duration = Duration::from_secs(60);
const MAX_DEPTH: usize = 8;
static START: OnceLock<Instant> = OnceLock::new();

macro_rules! debug {
    ($($arg:tt)*) => {
        if std::env::var_os("HYPR_NAV_DEBUG").is_some() {
            eprintln!("hypr-nav: {}", format!($($arg)*));
        }
    };
}

fn remaining() -> io::Result<Duration> {
    let deadline = *START.get_or_init(Instant::now) + BUDGET;
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "keypress budget exhausted"))
}

/// Send `request` and read until `done` accepts the reply or the peer closes.
fn exchange(path: &Path, request: &[u8], done: impl Fn(&[u8]) -> bool) -> R<Vec<u8>> {
    let run = || -> io::Result<Vec<u8>> {
        let mut stream = UnixStream::connect(path)?;
        stream.set_write_timeout(Some(remaining()?))?;
        stream.write_all(request)?;
        let mut reply = Vec::new();
        let mut chunk = [0; 16384];
        while !done(&reply) {
            stream.set_read_timeout(Some(remaining()?))?;
            match stream.read(&mut chunk)? {
                0 => break,
                n => reply.extend_from_slice(&chunk[..n]),
            }
        }
        Ok(reply)
    };
    run().map_err(|err| format!("{}: {err}", path.display()))
}

fn runtime_dir() -> R<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| "XDG_RUNTIME_DIR is unset".into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dir {
    Left,
    Right,
    Up,
    Down,
}

impl Dir {
    fn parse(arg: &str) -> Option<Self> {
        match arg {
            "left" | "h" => Some(Self::Left),
            "right" | "l" => Some(Self::Right),
            "up" | "k" => Some(Self::Up),
            "down" | "j" => Some(Self::Down),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        ["left", "right", "up", "down"][self as usize]
    }

    fn opposite(self) -> Self {
        [Self::Right, Self::Left, Self::Down, Self::Up][self as usize]
    }
}

/// A layer either handled an action or leaves it to the next outer layer.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Done,
    Pass,
}

enum Layer {
    Kitty(kitty::Kitty),
    Tmux(tmux::Tmux),
    Herdr(herdr::Herdr),
    Nvim(nvim::Nvim),
}

impl Layer {
    /// Recognise the layer a pane's foreground process provides, if any.
    fn attach(pid: u32) -> R<Option<Self>> {
        let argv = proc::argv(pid);
        Ok(match argv.first().map(|arg0| proc::basename(arg0)) {
            Some("nvim") => nvim::Nvim::attach(pid, &argv)?.map(Self::Nvim),
            Some("tmux") => Some(Self::Tmux(tmux::Tmux::attach(pid, &argv)?)),
            Some("herdr") => herdr::Herdr::attach(pid, &argv)?.map(Self::Herdr),
            _ => None,
        })
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Kitty(_) => "kitty",
            Self::Tmux(_) => "tmux",
            Self::Herdr(_) => "herdr",
            Self::Nvim(_) => "nvim",
        }
    }

    /// Foreground process of this layer's focused pane.
    fn inner(&self) -> R<Option<u32>> {
        match self {
            Self::Kitty(layer) => layer.inner(),
            Self::Tmux(layer) => Ok(layer.inner()),
            Self::Herdr(layer) => layer.inner(),
            Self::Nvim(_) => Ok(None),
        }
    }

    fn navigate(&self, dir: Dir) -> R<Step> {
        match self {
            Self::Kitty(layer) => layer.navigate(dir),
            Self::Tmux(layer) => layer.navigate(dir),
            Self::Herdr(layer) => layer.navigate(dir),
            Self::Nvim(layer) => layer.navigate(dir),
        }
    }

    /// Focus the pane on the edge just entered from `dir`.
    fn enter(&self, dir: Dir) -> R<Step> {
        match self {
            Self::Kitty(layer) => layer.enter(dir),
            Self::Tmux(layer) => layer.enter(dir),
            Self::Herdr(layer) => layer.enter(dir),
            Self::Nvim(layer) => layer.enter(dir),
        }
    }

    fn close(&self) -> R<Step> {
        match self {
            Self::Kitty(layer) => layer.close(),
            Self::Tmux(layer) => layer.close(),
            Self::Herdr(layer) => layer.close(),
            Self::Nvim(_) => Ok(Step::Pass),
        }
    }
}

/// Layers inside `window`, innermost first, and whether resolution reached a
/// process that provides no further layer. Navigation uses what resolved;
/// close refuses an incomplete chain.
fn layers(window: &Window) -> (Vec<Layer>, R<()>) {
    let mut layers = Vec::new();
    let status = (|| {
        let pid = match kitty::Kitty::attach(window)? {
            Some(kitty) => push(&mut layers, Layer::Kitty(kitty))?,
            None => proc::window_foreground(window.pid)?,
        };
        descend(&mut layers, pid)
    })();
    layers.reverse();
    debug!(
        "{} layers {:?} {:?}",
        window.class,
        layers.iter().map(Layer::name).collect::<Vec<_>>(),
        status
    );
    (layers, status)
}

/// Keep `layer` even if its focused pane cannot be read, so navigation can
/// still use it; return that pane's foreground process.
fn push(layers: &mut Vec<Layer>, layer: Layer) -> R<Option<u32>> {
    let inner = layer.inner();
    layers.push(layer);
    inner
}

/// Follow foreground processes inward from `pid`, outermost layer first.
fn descend(layers: &mut Vec<Layer>, mut pid: Option<u32>) -> R<()> {
    while let Some(foreground) = pid {
        if layers.len() >= MAX_DEPTH {
            return Err("layers nest too deeply".into());
        }
        let Some(layer) = Layer::attach(foreground)? else {
            return Ok(());
        };
        pid = push(layers, layer)?;
    }
    Ok(())
}

fn navigate(dir: Dir) -> R<()> {
    let hypr = Hypr::connect()?;
    let source = hypr.active()?;
    if let Some(window) = &source {
        for layer in layers(window).0 {
            if layer.navigate(dir)? == Step::Done {
                debug!("{} moved {}", layer.name(), dir.name());
                return Ok(());
            }
        }
        // Every layer action names what its own read saw, or lets the layer
        // decide and act in one request. Hyprland's move is relative, so its
        // origin must still be the source window.
        hypr.still(window)?;
    }
    hypr.dispatch(&format!(
        "hl.dsp.focus({{direction = \"{}\"}})",
        &dir.name()[..1]
    ))?;
    let Some(target) = hypr.active()? else {
        return Ok(());
    };
    if source.is_none_or(|source| source.address == target.address) {
        return Ok(());
    }
    // Entry stops at the first layer that moves: inner layers then belong to
    // a different pane than the one resolved.
    for layer in layers(&target).0.iter().rev() {
        if layer.enter(dir)? == Step::Done {
            debug!("{} entered from {}", layer.name(), dir.name());
            break;
        }
    }
    Ok(())
}

fn close() -> R<()> {
    let hypr = Hypr::connect()?;
    let window = hypr.active()?.ok_or("no active window")?;
    let (layers, status) = layers(&window);
    status.map_err(|err| format!("cannot identify {} contents: {err}", window.class))?;
    for layer in layers {
        if layer.close()? == Step::Done {
            debug!("{} closed its pane", layer.name());
            return Ok(());
        }
    }
    hypr.dispatch(&format!(
        "hl.dsp.window.close({{address = \"{}\"}})",
        window.address
    ))
}

/// Failures reach stderr and the journal (`journalctl --user -t hypr-nav`),
/// since keybinding processes have no visible stderr.
fn report(action: &str, err: &str) {
    let message = format!("hypr-nav {action}: {err}");
    eprintln!("{message}");
    if let Ok(socket) = UnixDatagram::unbound() {
        let entry = format!(
            "SYSLOG_IDENTIFIER=hypr-nav\nPRIORITY=3\nMESSAGE={}\n",
            message.replace('\n', " ")
        );
        let _ = socket.send_to(entry.as_bytes(), "/run/systemd/journal/socket");
    }
}

fn main() {
    START.get_or_init(Instant::now);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [action] if action == "close" => close(),
        [action] => match Dir::parse(action) {
            Some(dir) => navigate(dir),
            None => Err("usage: hypr-nav <left|right|up|down|close>".into()),
        },
        _ => Err("usage: hypr-nav <left|right|up|down|close>".into()),
    };
    if let Err(err) = result {
        report(args.first().map_or("", String::as_str), &err);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directions_map_consistently() {
        for (arg, dir) in [("h", Dir::Left), ("right", Dir::Right), ("k", Dir::Up)] {
            assert_eq!(Dir::parse(arg), Some(dir));
            assert_eq!(dir.opposite().opposite(), dir);
        }
        assert_eq!(Dir::parse("r"), None);
    }

    fn resolve(pid: u32) -> Vec<Layer> {
        let mut layers = Vec::new();
        descend(&mut layers, Some(pid)).unwrap();
        layers.reverse();
        layers
    }

    fn names(layers: &[Layer]) -> Vec<&'static str> {
        layers.iter().map(Layer::name).collect()
    }

    /// A real tmux server and pty client, Neovim in the left pane: resolution,
    /// fall-through, entry and close all run against the live protocols.
    #[test]
    fn tmux_and_nvim_route_innermost_first() {
        use std::process::{Command, Stdio};
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("hypr-nav-tmux-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
            // SAFETY: set once, before any test thread reads it, to the same value.
            unsafe { std::env::set_var("XDG_RUNTIME_DIR", &dir) };
        }
        let env = [
            ("TMUX_TMPDIR", dir.as_os_str()),
            ("TERM", "xterm-256color".as_ref()),
        ];
        let tmux = |args: &[&str]| {
            let out = Command::new("tmux")
                .args(["-L", "hypr-nav", "-f", "/dev/null"])
                .args(args)
                .envs(env)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let wait_for = |what: &str, ready: &dyn Fn() -> bool| {
            for _ in 0..500 {
                if ready() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("timed out waiting for {what}");
        };
        tmux(&["new-session", "-d", "-x", "120", "-y", "40", "nvim --clean"]);
        tmux(&["split-window", "-h", "-d"]);
        let mut client = Command::new("script")
            .args(["-qfc", "tmux -L hypr-nav attach", "/dev/null"])
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("script on PATH");
        let result = std::panic::catch_unwind(|| {
            let client_pid = || tmux(&["list-clients", "-F", "#{client_pid}"]).parse::<u32>();
            wait_for("tmux client", &|| client_pid().is_ok());
            let pid = client_pid().unwrap();
            wait_for("nvim socket", &|| resolve(pid).len() == 2);
            let active = || tmux(&["display", "-p", "#{pane_index}"]);

            let layers = resolve(pid);
            assert_eq!(names(&layers), ["nvim", "tmux"]);
            assert_eq!(layers[0].navigate(Dir::Right).unwrap(), Step::Pass);
            assert_eq!(layers[1].navigate(Dir::Right).unwrap(), Step::Done);
            assert_eq!(active(), "1");

            let layers = resolve(pid);
            assert_eq!(names(&layers), ["tmux"]);
            assert_eq!(layers[0].navigate(Dir::Right).unwrap(), Step::Pass);
            assert_eq!(layers[0].enter(Dir::Right).unwrap(), Step::Done);
            assert_eq!(active(), "0");

            // An unnamed session with two panes loses only the focused pane.
            let layers = resolve(pid);
            assert_eq!(layers[0].close().unwrap(), Step::Pass);
            assert_eq!(layers[1].close().unwrap(), Step::Done);
            wait_for("pane close", &|| tmux(&["list-panes", "-F", "x"]) == "x");
        });
        tmux(&["kill-server"]);
        let _ = client.kill();
        let _ = client.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap();
    }
}
