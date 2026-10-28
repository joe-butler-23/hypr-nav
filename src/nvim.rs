use crate::{Dir, R, Step, exchange, proc, runtime_dir};
use rmpv::Value;
use std::path::PathBuf;

const EDGE: &str = "HYPRNAV_EDGE";

pub struct Nvim {
    socket: PathBuf,
}

impl Nvim {
    /// The server socket is `--listen`, or the default `nvim.<pid>.0` of the
    /// process or its embedded server child (the TUI and server split in 0.10+).
    pub fn attach(pid: u32, argv: &[String]) -> R<Option<Self>> {
        let listen = argv
            .iter()
            .position(|arg| arg == "--listen")
            .and_then(|index| argv.get(index + 1).cloned())
            .or_else(|| {
                argv.iter()
                    .find_map(|arg| Some(arg.strip_prefix("--listen=")?.into()))
            });
        let dir = runtime_dir()?;
        let defaults = std::iter::once(pid)
            .chain(proc::children(pid))
            .map(|pid| dir.join(format!("nvim.{pid}.0")));
        let socket = listen
            .map(PathBuf::from)
            .into_iter()
            .chain(defaults)
            .find(|path| path.exists());
        Ok(socket.map(|socket| Self { socket }))
    }

    /// Evaluate through `execute()` so `wincmd` works in every mode and never
    /// types into a buffer.
    fn eval(&self, expr: &str) -> R<String> {
        let request = Value::Array(vec![
            0.into(),
            0.into(),
            "nvim_eval".into(),
            Value::Array(vec![expr.into()]),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &request).map_err(|err| err.to_string())?;
        let decode = |reply: &[u8]| rmpv::decode::read_value(&mut &reply[..]);
        let reply = exchange(&self.socket, &bytes, |reply| decode(reply).is_ok())?;
        match decode(&reply).map_err(|err| format!("nvim reply: {err}"))? {
            Value::Array(items) if items.len() == 4 && items[2].is_nil() => Ok(items[3]
                .as_str()
                .map_or_else(|| items[3].to_string(), String::from)),
            reply => Err(format!("nvim: {reply}")),
        }
    }

    fn eval_step(&self, expr: String) -> R<Step> {
        Ok(match self.eval(&expr)?.as_str() {
            EDGE => Step::Pass,
            _ => Step::Done,
        })
    }

    pub fn navigate(&self, dir: Dir) -> R<Step> {
        let key = vim_key(dir);
        self.eval_step(format!(
            "winnr() == winnr('{key}') ? '{EDGE}' : execute('wincmd {key}')"
        ))
    }

    pub fn enter(&self, dir: Dir) -> R<Step> {
        let key = vim_key(dir.opposite());
        self.eval_step(format!(
            "winnr('$') == 1 ? '{EDGE}' : execute('999wincmd {key}')"
        ))
    }
}

fn vim_key(dir: Dir) -> char {
    ['h', 'l', 'k', 'j'][dir as usize]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    /// Drives a real headless Neovim over its socket.
    #[test]
    fn navigates_real_splits_and_reports_edges() {
        let dir = std::env::temp_dir().join(format!("hypr-nav-nvim-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("sock");
        let mut server = Command::new("nvim")
            .args(["--headless", "--clean", "--listen"])
            .arg(&socket)
            .args(["-c", "vsplit"])
            .stdin(Stdio::null())
            .spawn()
            .expect("nvim on PATH");
        while !socket.exists() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let nvim = Nvim { socket };
        let result = std::panic::catch_unwind(|| {
            assert_eq!(nvim.navigate(Dir::Left).unwrap(), Step::Pass);
            assert_eq!(nvim.navigate(Dir::Right).unwrap(), Step::Done);
            assert_eq!(nvim.navigate(Dir::Right).unwrap(), Step::Pass);
            assert_eq!(nvim.navigate(Dir::Up).unwrap(), Step::Pass);
            assert_eq!(nvim.enter(Dir::Left).unwrap(), Step::Done);
            assert_eq!(nvim.eval("winnr()").unwrap(), "2");
            assert!(nvim.eval("nonsense(").is_err());
        });
        let _ = server.kill();
        let _ = server.wait();
        std::fs::remove_dir_all(&dir).unwrap();
        result.unwrap();
    }
}
