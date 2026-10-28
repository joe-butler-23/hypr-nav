use crate::{Dir, R, Step, proc};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Space-separated: tmux escapes tabs outside UTF-8 locales, and only the
/// final session name may contain spaces.
const CLIENT_FORMAT: &str = "#{client_pid} #{client_tty} #{pane_id} #{pane_pid} #{pane_at_left} #{pane_at_right} #{pane_at_top} #{pane_at_bottom} #{session_windows} #{window_panes} #{session_name}";

/// A tmux client and the pane it shows, captured in one query.
pub struct Tmux {
    socket: PathBuf,
    client: Client,
}

#[derive(Debug, PartialEq, Eq)]
struct Client {
    tty: String,
    pane: String,
    pane_pid: u32,
    edges: [bool; 4],
    /// Named sessions and a final pane persist: close detaches instead.
    keep: bool,
}

impl Tmux {
    pub fn attach(pid: u32, argv: &[String]) -> R<Self> {
        let socket = socket(pid, argv)?;
        let rows = tmux(&socket, &["list-clients", "-F", CLIENT_FORMAT])?;
        let client = parse_client(&rows, pid).ok_or("tmux client not listed")?;
        Ok(Self { socket, client })
    }

    fn run(&self, args: &[&str]) -> R<String> {
        tmux(&self.socket, args)
    }

    pub fn inner(&self) -> Option<u32> {
        proc::foreground(self.client.pane_pid)
    }

    pub fn navigate(&self, dir: Dir) -> R<Step> {
        if self.client.edges[dir as usize] {
            return Ok(Step::Pass);
        }
        let flag = format!("-{}", dir.name()[..1].to_ascii_uppercase());
        self.run(&["select-pane", "-t", &self.client.pane, &flag])?;
        Ok(Step::Done)
    }

    pub fn enter(&self, dir: Dir) -> R<Step> {
        let format = "#{pane_id} #{pane_at_left} #{pane_at_right} #{pane_at_top} #{pane_at_bottom}";
        let rows = self.run(&["list-panes", "-t", &self.client.pane, "-F", format])?;
        match entry_pane(&rows, dir, &self.client.pane) {
            Some(pane) => {
                self.run(&["select-pane", "-t", &pane])?;
                Ok(Step::Done)
            }
            None => Ok(Step::Pass),
        }
    }

    pub fn close(&self) -> R<Step> {
        match self.client.keep {
            true => self.run(&["detach-client", "-t", &self.client.tty])?,
            false => self.run(&["kill-pane", "-t", &self.client.pane])?,
        };
        Ok(Step::Done)
    }
}

fn tmux(socket: &Path, args: &[&str]) -> R<String> {
    proc::run(Command::new("tmux").arg("-S").arg(socket).args(args))
}

/// The server socket from `-S path` or `-L name`, else tmux's default.
fn socket(pid: u32, argv: &[String]) -> R<PathBuf> {
    let mut args = argv.iter().skip(1);
    let mut name = "default".to_string();
    while let Some(arg) = args.next() {
        let (flag, inline) = match arg.split_at_checked(2) {
            Some((flag @ ("-S" | "-L"), inline)) => (flag, inline),
            _ => continue,
        };
        let value = match inline {
            "" => args.next().ok_or("tmux flag without value")?.clone(),
            inline => inline.to_string(),
        };
        match flag {
            "-S" => return Ok(value.into()),
            _ => name = value,
        }
    }
    // tmux names its directory by the client's real uid.
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:")?.split_whitespace().next())
        .ok_or("tmux client uid unreadable")?;
    let dir = proc::env(pid, "TMUX_TMPDIR").unwrap_or_else(|| "/tmp".into());
    Ok(PathBuf::from(dir).join(format!("tmux-{uid}")).join(name))
}

fn parse_client(rows: &str, pid: u32) -> Option<Client> {
    rows.lines().find_map(|row| {
        let fields: Vec<&str> = row.splitn(11, ' ').collect();
        let [
            client_pid,
            tty,
            pane,
            pane_pid,
            left,
            right,
            top,
            bottom,
            windows,
            panes,
            session,
        ] = fields.as_slice()
        else {
            return None;
        };
        (client_pid.parse() == Ok(pid)).then(|| Client {
            tty: tty.to_string(),
            pane: pane.to_string(),
            pane_pid: pane_pid.parse().unwrap_or(0),
            edges: [left, right, top, bottom].map(|edge| *edge == "1"),
            keep: session.parse::<u32>().is_err() || (*windows == "1" && *panes == "1"),
        })
    })
}

/// A pane on the edge entered from `dir`, unless the active pane is already there.
fn entry_pane(rows: &str, dir: Dir, active: &str) -> Option<String> {
    let edge = dir.opposite() as usize + 1;
    let on_edge: Vec<&str> = rows
        .lines()
        .map(|row| row.split(' ').collect::<Vec<_>>())
        .filter(|fields| fields.get(edge) == Some(&"1"))
        .map(|fields| fields[0])
        .collect();
    match on_edge.contains(&active) {
        true => None,
        false => on_edge.first().map(|pane| pane.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_row_matches_pid_and_close_policy() {
        let rows = "7 /dev/pts/1 %1 10 1 0 1 1 1 2 0\n8 /dev/pts/2 %4 11 0 1 1 1 1 1 my work";
        let unnamed = parse_client(rows, 7).unwrap();
        assert_eq!(
            (
                unnamed.tty.as_str(),
                unnamed.pane.as_str(),
                unnamed.edges,
                unnamed.keep
            ),
            ("/dev/pts/1", "%1", [true, false, true, true], false)
        );
        assert!(parse_client(rows, 8).unwrap().keep);
        assert!(parse_client(rows, 9).is_none());
    }

    #[test]
    fn entry_prefers_staying_on_the_entered_edge() {
        let rows = "%1 1 0 1 1\n%2 0 1 1 1";
        assert_eq!(entry_pane(rows, Dir::Right, "%2").as_deref(), Some("%1"));
        assert_eq!(entry_pane(rows, Dir::Right, "%1"), None);
        assert_eq!(entry_pane(rows, Dir::Down, "%2"), None);
    }

    #[test]
    fn socket_follows_client_flags() {
        let argv = |args: &[&str]| args.iter().map(|a| a.to_string()).collect::<Vec<_>>();
        let pid = std::process::id();
        assert_eq!(
            socket(pid, &argv(&["tmux", "-S", "/s/x", "a"])).unwrap(),
            PathBuf::from("/s/x")
        );
        assert_eq!(
            socket(pid, &argv(&["tmux", "-S/s/y"])).unwrap(),
            PathBuf::from("/s/y")
        );
        assert!(
            socket(pid, &argv(&["tmux", "-L", "work"]))
                .unwrap()
                .ends_with("work")
        );
        assert!(
            socket(pid, &argv(&["tmux", "attach"]))
                .unwrap()
                .ends_with("default")
        );
    }
}
