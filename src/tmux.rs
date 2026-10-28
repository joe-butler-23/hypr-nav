use crate::{Dir, R, Step, proc};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CLIENT_FORMAT: &str = "#{client_tty}\t#{pane_id}\t#{pane_pid}\t#{pane_at_left}\t#{pane_at_right}\t#{pane_at_top}\t#{pane_at_bottom}\t#{session_windows}\t#{window_panes}\t#{session_name}";

/// A tmux client and the pane it shows, captured in one query.
pub struct Tmux {
    socket: PathBuf,
    tty: String,
    client: Client,
}

#[derive(Debug, PartialEq, Eq)]
struct Client {
    pane: String,
    pane_pid: u32,
    edges: [bool; 4],
    /// Named sessions and a final pane persist: close detaches instead.
    keep: bool,
}

impl Tmux {
    pub fn attach(pid: u32, argv: &[String]) -> R<Self> {
        let tty = std::fs::read_link(format!("/proc/{pid}/fd/0"))
            .map_err(|err| format!("tmux client tty: {err}"))?
            .display()
            .to_string();
        let socket = socket(pid, argv)?;
        let rows = tmux(&socket, &["list-clients", "-F", CLIENT_FORMAT])?;
        let client = parse_client(&rows, &tty).ok_or("tmux client not listed")?;
        Ok(Self {
            socket,
            tty,
            client,
        })
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
        let format =
            "#{pane_id}\t#{pane_at_left}\t#{pane_at_right}\t#{pane_at_top}\t#{pane_at_bottom}";
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
            true => self.run(&["detach-client", "-t", &self.tty])?,
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
    let uid = std::fs::metadata("/proc/self")
        .map_err(|err| err.to_string())?
        .uid();
    let dir = proc::env(pid, "TMUX_TMPDIR").unwrap_or_else(|| "/tmp".into());
    Ok(PathBuf::from(dir).join(format!("tmux-{uid}")).join(name))
}

fn parse_client(rows: &str, tty: &str) -> Option<Client> {
    rows.lines().find_map(|row| {
        let fields: Vec<&str> = row.splitn(10, '\t').collect();
        let [
            client_tty,
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
        (*client_tty == tty).then(|| Client {
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
        .map(|row| row.split('\t').collect::<Vec<_>>())
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
    fn client_row_matches_tty_and_close_policy() {
        let rows = "/dev/pts/1\t%1\t10\t1\t0\t1\t1\t1\t2\t0\n\
                    /dev/pts/2\t%4\t11\t0\t1\t1\t1\t1\t1\twork\tname";
        let unnamed = parse_client(rows, "/dev/pts/1").unwrap();
        assert_eq!(
            (unnamed.pane.as_str(), unnamed.edges, unnamed.keep),
            ("%1", [true, false, true, true], false)
        );
        assert!(parse_client(rows, "/dev/pts/2").unwrap().keep);
        assert!(parse_client(rows, "/dev/pts/9").is_none());
    }

    #[test]
    fn entry_prefers_staying_on_the_entered_edge() {
        let rows = "%1\t1\t0\t1\t1\n%2\t0\t1\t1\t1";
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
