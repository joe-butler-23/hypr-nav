use crate::{R, remaining};
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

pub fn argv(pid: u32) -> Vec<String> {
    fs::read(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

pub fn env(pid: u32, key: &str) -> Option<String> {
    let environ = fs::read(format!("/proc/{pid}/environ")).ok()?;
    environ.split(|byte| *byte == 0).find_map(|entry| {
        let value = entry.strip_prefix(key.as_bytes())?.strip_prefix(b"=")?;
        Some(String::from_utf8_lossy(value).into_owned()).filter(|value| !value.is_empty())
    })
}

/// Children of every thread, since a multithreaded parent may fork from any.
pub fn children(pid: u32) -> Vec<u32> {
    let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) else {
        return Vec::new();
    };
    tasks
        .flatten()
        .filter_map(|task| fs::read_to_string(task.path().join("children")).ok())
        .flat_map(|list| {
            let pids: Vec<u32> = list
                .split_whitespace()
                .filter_map(|c| c.parse().ok())
                .collect();
            pids
        })
        .collect()
}

/// `(tty_nr, tpgid)` from `/proc/<pid>/stat`.
fn terminal(pid: u32) -> Option<(u64, u32)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_terminal(&stat)
}

fn parse_terminal(stat: &str) -> Option<(u64, u32)> {
    // Fields after the parenthesised command: state ppid pgrp session tty_nr tpgid.
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    let tty = fields.get(4)?.parse().ok()?;
    let foreground = fields.get(5)?.parse::<i64>().ok()?;
    Some((tty, u32::try_from(foreground).ok().filter(|pid| *pid > 0)?))
}

/// Leader of the foreground process group on `pid`'s controlling terminal.
pub fn foreground(pid: u32) -> Option<u32> {
    terminal(pid)
        .filter(|(tty, _)| *tty != 0)
        .map(|(_, leader)| leader)
}

/// Foreground of a window process that hosts exactly one terminal session.
/// Windows with no terminal children have no inner layers; several sessions
/// cannot be told apart without the terminal's own focus information.
pub fn window_foreground(pid: u32) -> R<Option<u32>> {
    let sessions: HashSet<(u64, u32)> = children(pid)
        .into_iter()
        .filter_map(terminal)
        .filter(|(tty, _)| *tty != 0)
        .collect();
    match sessions.len() {
        0 => Ok(None),
        1 => Ok(sessions.into_iter().next().map(|(_, leader)| leader)),
        n => Err(format!("{n} terminal sessions and no focus information")),
    }
}

/// Run a short client command within the keypress budget.
pub fn run(command: &mut Command) -> R<String> {
    let name = format!("{:?}", command.get_program());
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("{name}: {err}"))?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                if let Some(mut stdout) = child.stdout.take() {
                    let _ = stdout.read_to_string(&mut out);
                }
                return match status.success() {
                    true => Ok(out),
                    false => Err(format!("{name} exited with {status}")),
                };
            }
            Ok(None) if remaining().is_ok() => std::thread::sleep(Duration::from_millis(1)),
            other => {
                let _ = child.kill();
                let _ = child.wait();
                let reason = other.map_or_else(|err| err.to_string(), |_| "timed out".into());
                return Err(format!("{name}: {reason}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_fields_follow_the_last_parenthesis() {
        let stat = "42 (odd) name)) S 1 42 42 34816 42 4194304";
        assert_eq!(parse_terminal(stat), Some((34816, 42)));
        assert_eq!(parse_terminal("9 (kitty) S 1 9 9 0 -1 0"), None);
    }

    #[test]
    fn own_terminal_state_is_readable() {
        assert_eq!(basename("/nix/store/x-neovim/bin/nvim"), "nvim");
        assert!(!argv(std::process::id()).is_empty());
        assert_eq!(
            run(Command::new("sh").args(["-c", "echo hi"])).as_deref(),
            Ok("hi\n")
        );
        assert!(run(&mut Command::new("false")).is_err());
    }
}
