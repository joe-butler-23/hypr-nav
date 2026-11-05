use crate::hypr::Window;
use crate::{Dir, R, Step, exchange, proc, runtime_dir};
use serde_json::{Value, json};
use std::path::PathBuf;

/// The focused pane of one Kitty OS window, read over Kitty's control socket.
pub struct Kitty {
    socket: PathBuf,
    tab: Value,
    window: Value,
}

impl Kitty {
    /// Kitty listens at `$XDG_RUNTIME_DIR/kitty-<pid>`; a window without that
    /// socket is not a remotely controllable Kitty.
    pub fn attach(window: &Window) -> R<Option<Self>> {
        let socket = runtime_dir()?.join(format!("kitty-{}", window.pid));
        if !socket.exists() {
            return Ok(None);
        }
        let reply = command(&socket, "ls", json!({}))?;
        let data: Value = reply["data"]
            .as_str()
            .and_then(|data| serde_json::from_str(data).ok())
            .ok_or("kitty ls: malformed data")?;
        let (tab, pane) = focused(&data, window).map_err(|err| format!("kitty: {err}"))?;
        Ok(Some(Self {
            socket,
            tab: tab.clone(),
            window: pane.clone(),
        }))
    }

    pub fn inner(&self) -> R<Option<u32>> {
        let pid = self.window["pid"].as_u64().ok_or("kitty pane has no pid")?;
        Ok(u32::try_from(pid).ok().and_then(proc::foreground))
    }

    fn act(&self, name: &str, window: u64) -> R<Step> {
        command(&self.socket, name, json!({"match": format!("id:{window}")}))?;
        Ok(Step::Done)
    }

    pub fn navigate(&self, dir: Dir) -> R<Step> {
        let groups = ids(&self.window["neighbors"][side(dir)]);
        match pick(&self.tab, &groups) {
            Some(window) => self.act("focus-window", window),
            None => Ok(Step::Pass),
        }
    }

    pub fn enter(&self, dir: Dir) -> R<Step> {
        match entry_window(&self.tab, &self.window, dir) {
            Some(window) => self.act("focus-window", window),
            None => Ok(Step::Pass),
        }
    }

    /// Close exactly the pane that was read; Kitty closes its tab and OS
    /// window with their last pane. Closing the window through Hyprland
    /// instead would take any pane opened since the read (model/README.md).
    pub fn close(&self) -> R<Step> {
        let window = self.window["id"].as_u64().ok_or("kitty pane has no id")?;
        self.act("close-window", window)
    }
}

fn command(socket: &std::path::Path, name: &str, payload: Value) -> R<Value> {
    const PREFIX: &[u8] = b"\x1bP@kitty-cmd";
    const SUFFIX: &[u8] = b"\x1b\\";
    let body = json!({"cmd": name, "version": [0, 49, 0], "payload": payload});
    let request = [PREFIX, body.to_string().as_bytes(), SUFFIX].concat();
    let reply = exchange(socket, &request, |reply| reply.ends_with(SUFFIX))?;
    let reply: Value = reply
        .strip_prefix(PREFIX)
        .and_then(|reply| reply.strip_suffix(SUFFIX))
        .and_then(|reply| serde_json::from_slice(reply).ok())
        .ok_or_else(|| format!("kitty {name}: malformed reply"))?;
    match reply["ok"].as_bool() {
        Some(true) => Ok(reply),
        _ => Err(format!("kitty {name}: {}", reply["error"])),
    }
}

/// One shared Kitty process can own many OS windows; Hyprland's `xdgTag`
/// (Kitty's `wm_name`) says which. Kitty gives OS windows it creates itself
/// (a tab dragged out, `new_os_window`) the server's first tag, and untagged
/// windows carry none, so several may match: then the one Kitty reports
/// focused is the window Hyprland focused.
fn focused<'a>(data: &'a Value, window: &Window) -> R<(&'a Value, &'a Value)> {
    let os_windows = data.as_array().ok_or("ls is not a list")?;
    let candidates: Vec<&Value> = os_windows
        .iter()
        .filter(|os| {
            os["wm_class"] == window.class.as_str()
                && (window.tag.is_empty() || os["wm_name"] == window.tag.as_str())
        })
        .collect();
    let os_window = match candidates.as_slice() {
        [] => {
            let names: Vec<String> = os_windows
                .iter()
                .map(|os| format!("{}/{}", os["wm_class"], os["wm_name"]))
                .collect();
            return Err(format!(
                "no OS window matches class {:?} tag {:?} (has {})",
                window.class,
                window.tag,
                names.join(", ")
            ));
        }
        [only] => *only,
        several => {
            only(several.iter().copied(), |os| os["is_focused"] == true).ok_or_else(|| {
                format!(
                    "{} OS windows match tag {:?} and none is uniquely focused",
                    several.len(),
                    window.tag
                )
            })?
        }
    };
    let tab = only(
        os_window["tabs"]
            .as_array()
            .ok_or("OS window has no tabs")?,
        |tab| tab["is_active"] == true,
    )
    .ok_or("no unique active tab")?;
    let pane = only(
        tab["windows"].as_array().ok_or("tab has no windows")?,
        |pane| pane["is_active"] == true,
    )
    .ok_or("no unique active pane")?;
    Ok((tab, pane))
}

/// The single item satisfying `predicate`, if exactly one does.
fn only<T>(items: impl IntoIterator<Item = T>, predicate: impl Fn(&T) -> bool) -> Option<T> {
    let mut matches = items.into_iter().filter(|item| predicate(item));
    let found = matches.next()?;
    matches.next().is_none().then_some(found)
}

fn ids(value: &Value) -> Vec<u64> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .collect()
}

fn side(dir: Dir) -> &'static str {
    ["left", "right", "top", "bottom"][dir as usize]
}

fn group_of(tab: &Value, window: u64) -> Option<u64> {
    let groups = tab["groups"].as_array()?;
    let group = groups
        .iter()
        .find(|group| ids(&group["windows"]).contains(&window))?;
    group["id"].as_u64()
}

/// The pane Kitty itself would focus among `groups`: the most recently active
/// group, else the first. Overlay groups show their last window.
fn pick(tab: &Value, groups: &[u64]) -> Option<u64> {
    let recent = ids(&tab["active_window_history"])
        .into_iter()
        .rev()
        .filter_map(|window| group_of(tab, window));
    let group = recent
        .chain(groups.iter().copied())
        .find(|group| groups.contains(group))?;
    let group = tab["groups"]
        .as_array()?
        .iter()
        .find(|g| g["id"] == group)?;
    ids(&group["windows"]).last().copied()
}

/// A pane on the edge entered from `dir`, unless the focused pane is on it.
fn entry_window(tab: &Value, focused: &Value, dir: Dir) -> Option<u64> {
    let side = side(dir.opposite());
    if ids(&focused["neighbors"][side]).is_empty() {
        return None;
    }
    let edge: Vec<u64> = tab["windows"]
        .as_array()?
        .iter()
        .filter(|window| ids(&window["neighbors"][side]).is_empty())
        .filter_map(|window| group_of(tab, window["id"].as_u64()?))
        .collect();
    pick(tab, &edge)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three splits `1 | 2 / 3` (2 above 3), as `kitty @ ls` reports them.
    fn tab() -> Value {
        json!({
            "is_active": true,
            "active_window_history": [3, 1],
            "groups": [{"id": 11, "windows": [1]}, {"id": 12, "windows": [2]}, {"id": 13, "windows": [3, 4]}],
            "windows": [
                {"id": 1, "pid": 100, "is_active": true, "neighbors": {"right": [12, 13]}},
                {"id": 2, "pid": 101, "is_active": false, "neighbors": {"left": [11], "bottom": [13]}},
                {"id": 4, "pid": 102, "is_active": false, "neighbors": {"left": [11], "top": [12]}}
            ]
        })
    }

    #[test]
    fn navigation_prefers_recent_neighbours_and_overlay_tops() {
        let tab = tab();
        assert_eq!(pick(&tab, &[12, 13]), Some(4));
        assert_eq!(pick(&tab, &[12]), Some(2));
        assert_eq!(pick(&tab, &[]), None);
    }

    #[test]
    fn entry_lands_on_the_entered_edge() {
        let tab = tab();
        let windows = tab["windows"].as_array().unwrap();
        assert_eq!(entry_window(&tab, &windows[1], Dir::Right), Some(1));
        assert_eq!(entry_window(&tab, &windows[0], Dir::Right), None);
        assert_eq!(entry_window(&tab, &windows[0], Dir::Left), Some(4));
    }

    #[test]
    fn shared_process_resolves_by_tag_then_kitty_focus() {
        let os = |tag: &str, focused: bool| json!({"wm_class": "kitty", "wm_name": tag, "is_focused": focused, "tabs": [tab()]});
        let window = |tag: &str| Window {
            address: "0x1".into(),
            class: "kitty".into(),
            pid: 9,
            tag: tag.into(),
        };
        let distinct = json!([os("kitty-a", true), os("kitty-b", false)]);
        assert!(focused(&distinct, &window("kitty-b")).is_ok());
        assert!(focused(&distinct, &window("kitty-c")).is_err());
        // A dragged-out tab reuses the server's tag: Kitty's focus decides.
        let shared = json!([os("kitty-a", false), os("kitty-a", true)]);
        let (tab, _) = focused(&shared, &window("kitty-a")).unwrap();
        assert!(std::ptr::eq(tab, &shared[1]["tabs"][0]));
        assert!(focused(&distinct, &window("")).is_ok());
        let unfocused = json!([os("kitty-a", false), os("kitty-a", false)]);
        assert!(focused(&unfocused, &window("kitty-a")).is_err());
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        /// OS windows sharing tags and focus, with any number of active tabs
        /// and panes.
        fn ls() -> impl Strategy<Value = Value> {
            let pane = (1u64..5, any::<bool>())
                .prop_map(|(id, active)| json!({"id": id, "is_active": active}));
            let tab = (any::<bool>(), proptest::collection::vec(pane, 0..3))
                .prop_map(|(active, windows)| json!({"is_active": active, "windows": windows}));
            let os = (
                proptest::sample::select(&["kitty", "yazi"][..]),
                proptest::sample::select(&["a", "b", ""][..]),
                any::<bool>(),
                proptest::collection::vec(tab, 0..3),
            )
                .prop_map(|(class, tag, focused, tabs)| {
                    json!({"wm_class": class, "wm_name": tag, "is_focused": focused, "tabs": tabs})
                });
            proptest::collection::vec(os, 0..4).prop_map(Value::from)
        }

        proptest! {
            /// The pane read is the unique active pane of the unique active
            /// tab of an OS window that matches the compositor's class and
            /// tag, and Kitty's focus decides between several such windows.
            #[test]
            fn focused_pane_belongs_to_the_compositor_window(
                data in ls(),
                tag in proptest::sample::select(&["a", "b", ""][..]),
            ) {
                let window = Window { address: "0x1".into(), class: "kitty".into(), pid: 9, tag: tag.into() };
                let matches = |os: &Value| os["wm_class"] == "kitty" && (tag.is_empty() || os["wm_name"] == tag);
                let candidates: Vec<&Value> = data.as_array().unwrap().iter().filter(|os| matches(os)).collect();
                if let Ok((tab, pane)) = focused(&data, &window) {
                    let os = candidates
                        .iter()
                        .find(|os| os["tabs"].as_array().unwrap().iter().any(|t| std::ptr::eq(t, tab)))
                        .expect("tab comes from a matching OS window");
                    let focused = candidates.iter().filter(|os| os["is_focused"] == true).count();
                    prop_assert!(candidates.len() == 1 || (os["is_focused"] == true && focused == 1));
                    prop_assert!(tab["is_active"] == true && pane["is_active"] == true);
                    prop_assert_eq!(os["tabs"].as_array().unwrap().iter().filter(|t| t["is_active"] == true).count(), 1);
                    prop_assert_eq!(tab["windows"].as_array().unwrap().iter().filter(|p| p["is_active"] == true).count(), 1);
                }
            }
        }
    }
}
