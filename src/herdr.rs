use crate::{Dir, R, Step, exchange, proc};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::PathBuf;

/// An attached Herdr client, addressed through its server's JSON socket.
pub struct Herdr {
    socket: PathBuf,
}

impl Herdr {
    /// Explicit `--session` beats variables inherited from a parent Herdr
    /// pane. Remote clients and one-shot commands are not attached clients.
    pub fn attach(pid: u32, argv: &[String]) -> R<Option<Self>> {
        let Some(session) = client_session(argv) else {
            return Ok(None);
        };
        let sessions =
            |name: &str| config_dir().map(|dir| dir.join("sessions").join(name).join("herdr.sock"));
        let socket = match session {
            Some(name) => sessions(&name)?,
            None => match proc::env(pid, "HERDR_SOCKET_PATH") {
                Some(path) => path.into(),
                None => match proc::env(pid, "HERDR_SESSION") {
                    Some(name) => sessions(&name)?,
                    None => config_dir()?.join("herdr.sock"),
                },
            },
        };
        Ok(Some(Self { socket }))
    }

    fn call(&self, method: &str, params: Value) -> R<Value> {
        let request = format!(
            "{}\n",
            json!({"id": "hypr-nav", "method": method, "params": params})
        );
        let reply = exchange(&self.socket, request.as_bytes(), |reply| {
            reply.ends_with(b"\n")
        })?;
        let mut reply: Value =
            serde_json::from_slice(&reply).map_err(|err| format!("herdr {method}: {err}"))?;
        match reply.get("error") {
            Some(error) => Err(format!("herdr {method}: {error}")),
            None => Ok(reply["result"].take()),
        }
    }

    pub fn inner(&self) -> R<Option<u32>> {
        let info = self.call("pane.process_info", json!({}))?;
        Ok(info["process_info"]["foreground_process_group_id"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok()))
    }

    pub fn navigate(&self, dir: Dir) -> R<Step> {
        let reply = self.call("pane.focus_direction", json!({"direction": dir.name()}))?;
        match (&reply["focus"]["changed"], &reply["focus"]["reason"]) {
            (Value::Bool(true), _) => Ok(Step::Done),
            (Value::Bool(false), reason) if reason == "no_neighbor" => Ok(Step::Pass),
            _ => Err(format!("herdr focus_direction: {reply}")),
        }
    }

    pub fn enter(&self, dir: Dir) -> R<Step> {
        let layout = self.call("pane.layout", json!({}))?;
        match entry_pane(&layout["layout"], dir) {
            Some(pane) => self.pane_call("pane.focus", &pane),
            None => Ok(Step::Pass),
        }
    }

    /// Close the focused pane; the final pane passes so the outer layer
    /// closes the client and the persistent session survives.
    pub fn close(&self) -> R<Step> {
        let snapshot = self.call("session.snapshot", json!({}))?;
        match close_target(&snapshot["snapshot"]) {
            Some(Some(pane)) => self.pane_call("pane.close", &pane),
            Some(None) => Ok(Step::Pass),
            None => Err("herdr snapshot is inconsistent".into()),
        }
    }

    /// Herdr acknowledges with a method-specific result; only an error fails.
    fn pane_call(&self, method: &str, pane: &str) -> R<Step> {
        self.call(method, json!({"pane_id": pane}))?;
        Ok(Step::Done)
    }
}

fn config_dir() -> R<PathBuf> {
    let env = |key| {
        std::env::var_os(key)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    env("XDG_CONFIG_HOME")
        .or_else(|| env("HOME").map(|home| home.join(".config")))
        .map(|dir| dir.join("herdr"))
        .ok_or_else(|| "neither XDG_CONFIG_HOME nor HOME is set".into())
}

/// `Some(session)` for a local attached client, `None` for anything else.
fn client_session(argv: &[String]) -> Option<Option<String>> {
    let args: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    if let ["session", "attach", name] = args.as_slice() {
        return (!name.is_empty()).then(|| Some(name.to_string()));
    }
    if args.first() == Some(&"session") {
        return None;
    }
    let mut session = None;
    let mut rest = args.iter().copied().skip_while(|arg| *arg == "client");
    while let Some(arg) = rest.next() {
        let name = match arg.strip_prefix("--session") {
            Some("") => rest.next()?,
            Some(inline) => inline.strip_prefix('=')?,
            None => return None,
        };
        if session.replace(name).is_some() || name.is_empty() {
            return None;
        }
    }
    Some(session.map(String::from))
}

/// A pane on the edge entered from `dir`, unless the focused pane is on it.
fn entry_pane(layout: &Value, dir: Dir) -> Option<String> {
    let panes = layout["panes"].as_array()?;
    if layout["zoomed"].as_bool()? || panes.len() < 2 {
        return None;
    }
    let (axis, extent) = match dir {
        Dir::Left | Dir::Right => ("x", "width"),
        Dir::Up | Dir::Down => ("y", "height"),
    };
    // Moving left or up enters at the far (right or bottom) side.
    let far = matches!(dir, Dir::Left | Dir::Up);
    let edge = |rect: &Value| {
        let start = rect[axis].as_u64()?;
        Some(if far {
            start + rect[extent].as_u64()?
        } else {
            start
        })
    };
    let boundary = edge(&layout["area"])?;
    let mut ids = HashSet::new();
    let mut on_edge = Vec::new();
    for pane in panes {
        let id = pane["pane_id"].as_str().filter(|id| ids.insert(*id))?;
        if edge(&pane["rect"])? == boundary {
            on_edge.push(id);
        }
    }
    let focused = layout["focused_pane_id"].as_str()?;
    match on_edge.contains(&focused) {
        true => None,
        false => on_edge.first().map(|id| id.to_string()),
    }
}

/// `Some(Some(pane))` closes that pane, `Some(None)` leaves the final pane to
/// the outer layer, and `None` refuses a snapshot whose focus is inconsistent.
fn close_target(snapshot: &Value) -> Option<Option<String>> {
    let pane_id = snapshot["focused_pane_id"]
        .as_str()
        .filter(|id| !id.is_empty())?;
    let tab_id = snapshot["focused_tab_id"]
        .as_str()
        .filter(|id| !id.is_empty())?;
    let workspace_id = snapshot["focused_workspace_id"]
        .as_str()
        .filter(|id| !id.is_empty())?;
    let unique = |kind: &str, key: &str, id: &str| -> Option<&Value> {
        let items = snapshot[kind].as_array()?;
        let mut matches = items.iter().filter(|item| item[key] == id);
        let found = matches.next()?;
        matches.next().is_none().then_some(found)
    };
    let pane = unique("panes", "pane_id", pane_id)?;
    let tab = unique("tabs", "tab_id", tab_id)?;
    let workspace = unique("workspaces", "workspace_id", workspace_id)?;
    let count = |kind: &str, key: &str, id: &str| {
        snapshot[kind].as_array().map_or(0, |items| {
            items.iter().filter(|item| item[key] == id).count()
        }) as u64
    };
    let consistent = pane["tab_id"] == tab_id
        && pane["workspace_id"] == workspace_id
        && tab["workspace_id"] == workspace_id
        && workspace["active_tab_id"] == tab_id
        && tab["pane_count"].as_u64()? == count("panes", "tab_id", tab_id)
        && workspace["tab_count"].as_u64()? == count("tabs", "workspace_id", workspace_id);
    if !consistent {
        return None;
    }
    let total = |kind: &str| snapshot[kind].as_array().map_or(0, Vec::len);
    let last = total("panes") == 1 && total("tabs") == 1 && total("workspaces") == 1;
    Some((!last).then(|| pane_id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn only_local_attached_clients_are_layers() {
        let session = |list: &[&str]| client_session(&args(list));
        assert_eq!(session(&["herdr"]), Some(None));
        assert_eq!(
            session(&["herdr", "--session", "gk"]),
            Some(Some("gk".into()))
        );
        assert_eq!(
            session(&["herdr", "client", "--session=gk"]),
            Some(Some("gk".into()))
        );
        assert_eq!(
            session(&["herdr", "session", "attach", "w"]),
            Some(Some("w".into()))
        );
        assert_eq!(
            session(&["herdr", "--session", "a", "--session", "b"]),
            None
        );
        assert_eq!(session(&["herdr", "--remote", "host"]), None);
        assert_eq!(session(&["herdr", "api", "schema"]), None);
        assert_eq!(session(&["herdr", "session", "list"]), None);
        assert_eq!(session(&["herdr", "--session="]), None);
    }

    fn layout(focused: &str) -> Value {
        // Two side-by-side panes, as `pane.layout` reports them.
        json!({
            "zoomed": false, "focused_pane_id": focused,
            "area": {"x": 0, "y": 0, "width": 94, "height": 39},
            "panes": [
                {"pane_id": "w1:p1", "rect": {"x": 0, "y": 0, "width": 47, "height": 39}},
                {"pane_id": "w1:p2", "rect": {"x": 47, "y": 0, "width": 47, "height": 39}}
            ]
        })
    }

    #[test]
    fn entry_targets_the_entered_edge() {
        assert_eq!(
            entry_pane(&layout("w1:p2"), Dir::Right).as_deref(),
            Some("w1:p1")
        );
        assert_eq!(
            entry_pane(&layout("w1:p1"), Dir::Left).as_deref(),
            Some("w1:p2")
        );
        assert_eq!(entry_pane(&layout("w1:p1"), Dir::Right), None);
        assert_eq!(entry_pane(&layout("w1:p1"), Dir::Down), None);
        let mut duplicate = layout("w1:p2");
        duplicate["panes"][1]["pane_id"] = "w1:p1".into();
        assert_eq!(entry_pane(&duplicate, Dir::Right), None);
    }

    fn snapshot(panes: &[&str]) -> Value {
        json!({
            "focused_workspace_id": "w1", "focused_tab_id": "w1:t1", "focused_pane_id": panes[0],
            "workspaces": [{"workspace_id": "w1", "tab_count": 1, "active_tab_id": "w1:t1"}],
            "tabs": [{"tab_id": "w1:t1", "workspace_id": "w1", "pane_count": panes.len()}],
            "panes": panes.iter().map(|id| json!({"pane_id": id, "tab_id": "w1:t1", "workspace_id": "w1"})).collect::<Vec<_>>()
        })
    }

    #[test]
    fn close_spares_the_final_pane_and_refuses_inconsistency() {
        assert_eq!(
            close_target(&snapshot(&["w1:p1", "w1:p2"])),
            Some(Some("w1:p1".into()))
        );
        assert_eq!(close_target(&snapshot(&["w1:p1"])), Some(None));
        let mut stale = snapshot(&["w1:p1", "w1:p2"]);
        stale["tabs"][0]["pane_count"] = 3.into();
        assert_eq!(close_target(&stale), None);
        let mut duplicate = snapshot(&["w1:p1", "w1:p1"]);
        duplicate["tabs"][0]["pane_count"] = 2.into();
        assert_eq!(close_target(&duplicate), None);
    }
}
