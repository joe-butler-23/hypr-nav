use crate::{R, exchange, runtime_dir};
use serde_json::Value;
use std::path::PathBuf;

pub struct Hypr(PathBuf);

/// Compositor identity of a window; any change cancels a pending action.
#[derive(Debug, PartialEq, Eq)]
pub struct Window {
    pub address: String,
    pub class: String,
    pub pid: u32,
    pub tag: String,
}

impl Hypr {
    pub fn connect() -> R<Self> {
        let signature = std::env::var("HYPRLAND_INSTANCE_SIGNATURE")
            .map_err(|_| "HYPRLAND_INSTANCE_SIGNATURE is unset")?;
        Ok(Self(
            runtime_dir()?
                .join("hypr")
                .join(signature)
                .join(".socket.sock"),
        ))
    }

    fn request(&self, message: &str) -> R<String> {
        let reply = exchange(&self.0, message.as_bytes(), |_| false)?;
        Ok(String::from_utf8_lossy(&reply).trim().to_string())
    }

    pub fn active(&self) -> R<Option<Window>> {
        let reply: Value = serde_json::from_str(&self.request("j/activewindow")?)
            .map_err(|err| format!("activewindow: {err}"))?;
        Ok(parse_window(&reply))
    }

    pub fn still(&self, window: &Window) -> R<()> {
        match self.active()? {
            Some(active) if active == *window => Ok(()),
            _ => Err(format!("{} lost focus mid-action", window.class)),
        }
    }

    pub fn dispatch(&self, lua: &str) -> R<()> {
        match self.request(&format!("dispatch {lua}"))?.as_str() {
            "ok" => Ok(()),
            reply => Err(format!("dispatch {lua}: {reply}")),
        }
    }
}

fn parse_window(reply: &Value) -> Option<Window> {
    Some(Window {
        address: reply["address"].as_str()?.to_string(),
        class: reply["class"].as_str()?.to_string(),
        pid: u32::try_from(reply["pid"].as_u64()?).ok()?,
        tag: reply["xdgTag"].as_str().unwrap_or_default().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_workspace_has_no_window() {
        assert_eq!(parse_window(&json!({})), None);
        let window = parse_window(&json!({
            "address": "0x5a", "class": "kitty", "pid": 7, "xdgTag": "kitty-a", "title": "t"
        }))
        .unwrap();
        assert_eq!((window.pid, window.tag.as_str()), (7, "kitty-a"));
    }
}
