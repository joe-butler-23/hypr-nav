# hypr-nav

**Context-Aware Navigation for Hyprland, Tmux, and Kitty.**

Stop fighting with your keybinds. `hypr-nav` is a "smart bridge" that lets you use the same keys (e.g., `Super+H/J/K/L`) to navigate:
1.  **Inside** your terminal multiplexer (Tmux panes, Kitty windows)
2.  **Between** Hyprland windows (when you hit the edge of a pane)

It also includes `hypr-smart-close`, a context-aware `Super+C` that knows when to close a pane, detach a session, or kill a window.

## Features

- **Seamless Context Switching**: Automatically detects if you are in a terminal running Tmux.
- **Edge Detection**: Smart enough to know when you're at the top pane of Tmux and pass the `Up` command to Hyprland instead.
- **Smart Close**: 
    - Closing a named Tmux session? **Detaches** it.
    - Closing a generic pane? **Kills** it.
    - Closing the last pane? **Closes** the window.
- **Zero Config for Apps**: Works by inspecting the process tree and IPC sockets. No plugins required for Hyprland (just binds).

## Installation

### From Source (Rust)

```bash
git clone https://github.com/joe-butler-23/hypr-nav
cd hypr-nav
cargo build --release
sudo cp target/release/hypr-tmux-nav /usr/local/bin/
sudo cp target/release/hypr-smart-close /usr/local/bin/
sudo cp target/release/hypr-kitty-nav /usr/local/bin/
```

## Configuration (Hyprland)

Add this to your `~/.config/hypr/hyprland.conf`:

```ini
# Navigation (replace with your preferred keys)
bind = SUPER, h, exec, hypr-tmux-nav left
bind = SUPER, j, exec, hypr-tmux-nav down
bind = SUPER, k, exec, hypr-tmux-nav up
bind = SUPER, l, exec, hypr-tmux-nav right

# Smart Close
bind = SUPER, c, exec, hypr-smart-close
```

## How It Works

The architecture follows a **Discover -> Inspect -> Act** pipeline:

1.  **Discover**: Queries Hyprland to see if the active window is a terminal.
2.  **Inspect**: Walks the process tree (`/proc`) to see if `tmux` is running inside that terminal.
3.  **Act**: 
    - If in Tmux, asks Tmux "Am I at the edge?". 
    - If yes, tells Hyprland to move focus.
    - If no, tells Tmux to select the next pane.

## Hacking

The core logic is modularized in `src/lib.rs`. You can easily extend this to support other multiplexers (Zellij?) or editors (Neovim?) by adding new detection logic.

## License

MIT
