# hypr-nav

![hypr-nav-banner](assets/hypr-nav.png)

**Context-Aware Navigation for Hyprland, Tmux, and Kitty.**

Stop fighting with your keybinds (or memorizing different binds for different apps). `hypr-nav` is like a bridge that lets you reuse binds, e.g:
1.  **Inside** your terminal multiplexer (Tmux panes, Kitty windows)
2.  **Between** Hyprland windows (when you hit the edge of a pane)

I have also included `hypr-smart-close`, a context-aware `Super+C` that knows when to close a pane, detach a session, or kill a window:

- **Seamless Context Switching**: Automatically detects if you are in a terminal running Tmux.
- **Edge Detection**: Smart enough to know when you're at the top pane of Tmux and pass the `Up` command to Hyprland instead.
- **Smart Close**: 
    - Closing a named Tmux session? **Detaches** it.
    - Closing a generic pane? **Kills** it.
    - Closing the last pane? **Closes** the window.
- **Zero Config for Apps**: Works by inspecting the process tree and IPC sockets. No plugins required for Hyprland (just binds).

The tmux/kitty stuff may be useful for people in its current form. I imagine the smart-close thing will mostly be useful for me and my specific needs. But it should serve as a useful demonstration of how the approach taken with this tool could be adapted to your own specific needs. 

## Installation

### From Source (Rust)

```bash
git clone https://github.com/joe-butler-23/hypr-nav
cd hypr-nav
cargo build --release
sudo cp target/release/hypr-tmux-nav /usr/local/bin/
sudo cp target/release/hypr-smart-close /usr/local/bin/
sudo cp target/release/hypr-nav /usr/local/bin/
```

## Configuration (Hyprland)

Replace your binds to call the relevant tools in your `~/.config/hypr/hyprland.conf`, e.g:

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

The architecture is basically **Discover -> Inspect -> Act**, for example hypr-smart-close does the following:

1.  **Discover**: Queries Hyprland to see if the active window is a terminal.
2.  **Inspect**: Walks the process tree (`/proc`) to see if `tmux` is running inside that terminal.
3.  **Act**: 
    - If in Tmux, asks Tmux "Am I at the edge?". 
    - If yes, tells Hyprland to move focus.
    - If no, tells Tmux to select the next pane.

## Forking 

The core logic is modularized in `src/lib.rs`. I am pretty confident you could easily extend this to support other multiplexers (Zellij?) or editors (Neovim?) by adding new detection logic.

## License

MIT
