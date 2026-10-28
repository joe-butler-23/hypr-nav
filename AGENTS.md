# Purpose — hypr-nav

`hypr-nav` gives one set of directional navigation and close keybindings across nested Hyprland, Kitty, tmux, Herdr and Neovim. It must act on exactly one current target, make edge transitions predictable, keep the keypress path bounded, and refuse any close whose target is not proven.

## Runtime Contract

- One binary: `hypr-nav <left|right|up|down>` navigates and `hypr-nav close` closes. Neither has an alternative entry point.
- A window resolves into a chain of layers by following foreground processes inward. Kitty names its focused pane over `$XDG_RUNTIME_DIR/kitty-<pid>`; any other window with exactly one terminal session uses that session. Each pane's terminal foreground process group leader is classified by name (`nvim`, `tmux`, `herdr`), and that layer names its own focused pane's foreground process. Cost follows the nesting present, never the number of supported layers: adding a layer is one `Layer` variant and one name.
- Actions run innermost first. A layer returns `Pass` only when it has nothing to do (an edge, a final pane); then the next outer layer acts, ending at Hyprland. Any unacknowledged or failed action stops routing.
- After an outer move, entry lands on the near edge of the destination, outermost layer first, and stops at the first layer that moves.
- Decide each action from one read of the layer that performs it and address exactly what that read named; where a layer decides and acts in one request (Neovim `wincmd`, Herdr `focus_direction`, Herdr snapshot-then-close), let it. A close destroys at most the one pane it names. Only Hyprland's relative move is guarded by re-reading the active window. Close refuses an incomplete chain.
- `model/HyprNav.tla` is the protocol's contract (`model/README.md`): contained and exact close, exact navigation, bounded mutation and termination, checked by TLC. Change the model with any routing change.
- Every socket and subprocess shares one 1.5 s keypress budget. All IPC except tmux is in-process over sockets: Hyprland, Kitty's control protocol, Herdr's JSON lines, Neovim msgpack-RPC.
- Only Lua Hyprland is supported (`dispatch hl.dsp...`).

## Hyprland Configuration

```lua
for key, dir in pairs({h = "left", j = "down", k = "up", l = "right"}) do
    hl.bind("SUPER + " .. key, hl.dsp.exec_cmd("hypr-nav " .. dir))
end
hl.bind("SUPER + C", hl.dsp.exec_cmd("hypr-nav close"))
```

Set `HYPR_NAV_DEBUG=1` to print the resolved chain and the acting layer to stderr. Failures always reach stderr and the journal: `journalctl --user -t hypr-nav`.

## Layer identity

- Kitty: a shared Kitty process can own several OS windows; Hyprland `xdgTag` must equal Kitty `wm_name` (launch with `--os-window-tag`). Untagged Kitty is used only when its process reports one OS window. Neighbours resolve to explicit pane IDs, preferring the most recently active group as Kitty does. Close closes the pane it read; Kitty closes the tab and OS window with their last pane, so a split opened meanwhile survives.
- tmux: the client's `-S`/`-L` flags and `TMUX_TMPDIR` select the server; one `list-clients` row gives pane, edges, pane pid and close policy. Named sessions and a final pane detach the client; other panes are killed.
- Herdr: explicit `--session` beats inherited `HERDR_*` variables; remote clients and one-shot commands are not layers. Success is the absence of an error (0.9.5 acknowledges `pane.focus` with `pane_info`). Close removes the focused pane after checking the snapshot is consistent; the final pane passes outward so the session survives.
- Neovim: the server socket is `--listen` or `nvim.<pid>.0` of the process or its embedded server child. Commands run through `execute()` so they work in every mode.

## Ownership and Safety

- This repository owns routing, detection and protocol behaviour. `~/nix-config` owns packaging, the pinned revision and deployment; Chezmoi owns the binds; `hf close-guard` (hypr-focus) runs `hypr-nav close`. Do not install binaries manually.
- Never exercise close against live work. Live checks use disposable tmux servers (`-L`) and Herdr sessions, removed afterwards.

## Verification

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Tests drive real protocols, not fakes: a headless Neovim, a real tmux server with a pty client and Neovim inside it, and TLC over the routing model (`tests/model.rs`, about 20 s). Pure decisions (Kitty neighbour choice, Herdr entry and close, tmux rows) use captured response shapes. Herdr and Kitty are not in the build sandbox: after changing either layer, check it against a disposable Herdr session and the live Kitty before release.

After deploying through `~/nix-config`, confirm `realpath "$(command -v hypr-nav)"` is the new store path, then exercise each affected route through its real keybinding.

<!-- clai:instructions:coding:start -->
<!-- source-sha256:1a131f46fafd56730f2f1706abcc2b7ff7ebdcb45e3956551ba62a37bf184580 -->
## Engineering Principles

- **Modern and idiomatic:** Use current, supported language, framework, and platform conventions. Match surrounding code when it is sound; do not reproduce obsolete patterns merely for consistency.
- **Lean end state:** Implement the intended final design directly. Remove superseded code, compatibility paths, shims, flags, dependencies, tests, comments, documentation, and configuration unless compatibility or migration is an explicit requirement. Git preserves history; current files describe only the current system.
- **Simple and explicit:** Use the least code and fewest moving parts that solve the problem. Prefer clear contracts, bounded resources, observable state, and existing project or platform primitives over speculative abstractions.
- **Efficient by design:** Avoid repeated work and unnecessary process, file, database, or network round trips. Reuse long-lived resources, batch small operations, stream large inputs, and keep concurrency, buffering, and retries bounded.
- **Evidence-led performance:** Set budgets and measure realistic workloads before optimizing. Fix algorithms, I/O, contention, and lifecycle design before micro-optimizing.
- **Verification:** Use existing checks and direct observation when they establish the outcome. A new test should earn its maintenance cost by catching a meaningful failure that existing coverage misses.
- **Timing and state:** Use time to model time, not to infer state. When work involves polling, debounce, readiness, timeouts, TTLs, cooldowns, throttling, retries, scheduling, animation timing, or event delivery, load the `timer-inference` skill.
- **Process identity:** Never identify a process with `pgrep -f` or `pkill -f`, and least of all over ssh: the invoking shell carries your pattern in its own command line and matches too, so a pattern kill takes the session with it and returns 255. `psfind <pattern>` lists matches while excluding its own ancestors; act on a PID you have looked at, and use `psfind -q` when a script needs them.
- **Context economy:** Prefer quiet output on noisy commands (`--reporter=dot`, `-q`, filtered tails) — verbose tool output occupies session context permanently.

## Heavy jobs on Minworker

Minworker shares 12 GB of RAM across agents. Run direct foreground builds, clippy, Cargo tests and other heavy verification through `agent-heavy <command>`. It queues work under the same host lock as native build and release runners, with lower CPU and I/O priority; it does not depend on a PTT checkout. Invoke runners that already own admission (`scripts/ship`, `release`, `overlay-updates.service`) directly. Use the repository's normal warm build directory, retain Cargo's managed default concurrency, and run each required heavy check once. Formatting, evaluation, Git and searches do not need the heavy-work queue.
<!-- clai:instructions:coding:end -->
