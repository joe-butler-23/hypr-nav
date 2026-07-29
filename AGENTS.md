# Purpose — hypr-nav

`hypr-nav` provides one set of directional navigation and close keybindings across nested Hyprland, Kitty, Neovim, Herdr, and tmux contexts. It must act on exactly one current target, make edge transitions predictable, keep the keypress path bounded, and refuse any close whose target is not proven.

Success means navigation reaches the intended split, pane, or window without surprising fall-through; close affects only the captured target; failures are bounded and observable; and the installed behaviour matches the tested source.

## Runtime Contract

- `hypr-nav <direction>` tries the active Kitty neighbour before falling through to Hyprland.
- `hypr-tmux-nav <direction>` routes inward to outward: Neovim, Herdr, tmux, then Hyprland. Preserve that precedence and the cross-window entry-assist behaviour.
- `hypr-smart-close` routes through Herdr or an exact tmux target before closing the captured Hyprland window address. Navigation may fall through when an inner layer is unavailable; close must fail closed on incomplete identity, ambiguity, timeout, or failed inner action.
- `src/lib.rs` owns process-tree discovery, socket selection, IPC deadlines, and Hyprland dispatch. Runtime sockets and navigation state belong under `XDG_RUNTIME_DIR`, with `/run/user/<uid>` as the fallback; do not reintroduce `/tmp` runtime state.
- Lua dispatch is attempted first and legacy Hyprland syntax remains the compatibility fallback. Preserve active-window and process-ancestry checks so one Kitty instance or an inherited Herdr environment cannot redirect another window's action.

## Hyprland Configuration

A typical configuration binds the layered navigator in each direction and smart close separately:

```ini
bind = SUPER, h, exec, hypr-tmux-nav left
bind = SUPER, j, exec, hypr-tmux-nav down
bind = SUPER, k, exec, hypr-tmux-nav up
bind = SUPER, l, exec, hypr-tmux-nav right
bind = SUPER, c, exec, hypr-smart-close
```

Set `HYPR_NAV_DEBUG=1` to print routing decisions to stderr. `HYPR_CLOSE_LOG=/path/to/events.jsonl` enables bounded JSONL close logging; it is opt-in because events can contain window titles.

## Ownership and Safety

- This repository owns routing, detection, and protocol behaviour. `~/nix-config` owns packaging, the pinned source revision, and deployment; do not copy or install binaries manually on this NixOS system.
- Use `tests/integration_harness.rs` for automated behaviour proof against fake Hyprland, Kitty, Neovim, Herdr, and tmux interfaces. Do not invoke real close, tmux detach, or pane-kill paths against live work. Any live close proof requires an explicitly disposable fixture and user approval.

## Verification

For every Rust change:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

`cargo test` runs both unit tests and the fake cross-runtime integration harness. Use a focused test while iterating, then run the full gate before completion.

When a behaviour change is intended to become active, update and deploy the `hypr-nav` input through `~/nix-config`, then prove the installed binaries resolve to the new Nix store closure:

```bash
for binary in hypr-nav hypr-tmux-nav hypr-smart-close; do realpath "$(command -v "$binary")"; done
```

That proves deployment only. Also exercise each affected route through its real Hyprland keybinding in a disposable topology and confirm the visible focus or close result; do not infer live correctness from the store path or harness alone.

<!-- clai:instructions:coding:start -->
<!-- source-sha256:125fbd0ba45f15bcd8964ecd8bb5dd139da49002dbaf2db8229a6156593a274e -->
## Engineering Principles

- **Modern and idiomatic:** Use current, supported language, framework, and platform conventions. Match surrounding code when it is sound; do not reproduce obsolete patterns merely for consistency.
- **Lean end state:** Implement the intended final design directly. Remove superseded code, compatibility paths, shims, flags, dependencies, tests, comments, documentation, and configuration unless compatibility or migration is an explicit requirement. Git preserves history; current files describe only the current system.
- **Simple and explicit:** Use the least code and fewest moving parts that solve the problem. Prefer clear contracts, bounded resources, observable state, and existing project or platform primitives over speculative abstractions.
- **Efficient by design:** Avoid repeated work and unnecessary process, file, database, or network round trips. Reuse long-lived resources, batch small operations, stream large inputs, and keep concurrency, buffering, and retries bounded.
- **Evidence-led performance:** Set budgets and measure realistic workloads before optimizing. Fix algorithms, I/O, contention, and lifecycle design before micro-optimizing.
- **Risk-proportionate verification:** Define success before editing. Run the cheapest sufficient checks first and escalate according to risk. Bugs require regression coverage, and completion requires evidence at the surface the user cares about.
- **Timing and state:** Use time to model time, not to infer state. When work involves polling, debounce, readiness, timeouts, TTLs, cooldowns, throttling, retries, scheduling, animation timing, or event delivery, load the `timer-inference` skill.
<!-- clai:instructions:coding:end -->
