# Purpose — hypr-nav

`hypr-nav` gives one directional navigation and close surface across Hyprland, Kitty, Herdr (local and remote `mw` over SSH), Neovim, and any universal `nav-v1` container (`$XDG_RUNTIME_DIR/nav-<pid>.sock`). It executes synchronously inside Hyprland on non-terminal surfaces, guards async fallbacks with strict monotone Epoch-CAS, keeps every keypress bounded, and refuses any close whose target is not proven.

## Architecture (`nav-v1` Coalgebra)

Every container implements one 3-verb, 4-outcome line protocol (`nav <left|right|up|down> | enter <left|right|up|down> | close` -> `done | pass | refuse <reason> | delegate <token> <cap> | enter <cap>`):

- **Layer 0 — Compositor VM (`share/hypr-nav.lua`):** Loaded from `hyprland.lua` via `dofile`; Chezmoi `binds.lua` owns keybindings. Handles all non-Kitty/non-`nav-v1` windows (including Brave, Obsidian, Anki, `hf-slot`, `herdr-gk`) synchronously in Hyprland's Lua 5.5 VM (0 forks, 0 sockets, strictly linearizable). Detects Kitty (`kitty-<pid>`) and universal `nav-v1` (`nav-<pid>.sock`) sockets without forking (`io.open` `ENXIO=6` vs `ENOENT=2`), maintains a monotone `window.active` focus epoch `GEN`, and exposes atomic Epoch-CAS callbacks (`hn_cas_focus`, `hn_cas_close`, `hn_cli`) over `.socket.sock` `repl`.
- **Layer 1 — Kitty VM (`share/kitty_nav.py`):** In-process `no_ui=True` Kitty kitten invoked over `$XDG_RUNTIME_DIR/kitty-<pid>` by absolute Nix store path (`HYPR_NAV_KITTEN` -> `<exe>/../../share/hypr-nav/kitty_nav.py` -> manifest fallback; zero edits to `kitty.conf`). Runs synchronously in Kitty's RAM using Kitty's own `boss.os_window_map`, `tab.neighboring_group_id`, `neighbors_for_any_window`, `boss.close_windows_no_confirm`, `os.tcgetpgrp(w.child.child_fd)` (falling back to `foreground_processes` only on a dead pipeline leader), and Layer-1 `w.id` CAS (`step_nav`, `step_close`). Internal moves `P -> Q` return `Q`'s near-edge entry in the same RAM call.
- **Layers 2..3 + Universal Router (`src/main.rs`):** Single-file `#![forbid(unsafe_code)]` Rust binary (runtime deps strictly `{ rmpv, serde_json }`, zero `thread::sleep`/`try_wait`, zero background daemons or threads). Owns the program-agnostic `nav-v1` recursive router (`route_node`, `route_from_hypr`), Herdr 0.9.5 JSON-RPC shim (`pane.process_info`, `pane.focus_direction`, `pane.edges`, `session.snapshot`, `pane.close` — sparing the final pane so persistent sessions survive), Neovim 0.12.4 `rmpv` msgpack-RPC shim (skipping interleaved `rpcnotify` frames; `close` always passes), universal `$XDG_RUNTIME_DIR/nav-<pid>.sock` client, stateless remote `mw` recursion (`ssh -o BatchMode=yes -T <host> hypr-nav --herdr <session> ...` riding OpenSSH `ControlMaster`, bounded by kernel `SO_RCVTIMEO`, fail-closed on network drops), and `/run/systemd/journal/socket` error reporting.

## Hyprland Configuration & CLI Entrypoints

Chezmoi owns all binds (including `focus-jail`):

```lua
local hyprNav = dofile("/run/current-system/sw/share/hypr-nav/hypr-nav.lua")
for key, dir in pairs({h = "left", j = "down", k = "up", l = "right"}) do
    hl.bind("SUPER + " .. key, hyprNav.nav(dir))
end
hl.bind("SUPER + C", hyprNav.close)
```

- Standalone CLI: `hypr-nav <left|right|up|down|close>` (routes through `share/hypr-nav.lua`'s `hn_cli`).
- Internal subcommands: `--from-hypr ...` (from `share/hypr-nav.lua`), `--herdr <session> <nav <dir> | enter <dir> | close>` (stateless remote `nav-v1` hop over OpenSSH `ControlMaster`).
- Environment overrides: `HYPR_NAV_BIN` (Lua -> binary path), `HYPR_NAV_KITTEN` (Rust -> `kitty_nav.py` path), `HYPR_NAV_SSH` (custom SSH wrapper for testing).

## Ownership and Safety

- This repository owns routing, dialect shims, formal proofs, and protocol verification. `~/nix-config` owns packaging (`install -Dm444 share/* $out/share/hypr-nav/`), the pinned revision, and deployment; Chezmoi owns Hyprland binds. Do not install binaries manually.
- Never exercise close against live work. Live checks use isolated `/tmp` Herdr sessions, loopback `sshd`, and isolated nested Hyprland/Kitty instances with `DBUS_SESSION_BUS_ADDRESS` and `NOTIFY_SOCKET` unset, cleaned on exit.

## Verification

```bash
bash scripts/verify.sh
```

Or run checks directly:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
lean -DwarningAsError=true proofs/HyprNav.lean
```

Verification spans two formal layers and live protocol proofs:
- **Unbounded Lean 4 (`proofs/HyprNav.lean`):** 19 machine-checked theorems (`-DwarningAsError=true`, zero `sorryAx`/`native_decide`/custom axioms) covering Layer-0 strict linearizability, monotone `GEN` Epoch-CAS ABA-freedom, arbitrary-depth `nav-v1` `CloseContained`/`IncompleteChainRefusesClose`/`NavigationDestroysNothing`/`BoundedMutation`/`Termination`, remote SSH partition safety, Hyprland `{window = "address:..."}` exactness, and the Push-Cache Asymmetry counterexample.
- **Bounded TLA+ / TLC (`model/HyprNav.tla`, `tests/model.rs`):** Exhaustively checks all 6 configs (`close`/`left`/`right` × `MaxEnv ∈ {1, 2}`, including ABA focus flips and `RemoteFault`).
- **Layer B Lockstep Bisimulation (`src/bisim.rs`):** 25,000 randomized concurrent traces driving unmodified `route_node`, `route_from_hypr`, wire codecs, and `share/kitty_nav.py` helpers.
- **Live isolated proofs (`scripts/verify.sh`):** `timer-audit` + 0-`sleep`/`try_wait` audit, real headless Neovim, real Herdr 0.9.5 + loopback OpenSSH `ControlMaster` `--herdr` remote `mw` & partition refusal, and isolated nested Hyprland 0.57.2 (`share/hypr-nav.lua`) + Kitty 0.50.0 (`share/kitty_nav.py`) + universal `nav-<pid>.sock` custom app.

To deploy a pushed change, start `systemctl start --no-block overlay-updates.service` on Minworker (it bumps the pin, validates both hosts and publishes `~/nix-config`), then ask the user to run `ns` on both hosts. After deploying, confirm `realpath "$(command -v hypr-nav)"` is the new store path, then exercise each affected route through its real keybinding.

<!-- clai:instructions:coding:start -->
<!-- source-sha256:a659a7de02b20fddaff37dbba7702b2692d5d9c67aba83d813cd9d20c3254525 -->
## Engineering Principles

- **Modern and idiomatic:** Use current, supported language, framework, and platform conventions. Match surrounding code when it is sound; do not reproduce obsolete patterns merely for consistency.
- **Lean end state:** Implement the intended final design directly. Remove superseded code, compatibility paths, shims, flags, dependencies, comments, documentation, and configuration unless compatibility or migration is an explicit requirement. Git preserves history; current files describe only the current system.
- **Simple and explicit:** Use the least code and fewest moving parts that solve the problem. Prefer clear contracts, bounded resources, observable state, and existing project or platform primitives over speculative abstractions.
- **Efficient by design:** Avoid repeated work and unnecessary process, file, database, or network round trips. Reuse long-lived resources, batch small operations, stream large inputs, and keep concurrency, buffering, and retries bounded.
- **Evidence-led performance:** Set budgets and measure realistic workloads before optimizing. Fix algorithms, I/O, contention, and lifecycle design before micro-optimizing.
- **Timing and state:** Use time to model time, not to infer state. When work involves polling, debounce, readiness, timeouts, TTLs, cooldowns, throttling, retries, scheduling, animation timing, or event delivery, load the `timer-inference` skill.
- **Process identity:** Never identify a process with `pgrep -f` or `pkill -f`, and least of all over ssh: the invoking shell carries your pattern in its own command line and matches too, so a pattern kill takes the session with it and returns 255. `psfind <pattern>` lists matches while excluding its own ancestors; act on a PID you have looked at, and use `psfind -q` when a script needs them.
- **Context economy:** Prefer quiet output on noisy commands (`-q`, filtered tails) — verbose tool output occupies session context permanently.
<!-- clai:instructions:coding:end -->
