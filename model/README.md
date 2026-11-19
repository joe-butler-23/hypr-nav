# hypr-nav Formal Model (`model/HyprNav.tla`)

Bounded TLA+ / TLC model of **Architecture 4A (`nav-v1`)** interleaved with concurrent user actions (including ABA focus flips `W1 -> W2 -> W1` under `MaxEnv = 2`), remote `mw` SSH network partitions (`RemoteFault`), and pane/window lifecycle changes.

## Topology & Mechanisms Modeled

- **Window `W1` (left):** Kitty (`K`, panes `k1, k2`), where `k1` hosts Herdr (`H`, panes `h1, h2` — local or remote `mw` over SSH), `h1` hosts Neovim (`N`, windows `n1, n2`), and `k2` is a plain shell pane.
- **Window `W2` (right):** Non-delegating application (Brave, Obsidian, `hf-slot`, `herdr-gk`), handled **synchronously** at Layer 0 inside `share/hypr-nav.lua` (0 forks, 0 interleavings).
- **Monotone Epoch-CAS (`gen`):** Every compositor focus transition increments `gen`. `hn_cas_focus` and `hn_cas_close` commit iff `gen = capGen /\ focus = cw`, rejecting stale and ABA-flipped commits cleanly.
- **Layer-1 Kitty RAM CAS (`snapK`):** `share/kitty_nav.py` executes plain Kitty pane actions synchronously in RAM and guards post-delegation `step_nav`/`step_close` on `cur["K"] = snapK`. Internal Kitty moves `P -> Q` return `Q`'s near-edge entry in the same RAM turn.
- **Fail-Closed Remote Partition (`RemoteFault`):** Any timeout or disconnect on Herdr/Neovim (including `mw` over SSH) aborts with zero mutations, sparing outer Kitty and Hyprland windows.

## Configurations & Invariants

All 6 configurations (`close-1`, `left-1`, `right-1`, `close-2`, `left-2`, `right-2`) are checked by `cargo test --test model`:

- `StepBound`: terminates in `<= 12` steps.
- `BoundedMutation`: `close` performs `<= 1` mutation; `nav` performs `<= 2` mutations (at most 1 outer move + 1 entry move).
- `NavigationDestroysNothing`: `left`/`right` destroy nothing.
- `IncompleteChainRefusesClose`: any `RemoteFault` or broken chain during `close` destroys nothing.
- `CloseContained`: never escapes to another window and never destroys a newly born Kitty/Herdr pane as collateral.
- `Layer0SyncExact`, `CloseExact`, `NavigateExact`: exact quiet-world match against reference semantics.

For unbounded depth (`D : Nat`) proofs and Hyprland `{window = "address:..."}` / Push-Cache Asymmetry theorems, see `proofs/HyprNav.lean`.
