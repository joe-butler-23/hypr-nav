# hypr-nav Agent Guide

This is a Rust CLI project for context-aware navigation and close behavior
across Hyprland, tmux, Kitty, and Nvim.

## Layout

- `src/lib.rs` - shared detection, tmux, Kitty, Nvim, and Hyprland helpers.
- `src/main.rs` - `hypr-nav`, Kitty-aware navigation with Hyprland fallback.
- `src/tmux.rs` - `hypr-tmux-nav`, layered Nvim/tmux/Hyprland navigation.
- `src/close.rs` - `hypr-smart-close`, context-aware close behavior.
- `tests/integration_harness.rs` - fake Hyprland, tmux, Kitty, and Nvim harness.
- `plans/` - advisor-generated implementation plans and status index.

## Safety

- Do not manually run live desktop-destructive commands such as real
  `hyprctl dispatch closewindow`, `tmux kill-pane`, or close keybind probes
  unless the operator explicitly asks.
- Prefer `cargo test` and the fake integration harness for behavior changes.
- Keep changes surgical; this repo is small enough that broad refactors are
  usually unnecessary.

## Verification

Run these before commit:

```bash
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

If you execute a file under `plans/`, update the matching row in
`plans/README.md`.
