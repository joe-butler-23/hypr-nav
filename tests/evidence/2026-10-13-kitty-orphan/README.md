# Reparented Kitty foreground helper proof

Source control: 71f2257392fe77cddb2812aecd60494a70afc0d7.

The real failure was a tagged shared Kitty window whose selected Claude pane
reported wl-copy children adopted by user systemd. They retained the pane shell's
Linux session, but the original resolver required every foreground PID to retain
Kitty ancestry.

The integration fixture creates a real session leader and an orphaned helper,
then uses fake Kitty/Hyprland interfaces. It plants an unrelated foreground PID
first: close refuses and does not dispatch. Replacing it with the real orphan
passes on the fixed source and fails on the control source. All closes target the
fake socket; no live desktop window was closed.

- `old-fail.txt`: isolated named test on the control source; legitimate orphan
  refuses with terminal_identity_unresolved (exit 101).
- `fixed-pass.txt`: same isolated test; foreign session refuses, exact orphan
  session dispatches (exit 0).
- `full-tests.txt`: full cargo test gate.
- `clippy.txt`: cargo clippy --all-targets -- -D warnings.

The isolated command is:

```sh
cargo test --test integration_harness shared_kitty_reparented_foreground_helper_requires_exact_pane_session -- --exact --nocapture
```

Formatting also passes. These proofs establish routing and the fired session
ownership guard. They do not claim a live keypress or compositor close.
