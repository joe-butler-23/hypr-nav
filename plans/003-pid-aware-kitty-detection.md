# Plan 003: Use PID-aware Kitty detection in the `hypr-nav` binary

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report. When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat c1a2300..HEAD -- src/main.rs src/lib.rs tests/integration_harness.rs`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `c1a2300`, 2026-06-15

## Why this matters

The library has been hardened to recognize Kitty by process metadata as well as
window class, which supports custom Kitty classes and wrappers. The `hypr-nav`
binary still uses a local helper that only checks whether the active window
class contains `kitty`. That means `hypr-nav` can skip Kitty neighbor navigation
and fall back to Hyprland movement for exactly the custom-class cases that the
shared library was built to handle.

## Current state

- `src/main.rs` is the standalone Kitty neighbor navigation binary.
- `src/lib.rs` contains shared PID-aware Kitty detection.
- Git history shows custom Kitty detection was recently important:
  `32ec22b fix(detect): handle custom kitty window classes by pid` and
  `df224f7 fix(detect): fallback to process tree for custom kitty class`.

Relevant excerpts:

```rust
// src/main.rs:73-84
fn is_kitty_active(socket_path: &std::path::PathBuf) -> bool {
    if let Some((class, _pid)) = get_active_window_info(socket_path) {
        let class = class.to_ascii_lowercase();
        let is_kitty = class.contains("kitty");
        debug_log(
            "kitty-nav",
            &format!("activewindow class={} kitty={}", class, is_kitty),
        );
        return is_kitty;
    }
    false
}
```

```rust
// src/lib.rs:215-217
pub fn is_kitty_window(class: &str, pid: u32) -> bool {
    class.to_ascii_lowercase().contains("kitty") || process_matches_terminal_name(pid, "kitty")
}
```

Existing integration coverage only checks class `kitty`:

```rust
// tests/integration_harness.rs:397-410
#[test]
fn hypr_nav_prefers_kitty_before_hypr_fallback() {
    let harness = Harness::new("kitty-precedence");
    let hypr = HyprServer::start(
        &harness.runtime_dir,
        &harness.hypr_sig,
        "kitty",
        std::process::id(),
    );
```

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Tests | `cargo test` | exit 0; all unit, integration, and doc tests pass |
| Format | `cargo fmt --check` | exit 0 |
| Lint | `cargo clippy --all-targets -- -D warnings` | exit 0 |

## Scope

**In scope**:
- `src/main.rs`
- `tests/integration_harness.rs`
- `src/lib.rs` only if a small helper must become public/testable

**Out of scope**:
- Changing `hypr-tmux-nav` runtime detection
- Changing Kitty socket URI normalization
- Adding support for non-Kitty terminals

## Git workflow

- Branch: `advisor/003-pid-aware-kitty-detection`
- Commit message style: `fix(nav): use pid-aware kitty detection`
- Do not push or open a PR unless the operator instructed it.

## Steps

### Step 1: Replace the local class-only helper

In `src/main.rs`, update `is_kitty_active` so it keeps the PID from
`get_active_window_info` and calls `is_kitty_window(&class, pid)`.

Target shape:

```rust
if let Some((class, pid)) = get_active_window_info(socket_path) {
    let is_kitty = is_kitty_window(&class, pid);
    debug_log(
        "kitty-nav",
        &format!("activewindow class={} pid={} kitty={}", class, pid, is_kitty),
    );
    return is_kitty;
}
```

Keep the helper local unless tests force a cleaner extraction.

**Verify**: `cargo test hypr_nav_prefers_kitty_before_hypr_fallback --test integration_harness` -> exits 0.

### Step 2: Add regression coverage for custom Kitty classes

Add an integration test in `tests/integration_harness.rs` proving that
`hypr-nav` attempts Kitty neighbor navigation when Hyprland reports a non-Kitty
class but the PID resolves to a process named `kitty`.

Implementation hint:

- Add a helper that spawns a long-running fake process whose argv0 or executable
  basename is `kitty`. A symlink named `kitty` to `/bin/sleep`, or a copied test
  script named `kitty` that sleeps, can work if `/proc/<pid>/comm`,
  `/proc/<pid>/cmdline`, or `/proc/<pid>/exe` presents `kitty`.
- Use `HyprServer::start(..., "custom-terminal", fake_kitty_pid)`.
- Set `TEST_KITTY_FOCUS_OK=1` and keep `KITTY_LISTEN_ON` from `Harness::envs`.
- Assert the command log contains
  `kitty @ --to unix:/tmp/fake-kitty focus-window --match neighbor:left`.
- Assert no Hyprland `dispatch movefocus` request was sent.

If process-name spoofing is unreliable in the harness, STOP and report rather
than adding a weak test that only repeats class-based detection.

**Verify**: `cargo test custom --test integration_harness` -> exits 0 if the new
test name contains `custom`; otherwise run the exact new test name.

### Step 3: Run the full verification baseline

**Verify**:
- `cargo test` -> exits 0
- `cargo fmt --check` -> exits 0
- `cargo clippy --all-targets -- -D warnings` -> exits 0

## Test plan

- Add one integration regression test for custom Kitty class plus PID-based
  recognition.
- Existing pattern to follow: `hypr_nav_prefers_kitty_before_hypr_fallback` in
  `tests/integration_harness.rs`.

## Done criteria

- [ ] `src/main.rs` uses shared `is_kitty_window` with both class and PID.
- [ ] A regression test fails against the old class-only helper and passes with the fix.
- [ ] Existing Kitty fallback behavior remains unchanged.
- [ ] `cargo test`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings` all exit 0.
- [ ] No files outside this plan's in-scope list are modified.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- The live `src/main.rs` already uses `is_kitty_window`.
- The test harness cannot reliably create a PID that `process_matches_terminal_name` recognizes as Kitty.
- The change appears to require redesigning process detection in `src/lib.rs`.

## Maintenance notes

Keep active-window classification rules in shared library functions where
possible. The recent git history shows this area regresses easily when each
binary has its own local detection shortcut.
