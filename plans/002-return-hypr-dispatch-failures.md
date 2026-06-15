# Plan 002: Make Hyprland dispatch failures observable to callers

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report. When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat c1a2300..HEAD -- src/lib.rs src/main.rs src/tmux.rs src/close.rs tests/integration_harness.rs`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: bug / dx
- **Planned at**: commit `c1a2300`, 2026-06-15

## Why this matters

The binaries are intended to be used from Hyprland keybinds. If a final
Hyprland dispatch fails, the current API logs only when debug is enabled and the
process can still exit successfully. In `hypr-smart-close`, the event log can
record `dispatch_closewindow` even when the socket connect or write failed.
Returning an explicit result makes keybind failures visible and gives tests a
stable way to cover failed dispatch behavior.

## Current state

- `src/lib.rs` owns the low-level Hyprland socket dispatch helper.
- `src/main.rs`, `src/tmux.rs`, and `src/close.rs` call it for final fallback or close actions.
- `tests/integration_harness.rs` already has a fake Hyprland socket server that records requests.

Relevant excerpts:

```rust
// src/lib.rs:1377-1393
pub fn hypr_dispatch(socket_path: &PathBuf, dispatcher: &str) {
    match UnixStream::connect(socket_path) {
        Ok(mut stream) => {
            let cmd = format!("dispatch {}", dispatcher);
            debug_log("lib", &format!("hypr dispatch: {}", cmd));
            if let Err(err) = stream.write_all(cmd.as_bytes()) {
                debug_log("lib", &format!("hypr dispatch write failed: {}", err));
                return;
            }
            if let Err(err) = stream.shutdown(std::net::Shutdown::Both) {
                debug_log("lib", &format!("hypr dispatch shutdown failed: {}", err));
            }
        }
        Err(err) => {
            debug_log("lib", &format!("hypr dispatch connect failed: {}", err));
        }
    }
}
```

```rust
// src/main.rs:66-70
debug_log(
    "kitty-nav",
    &format!("fallback to hypr movefocus {}", move_dir),
);
hypr_dispatch(&hypr_socket, &format!("movefocus {}", move_dir));
```

```rust
// src/close.rs:133-143
hypr_dispatch(
    &hypr_socket,
    &format!("closewindow address:{}", active.address),
);
log_close_event(
    "dispatch_closewindow",
    json!({
        "active": active_window_json(&active),
        "dispatcher": format!("closewindow address:{}", active.address),
    }),
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
- `src/lib.rs`
- `src/main.rs`
- `src/tmux.rs`
- `src/close.rs`
- `tests/integration_harness.rs`

**Out of scope**:
- Changing how Hyprland sockets are discovered
- Changing tmux, Kitty, or Nvim navigation policy
- Adding async runtimes or new dependencies

## Git workflow

- Branch: `advisor/002-return-hypr-dispatch-failures`
- Commit message style: `fix(nav): report hypr dispatch failures`
- Do not push or open a PR unless the operator instructed it.

## Steps

### Step 1: Change `hypr_dispatch` to return `bool` or `Result`

In `src/lib.rs`, update `hypr_dispatch` so callers can distinguish success from
failure. Prefer `pub fn hypr_dispatch(...) -> bool` for the smallest compatible
change:

- return `true` only after `write_all` succeeds
- return `false` when `UnixStream::connect` fails
- return `false` when `write_all` fails
- decide explicitly whether `shutdown` failure should be fatal; if you keep it
  non-fatal, leave a comment explaining that the dispatch bytes were already
  written

**Verify**: `cargo test --lib` -> exits 0.

### Step 2: Make all binary callers honor dispatch failure

Update call sites:

- `src/main.rs`: if fallback `movefocus` dispatch returns false, exit with
  status 1 after logging debug context.
- `src/tmux.rs`: if fallback `movefocus` dispatch returns false, exit with
  status 1. Keep `save_nav_state("hypr_movefocus", ...)` only after successful
  dispatch, or add an explicit failed-dispatch state if you can justify it in a
  comment.
- `src/close.rs`: only log `dispatch_closewindow` when dispatch succeeds. On
  failure, log a separate event such as `dispatch_closewindow_failed` and exit
  status 1.

Do not change successful behavior.

**Verify**: `cargo test hypr_nav_falls_back_to_hypr_when_kitty_navigation_fails --test integration_harness` -> exits 0.

### Step 3: Add failure-path integration tests

Extend `tests/integration_harness.rs` with tests that simulate a discovered
socket that cannot accept a dispatch after the active-window query. Keep the
existing fake Hypr server structure if possible.

Recommended cases:

- `hypr-nav` exits non-zero when fallback `movefocus` dispatch cannot be sent.
- `hypr-tmux-nav` exits non-zero when tmux is at edge and fallback `movefocus`
  dispatch cannot be sent.
- `hypr-smart-close` exits non-zero and logs a failure event when
  `closewindow address:<captured>` cannot be sent.

Implementation hint: add a `HyprServer::start_with_response_then_stop` or a
mode on the existing server that replies to one `activewindow` request and then
closes/stops before accepting a dispatch. Keep the helper local to the test
harness.

**Verify**: `cargo test dispatch --test integration_harness` -> exits 0 if you
name the tests with `dispatch`; otherwise run the exact new test names.

### Step 4: Run the full verification baseline

**Verify**:
- `cargo test` -> exits 0
- `cargo fmt --check` -> exits 0
- `cargo clippy --all-targets -- -D warnings` -> exits 0

## Test plan

- Add at least one integration test for each binary's failed final dispatch.
- Existing patterns to follow:
  - successful Hypr fallback: `tests/integration_harness.rs:426`
  - successful smart close dispatch logging: `tests/integration_harness.rs:490`
  - fail-closed smart close behavior: `tests/integration_harness.rs:575`

## Done criteria

- [ ] `hypr_dispatch` returns an explicit success/failure value.
- [ ] All call sites handle failure deterministically.
- [ ] `hypr-smart-close` no longer logs `dispatch_closewindow` after failed dispatch.
- [ ] New tests cover failed final dispatch behavior.
- [ ] `cargo test`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings` all exit 0.
- [ ] No files outside this plan's in-scope list are modified.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- Hyprland requires a socket shutdown pattern that makes successful dispatch
  impossible to distinguish from failure.
- Making callers return non-zero breaks a documented contract you find in the
  repo.
- The required test harness change grows beyond a small mode/helper on
  `HyprServer`.

## Maintenance notes

Reviewers should scrutinize exit statuses because these binaries run under
Hyprland keybinds. Silent success on failed action is worse than a visible
non-zero exit that can be debugged with `HYPR_NAV_DEBUG`.
