# Plan 004: Make smart-close event logging explicit, private, and bounded

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report. When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat c1a2300..HEAD -- src/close.rs tests/integration_harness.rs README.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/002-return-hypr-dispatch-failures.md recommended
- **Category**: security / dx
- **Planned at**: commit `c1a2300`, 2026-06-15

## Why this matters

`hypr-smart-close` currently writes an event log by default under the user's
state directory. The logged JSON includes active window title, class, PID,
parent process, and action detail. That is useful for debugging a dangerous
close command, but titles can contain sensitive document names, browser page
titles, shell context, or customer data, and the log has no retention bound.
Make logging intentional and private without removing the debugging path.

## Current state

- `src/close.rs` owns smart-close logging.
- `tests/integration_harness.rs` has one explicit logging test using
  `HYPR_CLOSE_LOG`.
- README does not mention `HYPR_CLOSE_LOG`.

Relevant excerpts:

```rust
// src/close.rs:23
log_close_event("invoked", json!({ "argv": args }));
```

```rust
// src/close.rs:146-153
fn active_window_json(active: &ActiveWindowInfo) -> serde_json::Value {
    json!({
        "address": &active.address,
        "class": &active.class,
        "pid": active.pid,
        "title": &active.title,
        "focus_history_id": active.focus_history_id,
    })
}
```

```rust
// src/close.rs:180-193
fn close_log_path() -> Option<PathBuf> {
    if let Some(path) = env::var_os("HYPR_CLOSE_LOG") {
        return Some(PathBuf::from(path));
    }
    if let Some(state_home) = env::var_os("XDG_STATE_HOME") {
        return Some(PathBuf::from(state_home).join("hypr-close/events.jsonl"));
    }
    env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("hypr-close")
            .join("events.jsonl")
    })
}
```

```rust
// tests/integration_harness.rs:490-523
fn hypr_smart_close_logs_captured_address_and_dispatch() {
    let harness = Harness::new("smart-close-log");
    let close_log = harness.runtime_dir.join("close-events.jsonl");
    ...
    envs.push((
        "HYPR_CLOSE_LOG".to_string(),
        close_log.display().to_string(),
    ));
```

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Tests | `cargo test` | exit 0; all unit, integration, and doc tests pass |
| Format | `cargo fmt --check` | exit 0 |
| Lint | `cargo clippy --all-targets -- -D warnings` | exit 0 |

## Scope

**In scope**:
- `src/close.rs`
- `tests/integration_harness.rs`
- `README.md` only for a short debug/logging note if behavior changes

**Out of scope**:
- Changing close policy for Kitty, tmux, or non-terminal windows
- Changing `HYPR_NAV_DEBUG`
- Adding a logging dependency or external log rotation package

## Git workflow

- Branch: `advisor/004-smart-close-log-privacy`
- Commit message style: `fix(smart-close): make event logging explicit`
- Do not push or open a PR unless the operator instructed it.

## Steps

### Step 1: Decide and implement the logging contract

Use this default contract unless the maintainer gives different instructions:

- Do not write event logs unless `HYPR_CLOSE_LOG` is set.
- If `HYPR_CLOSE_LOG=off`, `0`, `false`, or an empty string, disable logging.
- When logging is enabled, create the file with owner-only permissions where
  possible on Unix.
- Keep active-window title in explicit logs because the user opted in.
- Do not silently fall back to `$HOME/.local/state/...` by default.

Implement this in `close_log_path` and `log_close_event`. Keep the function
surface small and local to `src/close.rs`.

**Verify**: `cargo test hypr_smart_close_logs_captured_address_and_dispatch --test integration_harness` -> exits 0 after you update the test if needed.

### Step 2: Add tests for disabled default logging

Add or update integration tests:

- default run with no `HYPR_CLOSE_LOG` does not create a close events file in
  the harness state paths
- explicit `HYPR_CLOSE_LOG=<path>` still writes `invoked`, `active_captured`,
  and final action events
- `HYPR_CLOSE_LOG=off` disables logging

The existing harness controls `HOME`, `XDG_STATE_HOME`, and `HYPR_CLOSE_LOG`
only if you add those environment entries, so make the test explicit.

**Verify**: `cargo test log --test integration_harness` -> exits 0 if test names
contain `log`; otherwise run the exact new test names.

### Step 3: Add a short README note

In README, add a compact debug section after "How It Works" or installation:

- mention `HYPR_NAV_DEBUG=1` for stderr debug traces
- mention `HYPR_CLOSE_LOG=/path/to/events.jsonl` for smart-close JSONL event logs
- state that close event logging may include window titles and is opt-in

Keep it concise; do not turn README into internal implementation docs.

**Verify**: `cargo fmt --check` -> exits 0. README is not formatted by rustfmt,
but this verifies Rust files still format.

### Step 4: Run the full verification baseline

**Verify**:
- `cargo test` -> exits 0
- `cargo fmt --check` -> exits 0
- `cargo clippy --all-targets -- -D warnings` -> exits 0

## Test plan

- Use the existing `hypr_smart_close_logs_captured_address_and_dispatch` test as
  the positive opt-in pattern.
- Add negative coverage proving default and explicit-off logging are disabled.
- Keep assertions content-based; do not assert exact timestamps or PID values.

## Done criteria

- [ ] smart-close no longer writes a default event log when `HYPR_CLOSE_LOG` is unset.
- [ ] explicit log path still works.
- [ ] explicit off values disable logging.
- [ ] README documents the opt-in debug logging contract.
- [ ] `cargo test`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings` all exit 0.
- [ ] No files outside this plan's in-scope list are modified.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- The maintainer requires default logging for an active debugging workflow.
- File permission handling requires a non-std dependency.
- Changing default logging causes existing tests to need broad unrelated rewrites.

## Maintenance notes

If future debugging needs richer event data, prefer opt-in logs over default
logs. A smart close tool touches destructive actions, so traceability matters,
but the trace should not quietly accumulate sensitive titles forever.
