# Plan 001: Preserve tmux session names with spaces during client lookup

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report. When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat c1a2300..HEAD -- src/lib.rs tests/integration_harness.rs`
> If either in-scope file changed since this plan was written, compare the
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

`hypr-smart-close` promises to detach named tmux sessions safely. The code
already recognizes that tmux session names can contain spaces in
`get_tmux_session_info`, but `find_tmux_session` still asks tmux for
`session tty` separated by a plain space and then splits on whitespace. A named
session such as `work session` can therefore fail session lookup or be
truncated to `work`, causing close/navigation behavior to fail closed in cases
that should be safe.

## Current state

- `src/lib.rs` contains all tmux parsing and command helpers.
- `tests/integration_harness.rs` contains command-level integration tests with
  fake `tmux`, `kitty`, and `nvim` executables.

Relevant excerpts:

```rust
// src/lib.rs:1055-1057
let output = tmux_command(socket_path)
    .args(["list-clients", "-F", "#{client_session} #{client_tty}"])
```

```rust
// src/lib.rs:1088-1094
fn parse_tmux_client_session(clients: &str, tty: &str) -> Option<String> {
    for line in clients.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let session = parts[0];
            let client_tty = parts[1];
```

The same file already uses a safer tab-delimited pattern for names with spaces:

```rust
// src/lib.rs:1321-1330
pub fn get_tmux_session_info(session: &str, socket_path: Option<&str>) -> Option<TmuxSessionInfo> {
    // Use a stable delimiter because session names may contain spaces.
    // Format: #{session_name}\t#{window_panes}\t#{session_windows}
    let output = tmux_command(socket_path)
        .args([
            "display-message",
            "-t",
            session,
            "-p",
            "#{session_name}\t#{window_panes}\t#{session_windows}",
        ])
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
- `tests/integration_harness.rs` only if you add command-level regression coverage there

**Out of scope**:
- Changing tmux close policy in `src/close.rs`
- Reworking process discovery or Kitty/Nvim detection
- Changing public binary names or README installation commands

## Git workflow

- Branch: `advisor/001-preserve-tmux-session-names`
- Commit message style: use the repo's conventional style, for example
  `fix(tmux): preserve spaced session names in client lookup`
- Do not push or open a PR unless the operator instructed it.

## Steps

### Step 1: Make `find_tmux_session` emit a stable delimiter

In `src/lib.rs`, change the tmux format used by `find_tmux_session` from a
space-delimited string to a tab-delimited string. Keep the output order as
session first, tty second, but use `\t` between fields.

Target shape:

```rust
.args(["list-clients", "-F", "#{client_session}\t#{client_tty}"])
```

**Verify**: `cargo test parse_tmux_client_session --lib` -> exits 0. It may still
only run the existing tests at this point.

### Step 2: Replace whitespace parsing with tab-aware parsing

Update `parse_tmux_client_session` so each line is parsed with one tab
delimiter. The session name should be the text before the first tab, and the
client tty should be the text after it. Trim both sides. Return the full session
name unchanged except for surrounding whitespace.

Do not use `split_whitespace` for this parser after the change.

**Verify**: `cargo test parse_tmux_client_session --lib` -> exits 0.

### Step 3: Add regression tests for spaced session names

In the `#[cfg(test)]` module in `src/lib.rs`, add tests next to the existing
`parse_tmux_client_session_*` tests:

- a row like `work session\t/dev/pts/9\n` returns `Some("work session")`
- a row with the right session but different tty returns `None`
- a malformed row without a tab returns `None`

If you choose to update the fake tmux script in `tests/integration_harness.rs`,
make it emit the same tab-delimited format for the `#{client_session}` path, but
do not broaden the integration harness beyond this finding.

**Verify**: `cargo test parse_tmux_client_session --lib` -> exits 0 and includes
the new tests.

### Step 4: Run the full verification baseline

Run the full local checks.

**Verify**:
- `cargo test` -> exits 0; all tests pass
- `cargo fmt --check` -> exits 0
- `cargo clippy --all-targets -- -D warnings` -> exits 0

## Test plan

- Add unit coverage in `src/lib.rs` for spaced session names, mismatched tty,
  and malformed rows.
- Existing pattern to follow: `parse_tmux_session_info_output_handles_named_session_with_spaces`
  at `src/lib.rs:1663`.
- Full verification command: `cargo test`.

## Done criteria

- [ ] `find_tmux_session` requests tab-delimited `#{client_session}` and `#{client_tty}`.
- [ ] `parse_tmux_client_session` no longer uses `split_whitespace`.
- [ ] New regression tests prove session names containing spaces are preserved.
- [ ] `cargo test`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings` all exit 0.
- [ ] No files outside this plan's in-scope list are modified.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- The live parser already uses a stable delimiter and the excerpt above is stale.
- You discover tmux cannot emit `\t` in the `-F` format on the supported tmux version.
- Fixing this requires changing tmux action policy in `src/close.rs`.

## Maintenance notes

Any future parser that includes tmux names should use a stable delimiter, not
whitespace. TTYs and pane IDs are whitespace-free today, but session and window
names are user-controlled strings.
