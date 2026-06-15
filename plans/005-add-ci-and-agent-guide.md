# Plan 005: Add repo-level CI and agent execution guidance

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report. When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat c1a2300..HEAD -- README.md Cargo.toml .github/workflows/rust.yml AGENTS.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: plans/001-preserve-tmux-session-names.md, plans/002-return-hypr-dispatch-failures.md, plans/003-pid-aware-kitty-detection.md recommended
- **Category**: tests / dx
- **Planned at**: commit `c1a2300`, 2026-06-15

## Why this matters

The local verification story is good: tests, format, and clippy all pass. The
repo does not have checked CI, so regressions depend on every human or agent
remembering the same commands. It also has no `AGENTS.md` or `CLAUDE.md`, so
future implementation agents do not have local scope rules for a tool that
dispatches real window-manager and tmux actions.

## Current state

- Tracked files contain no `.github/`, `AGENTS.md`, `CLAUDE.md`, or
  `CONTRIBUTING`.
- `Cargo.toml` defines a library and three binaries.
- `.gitignore` ignores only `target/`.
- Verification commands observed during recon:
  - `cargo test` passed
  - `cargo fmt --check` passed
  - `cargo clippy --all-targets -- -D warnings` passed

Relevant excerpts:

```toml
// Cargo.toml:9-23
[lib]
name = "hypr_nav_lib"
path = "src/lib.rs"

[[bin]]
name = "hypr-nav"
path = "src/main.rs"

[[bin]]
name = "hypr-tmux-nav"
path = "src/tmux.rs"

[[bin]]
name = "hypr-smart-close"
path = "src/close.rs"
```

```gitignore
// .gitignore:1
target/
```

```markdown
// README.md:28-34
git clone https://github.com/joe-butler-23/hypr-nav
cd hypr-nav
cargo build --release
sudo cp target/release/hypr-tmux-nav /usr/local/bin/
sudo cp target/release/hypr-smart-close /usr/local/bin/
sudo cp target/release/hypr-nav /usr/local/bin/
```

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Tests | `cargo test` | exit 0; all unit, integration, and doc tests pass |
| Format | `cargo fmt --check` | exit 0 |
| Lint | `cargo clippy --all-targets -- -D warnings` | exit 0 |

## Scope

**In scope**:
- `.github/workflows/rust.yml` create
- `AGENTS.md` create
- `README.md` only if you add a short contributor verification note
- `.gitignore` only if new ignored CI/dev artifacts are needed

**Out of scope**:
- Changing Rust source behavior
- Adding release automation or publishing to crates.io
- Adding heavyweight dependency audit gates that require unavailable tools

## Git workflow

- Branch: `advisor/005-add-ci-and-agent-guide`
- Commit message style: `chore(repo): add rust ci and agent guide`
- Do not push or open a PR unless the operator instructed it.

## Steps

### Step 1: Add GitHub Actions Rust CI

Create `.github/workflows/rust.yml` with a single workflow that runs on pull
requests and pushes to `main`.

Required jobs:

- checkout
- install stable Rust toolchain with `rustfmt` and `clippy`
- cache Cargo registry/git/target if using a standard action is acceptable
- run `cargo fmt --check`
- run `cargo clippy --all-targets -- -D warnings`
- run `cargo test`

Keep the workflow simple. Do not add `cargo audit` unless you also add a
documented install step for `cargo-audit` and accept the extra CI time.

**Verify**: `git diff --check` -> exits 0.

### Step 2: Add `AGENTS.md`

Create a short root `AGENTS.md` for future coding agents. Include:

- project purpose: Rust CLI for Hyprland, tmux, Kitty, and Nvim navigation
- source layout: `src/lib.rs`, `src/main.rs`, `src/tmux.rs`, `src/close.rs`,
  `tests/integration_harness.rs`
- safety rule: do not run live desktop-destructive commands manually unless the
  operator explicitly asks; prefer the fake integration harness
- verification commands: `cargo test`, `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`
- plan rule: when executing files under `plans/`, update `plans/README.md`

Keep it repository-specific and concise.

**Verify**: `test -s AGENTS.md` -> exits 0.

### Step 3: Add a README contributor note

Add a compact section such as "Development" with the three local verification
commands. Do not duplicate all of `AGENTS.md`.

**Verify**: `rg -n "cargo test|cargo fmt --check|cargo clippy" README.md AGENTS.md .github/workflows/rust.yml` -> shows the commands in the intended files.

### Step 4: Run the full verification baseline

**Verify**:
- `cargo test` -> exits 0
- `cargo fmt --check` -> exits 0
- `cargo clippy --all-targets -- -D warnings` -> exits 0

## Test plan

This is a tooling/docs plan; no Rust tests are required beyond the existing
baseline. The workflow should encode the same commands that passed locally.

## Done criteria

- [ ] `.github/workflows/rust.yml` exists and runs fmt, clippy, and tests.
- [ ] `AGENTS.md` exists with local safety and verification guidance.
- [ ] README contains a short development verification note.
- [ ] `cargo test`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings` all exit 0.
- [ ] No Rust source files are modified by this plan.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- The repo is intentionally not hosted on GitHub despite `Cargo.toml` pointing
  at a GitHub repository.
- Adding CI requires secrets or deployment credentials.
- The maintainer wants a Nix-only CI path instead of GitHub Actions.

## Maintenance notes

If later plans add `cargo-audit`, `cargo-deny`, MSRV checks, or release builds,
extend this workflow incrementally. Keep the default CI fast enough that it
stays useful on every PR.
