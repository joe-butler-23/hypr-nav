# Bounded routing model

`cargo test` model-checks the `-1` configurations (`tests/model.rs`). Run a
deeper bound by hand from this directory:

```bash
nix shell nixpkgs#tlaplus --command tlc -workers auto -metadir "$(mktemp -d)" -config close-2.cfg HyprNav.tla
```

The runner uses `tlc` on PATH, otherwise `nix shell nixpkgs#tlaplus`; TLC
scratch state stays outside the repository.

`HyprNav.tla` checks the routing protocol, not the Rust. Each hypr-nav step is
one IPC exchange in the code (named in the spec), and the user may act between
any two: focus another window, focus another pane in any layer, open a pane
(it takes focus), or close a pane (never a session's last). Any read may fail
and any mutating request may lose its reply, with or without effect.

Fixed topology: Kitty window W1 (panes k1, k2) beside an application window W2.
k1 runs a Herdr client (h1, h2), k2 a tmux client (t1, t2), and `NvimHost`
runs Neovim (n1, n2): h1 in the plain configurations, t1 in `-tmux`.
Panes in a layer are ordered left to right. Initial states cover every
non-empty pane set and focus per layer, named or unnamed tmux, either window
focused: 1,024 starting desktops. Herdr and tmux sessions outlive clients;
Kitty panes and Neovim windows do not.

## Design rule

Decide each action from one read of the layer that performs it, and address
exactly what that read named; where a layer can decide and act in one request
(Neovim `wincmd`, Herdr `focus_direction`, Herdr's snapshot-then-close), let it.
A close never destroys more than the one pane it names. Only Hyprland's
directional move is relative, so only it is guarded by re-reading the active
window.

## Properties

| Property | Claim |
| --- | --- |
| `CloseContained` | Under any interleaving, close destroys at most one pane (and Neovim inside it) that was focused in its layer during the keypress, or a window with no pane layer. Never a Kitty window wholesale. |
| `CloseLinearizable` | Close destroys what an atomic close at one instant during the keypress would. Checked with one concurrent user action. |
| `CloseExact`, `NavigateExact` | Undisturbed and without failures, the result equals the declarative expectation at the press (`ExpectedLoss`, `ExpectedNav`). |
| `BoundedMutation` | At most one mutation per close; a move plus an entry per navigation. A lost reply stops routing. |
| `NavigationDestroysNothing` | Navigation never destroys. |
| `StepBound` + deadlock check | hypr-nav can always step until done and cannot step forever: every keypress terminates. |

## Results

TLC 2.19, 2026-10-28, six workers, no symmetry or state constraint:

| Configuration | Distinct states | Depth | Time |
| --- | ---: | ---: | ---: |
| close-1 | 204,304 | 13 | 5 s |
| close-2 | 1,930,740 | 14 | 23 s |
| left-1 | 556,486 | 18 | 9 s |
| left-2 | 5,573,302 | 19 | 70 s |
| right-1 | 393,176 | 18 | 7 s |
| right-2 | 3,871,630 | 19 | 45 s |

Neovim inside tmux, 2026-11-05, six workers:

| Configuration | Distinct states | Depth | Time |
| --- | ---: | ---: | ---: |
| close-1-tmux | 204,120 | 11 | in `cargo test` |
| close-2-tmux | 1,923,112 | 12 | 18 s |
| left-1-tmux | 557,268 | 18 | in `cargo test` |
| left-2-tmux | 5,565,958 | 19 | 49 s |
| right-1-tmux | 393,812 | 18 | in `cargo test` |
| right-2-tmux | 3,861,936 | 19 | 31 s |

All pass. This is exhaustive within this topology and these bounds, **not an
unbounded proof**.

## Found and fixed

- **Kitty window close took new panes.** Closing a single-pane Kitty window
  through Hyprland destroyed a split opened between the Kitty read and the
  close. Kitty now closes the pane it read and lets Kitty close the window.
  Reintroducing the old rule violates `CloseContained` at depth 11.
- **Mixed reads are unsafe.** Closing the Herdr pane captured during resolution,
  after a later snapshot says it is no longer the final pane, destroyed a final
  persistent pane when an agent split during the keypress
  (`CloseLinearizable`, depth 9). Herdr's target and its finality come from
  the same snapshot.
- Per-layer re-reads of the active window protected no property once every
  action names its target; they were removed.

## Limits

`CloseLinearizable` does not hold with two concurrent changes (TLC finds one at
depth 9 with `MaxEnv = 2`): no reader can snapshot Hyprland, Kitty, tmux and
Herdr atomically. For example, you press close on a one-pane Kitty window and
switch windows, while a script opens a Kitty split running tmux in the window
you left; close then removes that split's focused tmux pane. `CloseContained`
still holds and is the guarantee under arbitrary concurrency. Re-reading focus
before each layer only narrows such windows without making any property hold,
so hypr-nav does not do it.

A read that fails in the model is an IPC read (Kitty `ls`, tmux
`list-clients`, Herdr, Neovim). Local `/proc` reads are not: a process that
cannot be read hosts no inner layer (a dead pane kept open, or a pipeline whose
leader was reaped), so the outer layer acts, which is what closing such a pane
should do (`src/proc.rs`).

Not modelled: Kitty tabs and overlay groups, two-dimensional layouts and
Kitty's recency-based neighbour choice (unit-tested in `src/kitty.rs`), more
than two panes per layer, other nestings (tmux in tmux, Herdr in tmux),
multiple monitors, window identity reuse, timing, and the Rust itself.

## Code against model

The real tmux and Neovim test in `src/main.rs` routes through the same
innermost-first loop as `close` and `navigate`, records every request sent,
and asserts `BoundedMutation` and exact addressing on it: one close is one
`kill-pane` naming the pane resolution read, one move is one `select-pane`
from that pane. Full trace validation against this spec is not attempted:
Hyprland and Kitty cannot run in the build sandbox, so traces would cover
only the layers least at risk. Herdr and Kitty are checked live before
release.
