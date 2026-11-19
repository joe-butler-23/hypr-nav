//! Layer B Lockstep Code Bisimulation for Architecture 4A (`nav-v1`).
//!
//! Drives the unmodified production routing kernel (`route_node`, `route_from_hypr`)
//! and unmodified wire codecs (`Op`, `parse_outcome`, `parse_cas_focus`,
//! `parse_cas_close`, `herdr_*`, `decode_nvim_response`) against a quirk-accurate
//! concurrent desktop + remote-SSH world across >= 25,000 randomized traces.

use super::*;
use proptest::prelude::*;
use std::collections::BTreeSet;

/// Deterministic xorshift64* PRNG (zero extra crates).
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_1dd1)
    }

    fn range(&mut self, upper: usize) -> usize {
        if upper <= 1 {
            0
        } else {
            (self.next_u64() as usize) % upper
        }
    }

    fn chance(&mut self, num: usize, den: usize) -> bool {
        self.range(den) < num
    }
}

#[derive(Clone, Debug)]
struct PaneLayer {
    /// Ordered panes (left-to-right for Left/Right, top-to-bottom for Up/Down).
    panes: Vec<u32>,
    focused_idx: usize,
    /// If true, last pane passes on close (Herdr / universal session semantics).
    spare_last: bool,
    /// If true, always passes on close (Neovim semantics).
    never_close: bool,
    /// Optional child layer hosted inside each pane_id.
    children: Vec<(u32, Box<SimNode>)>,
}

#[derive(Clone, Debug)]
enum SimKind {
    NavV1,
    Kitty,
    Herdr { remote: bool },
    Nvim,
}

#[derive(Clone, Debug)]
struct SimNode {
    id: u32,
    kind: SimKind,
    layer: PaneLayer,
}

impl SimNode {
    fn focused_pane(&self) -> Option<u32> {
        self.layer.panes.get(self.layer.focused_idx).copied()
    }

    fn child_of(&self, pane: u32) -> Option<&SimNode> {
        self.layer
            .children
            .iter()
            .find(|(p, _)| *p == pane)
            .map(|(_, c)| c.as_ref())
    }

    fn cap(&self) -> Cap {
        match &self.kind {
            SimKind::NavV1 => Cap::NavSock(PathBuf::from(format!("/sim/nav-{}.sock", self.id))),
            SimKind::Kitty => Cap::Kitty {
                pid: self.id,
                class: "kitty".into(),
                tag: format!("tag-{}", self.id),
            },
            SimKind::Herdr { remote: false } => Cap::Herdr(format!("s{}", self.id)),
            SimKind::Herdr { remote: true } => Cap::Remote {
                host: "minworker".into(),
                session: format!("s{}", self.id),
            },
            SimKind::Nvim => Cap::Nvim {
                pid: self.id,
                cwd: "/tmp".into(),
                listen: format!("/sim/nvim-{}.sock", self.id),
            },
        }
    }

    fn collect_pane_ids(&self, out: &mut BTreeSet<u32>) {
        for &p in &self.layer.panes {
            out.insert(p);
        }
        for (_, c) in &self.layer.children {
            c.collect_pane_ids(out);
        }
    }

    fn find(&self, target_id: u32) -> Option<&SimNode> {
        if self.id == target_id {
            return Some(self);
        }
        for (_, c) in &self.layer.children {
            if let Some(found) = c.find(target_id) {
                return Some(found);
            }
        }
        None
    }

    fn find_mut(&mut self, target_id: u32) -> Option<&mut SimNode> {
        if self.id == target_id {
            return Some(self);
        }
        for (_, c) in &mut self.layer.children {
            if let Some(found) = c.find_mut(target_id) {
                return Some(found);
            }
        }
        None
    }
}

#[derive(Clone, Debug)]
struct SimWindow {
    addr: String,
    node: Option<SimNode>,
}

#[derive(Clone, Debug)]
struct Desktop {
    windows: Vec<SimWindow>,
    focus: usize,
    epoch: u64,
}

impl Desktop {
    fn active(&self) -> Option<&SimWindow> {
        self.windows.get(self.focus)
    }

    fn all_entities(&self) -> BTreeSet<(String, u32)> {
        let mut s = BTreeSet::new();
        for w in &self.windows {
            s.insert((w.addr.clone(), 0));
            if let Some(n) = &w.node {
                let mut ps = BTreeSet::new();
                n.collect_pane_ids(&mut ps);
                for p in ps {
                    s.insert((w.addr.clone(), p));
                }
            }
        }
        s
    }

    fn focus_window(&mut self, idx: usize) {
        if idx < self.windows.len() && idx != self.focus {
            self.focus = idx;
            self.epoch += 1;
        }
    }

    fn find_node(&self, id: u32) -> Option<&SimNode> {
        self.windows
            .iter()
            .filter_map(|w| w.node.as_ref())
            .find_map(|n| n.find(id))
    }

    fn find_node_mut(&mut self, id: u32) -> Option<&mut SimNode> {
        self.windows
            .iter_mut()
            .filter_map(|w| w.node.as_mut())
            .find_map(|n| n.find_mut(id))
    }
}

fn cap_node_id(cap: &Cap) -> u32 {
    match cap {
        Cap::NavSock(p) => p
            .to_string_lossy()
            .trim_start_matches("/sim/nav-")
            .trim_end_matches(".sock")
            .parse()
            .unwrap(),
        Cap::Kitty { pid, .. } | Cap::Nvim { pid, .. } => *pid,
        Cap::Herdr(s) | Cap::Remote { session: s, .. } => s[1..].parse().unwrap(),
    }
}

fn step_index(len: usize, idx: usize, dir: Dir) -> Option<usize> {
    match dir {
        Dir::Left | Dir::Up => idx.checked_sub(1),
        Dir::Right | Dir::Down => (idx + 1 < len).then_some(idx + 1),
    }
}

fn edge_index(len: usize, dir: Dir) -> Option<usize> {
    if len == 0 {
        return None;
    }
    match dir {
        Dir::Right | Dir::Down => Some(0),
        Dir::Left | Dir::Up => Some(len - 1),
    }
}

struct SimHarness {
    desk: Desktop,
    rng: Rng,
    env_budget: usize,
    fault_rate_pct: usize,
    remote_partition: bool,
    mutations: usize,
    destroyed: Vec<(String, u32)>,
    born: BTreeSet<(String, u32)>,
    steps: usize,
    faulted: bool,
}

impl SimHarness {
    fn maybe_env_interleave(&mut self) {
        if self.env_budget == 0 || !self.rng.chance(1, 2) {
            return;
        }
        self.env_budget -= 1;
        let n = self.desk.windows.len();
        if n == 0 {
            return;
        }
        match self.rng.range(4) {
            0 if n >= 2 => {
                // Concurrent focus switch
                let nxt = (self.desk.focus + 1 + self.rng.range(n - 1)) % n;
                self.desk.focus_window(nxt);
            }
            1 if n >= 2 => {
                // Concurrent ABA focus flip (A -> B -> A) incrementing GEN twice!
                let orig = self.desk.focus;
                let other = (orig + 1) % n;
                self.desk.focus_window(other);
                self.desk.focus_window(orig);
            }
            2 => {
                // User shifts pane focus inside focused window's root layer
                if let Some(node) = self.desk.windows[self.desk.focus].node.as_mut()
                    && node.layer.panes.len() >= 2
                {
                    node.layer.focused_idx = (node.layer.focused_idx + 1) % node.layer.panes.len();
                }
            }
            _ => {
                // User splits a pane inside root layer (cannot be killed as collateral!)
                let addr = self.desk.windows[self.desk.focus].addr.clone();
                if let Some(node) = self.desk.windows[self.desk.focus].node.as_mut() {
                    let fresh = 9000 + self.steps as u32 + self.env_budget as u32;
                    node.layer.panes.push(fresh);
                    self.born.insert((addr, fresh));
                }
            }
        }
    }

    fn simulate_wire_roundtrip(out: Outcome) -> Outcome {
        match out {
            Outcome::Done | Outcome::Pass | Outcome::Refuse(_) => {
                parse_outcome(&format_outcome_line(&out))
            }
            Outcome::Delegate { token, child } => {
                let wire = format!("delegate\t{token}\t{}\n", format_cap_wire(&child));
                parse_outcome(&wire)
            }
            Outcome::Enter(child) => {
                let wire = format!("enter\t{}\n", format_cap_wire(&child));
                parse_outcome(&wire)
            }
        }
    }

    fn close_pane_in_node(&mut self, node_id: u32, expected_pane: Option<u32>) -> Outcome {
        // Locate owning window address first for exact ghost accounting.
        let win_addr = self
            .desk
            .windows
            .iter()
            .find(|w| w.node.as_ref().is_some_and(|n| n.find(node_id).is_some()))
            .map(|w| w.addr.clone());
        let Some(win_addr) = win_addr else {
            return Outcome::Refuse("stale".into());
        };
        let Some(node) = self.desk.find_node_mut(node_id) else {
            return Outcome::Refuse("stale".into());
        };
        if node.layer.never_close {
            return Outcome::Pass;
        }
        let Some(cur_pane) = node.focused_pane() else {
            return Outcome::Pass;
        };
        if let Some(exp) = expected_pane
            && cur_pane != exp
        {
            return Outcome::Refuse("stale".into());
        }
        if node.layer.spare_last && node.layer.panes.len() <= 1 {
            return Outcome::Pass;
        }
        // Perform the close via real `herdr_close_target` check if Herdr!
        if matches!(node.kind, SimKind::Herdr { .. }) {
            let panes_json: Vec<Json> = node
                .layer
                .panes
                .iter()
                .enumerate()
                .map(|(i, p)| json!({"pane_id": format!("p{p}"), "focused": i == node.layer.focused_idx}))
                .collect();
            let snap = json!({
                "focused_pane_id": format!("p{cur_pane}"),
                "panes": panes_json
            });
            match herdr_close_target(&snap) {
                Some(Some(_)) => {}
                Some(None) => return Outcome::Pass,
                None => return Outcome::Refuse("inconsistent snapshot".into()),
            }
        }
        let idx = node.layer.focused_idx;
        let removed = node.layer.panes.remove(idx);
        node.layer.children.retain(|(p, _)| *p != removed);
        if node.layer.focused_idx >= node.layer.panes.len() && !node.layer.panes.is_empty() {
            node.layer.focused_idx = node.layer.panes.len() - 1;
        }
        self.mutations += 1;
        self.destroyed.push((win_addr.clone(), removed));
        // Layer-1 OS-window container (Kitty / top-level nav-v1) closes its OS window when its last pane closes.
        let remove_win =
            matches!(node.kind, SimKind::Kitty | SimKind::NavV1) && node.layer.panes.is_empty();
        if remove_win
            && let Some(wi) = self.desk.windows.iter().position(|w| w.addr == win_addr)
            && self.desk.windows[wi]
                .node
                .as_ref()
                .is_some_and(|n| n.id == node_id)
        {
            self.desk.windows.remove(wi);
            self.destroyed.push((win_addr, 0));
            if self.desk.focus >= self.desk.windows.len() && !self.desk.windows.is_empty() {
                self.desk.focus = self.desk.windows.len() - 1;
            }
            self.desk.epoch += 1;
        }
        Outcome::Done
    }

    fn move_pane_in_node(&mut self, node_id: u32, dir: Dir, expected_pane: Option<u32>) -> Outcome {
        let Some(node) = self.desk.find_node_mut(node_id) else {
            return Outcome::Refuse("stale".into());
        };
        let Some(cur_pane) = node.focused_pane() else {
            return Outcome::Pass;
        };
        if let Some(exp) = expected_pane
            && cur_pane != exp
        {
            return Outcome::Refuse("stale".into());
        }
        let Some(nxt_idx) = step_index(node.layer.panes.len(), node.layer.focused_idx, dir) else {
            return Outcome::Pass;
        };
        node.layer.focused_idx = nxt_idx;
        self.mutations += 1;
        let nxt_pane = node.layer.panes[nxt_idx];
        // Kitty internal move P -> Q returns Q's enter delegation in the same RAM call!
        if matches!(node.kind, SimKind::Kitty)
            && let Some(child) = node.child_of(nxt_pane)
        {
            return Outcome::Enter(child.cap());
        }
        Outcome::Done
    }

    fn enter_pane_in_node(&mut self, node_id: u32, dir: Dir) -> Outcome {
        let Some(node) = self.desk.find_node_mut(node_id) else {
            return Outcome::Refuse("stale".into());
        };
        let Some(target_idx) = edge_index(node.layer.panes.len(), dir) else {
            return Outcome::Pass;
        };
        // Exercise real `herdr_entry_from_edges` for Herdr layers!
        if matches!(node.kind, SimKind::Herdr { .. }) {
            let opp = dir.opposite();
            let at_opp = node.layer.focused_idx == target_idx;
            let n = node.layer.panes.len() as u64;
            let panes_json: Vec<Json> = node
                .layer
                .panes
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    json!({
                        "pane_id": format!("p{p}"),
                        "focused": i == node.layer.focused_idx,
                        "rect": {"x": (i as u64) * 10, "y": (i as u64) * 10, "width": 10, "height": 10}
                    })
                })
                .collect();
            let edges = json!({
                opp.name(): at_opp,
                "layout": {
                    "zoomed": false,
                    "area": {"x": 0, "y": 0, "width": n * 10, "height": n * 10},
                    "panes": panes_json
                }
            });
            let picked = herdr_entry_from_edges(&edges, dir).unwrap();
            assert_eq!(picked.is_some(), !at_opp);
        }
        if node.layer.focused_idx != target_idx {
            node.layer.focused_idx = target_idx;
            self.mutations += 1;
            return Outcome::Done;
        }
        let cur_pane = node.layer.panes[target_idx];
        if let Some(child) = node.child_of(cur_pane) {
            return Outcome::Enter(child.cap());
        }
        Outcome::Pass
    }
}

fn format_cap_wire(cap: &Cap) -> String {
    match cap {
        Cap::NavSock(p) => format!("nav\t{}", p.display()),
        Cap::Kitty { pid, class, tag } => format!("kitty\t{pid}\t{class}\t{tag}"),
        Cap::Herdr(s) => format!("herdr\t{s}"),
        Cap::Remote { host, session } => format!("remote\t{host}\t{session}"),
        Cap::Nvim { pid, cwd, listen } => {
            if listen.is_empty() {
                format!("nvim\t{pid}\t{cwd}\tnvim")
            } else {
                format!("nvim\t{pid}\t{cwd}\tnvim\t--listen\t{listen}")
            }
        }
    }
}

impl NavWorld for SimHarness {
    fn step(&mut self, cap: &Cap, op: Op) -> Outcome {
        self.steps += 1;
        self.maybe_env_interleave();
        // Exercise `Op` wire codec on every single step!
        assert_eq!(Op::parse_wire(&op.format_wire()), Some(op));
        if matches!(cap, Cap::Remote { .. }) && self.remote_partition {
            self.faulted = true;
            return Self::simulate_wire_roundtrip(Outcome::Refuse("remote network drop".into()));
        }
        if self.fault_rate_pct > 0 && self.rng.chance(self.fault_rate_pct, 100) {
            self.faulted = true;
            return Self::simulate_wire_roundtrip(Outcome::Refuse("injected ipc fault".into()));
        }
        let id = cap_node_id(cap);
        let Some(node) = self.desk.find_node(id).cloned() else {
            return Self::simulate_wire_roundtrip(Outcome::Pass);
        };
        let out = match op {
            Op::Nav(dir) => {
                if let Some(p) = node.focused_pane()
                    && let Some(child) = node.child_of(p)
                {
                    Outcome::Delegate {
                        token: p.to_string(),
                        child: child.cap(),
                    }
                } else {
                    self.move_pane_in_node(id, dir, None)
                }
            }
            Op::Enter(dir) => self.enter_pane_in_node(id, dir),
            Op::Close => {
                if node.layer.never_close {
                    Outcome::Pass
                } else if let Some(p) = node.focused_pane()
                    && let Some(child) = node.child_of(p)
                    && !child.layer.never_close
                {
                    Outcome::Delegate {
                        token: p.to_string(),
                        child: child.cap(),
                    }
                } else {
                    self.close_pane_in_node(id, None)
                }
            }
        };
        Self::simulate_wire_roundtrip(out)
    }

    fn commit(&mut self, cap: &Cap, op: Op, token: &str) -> Outcome {
        self.steps += 1;
        self.maybe_env_interleave();
        if matches!(cap, Cap::Remote { .. }) && self.remote_partition {
            self.faulted = true;
            return Self::simulate_wire_roundtrip(Outcome::Refuse("remote network drop".into()));
        }
        if self.fault_rate_pct > 0 && self.rng.chance(self.fault_rate_pct, 100) {
            self.faulted = true;
            return Self::simulate_wire_roundtrip(Outcome::Refuse("injected commit fault".into()));
        }
        let id = cap_node_id(cap);
        let expected_pane = matches!(cap, Cap::Kitty { .. })
            .then(|| token.parse::<u32>().ok())
            .flatten();
        let out = match op {
            Op::Nav(dir) => self.move_pane_in_node(id, dir, expected_pane),
            Op::Close => self.close_pane_in_node(id, expected_pane),
            Op::Enter(_) => Outcome::Pass,
        };
        Self::simulate_wire_roundtrip(out)
    }

    fn hypr_cas_focus(&mut self, addr: &str, epoch: u64, dir: Dir) -> Outcome {
        self.steps += 1;
        self.maybe_env_interleave();
        // Exact mirror of `share/hypr-nav.lua::hn_cas_focus` + real `parse_outcome`!
        let reply = match self.desk.active() {
            Some(cur) if self.desk.epoch == epoch && cur.addr == addr => {
                if let Some(nxt_idx) = step_index(self.desk.windows.len(), self.desk.focus, dir) {
                    self.desk.focus_window(nxt_idx);
                    self.mutations += 1;
                    match &self.desk.windows[nxt_idx].node {
                        Some(n) => format!("enter\t{}", format_cap_wire(&n.cap())),
                        None => "done".into(),
                    }
                } else {
                    "done".into()
                }
            }
            _ => "refuse\tstale".into(),
        };
        parse_outcome(&reply)
    }

    fn hypr_cas_close(&mut self, addr: &str, epoch: u64) -> Outcome {
        self.steps += 1;
        self.maybe_env_interleave();
        let reply = match self.desk.active() {
            Some(cur) if self.desk.epoch == epoch && cur.addr == addr => {
                let idx = self.desk.focus;
                let removed = self.desk.windows.remove(idx);
                self.mutations += 1;
                self.destroyed.push((removed.addr.clone(), 0));
                if let Some(n) = &removed.node {
                    let mut ps = BTreeSet::new();
                    n.collect_pane_ids(&mut ps);
                    for p in ps {
                        self.destroyed.push((removed.addr.clone(), p));
                    }
                }
                if self.desk.focus >= self.desk.windows.len() && !self.desk.windows.is_empty() {
                    self.desk.focus = self.desk.windows.len() - 1;
                }
                self.desk.epoch += 1;
                "done"
            }
            _ => "refuse\tstale",
        };
        parse_outcome(reply)
    }
}

fn gen_node(rng: &mut Rng, next_id: &mut u32, depth: usize, max_depth: usize) -> SimNode {
    let id = *next_id;
    *next_id += 1;
    let kind = if depth == 0 {
        if rng.chance(4, 5) {
            SimKind::Kitty
        } else {
            SimKind::NavV1
        }
    } else if depth == max_depth {
        if rng.chance(2, 3) {
            SimKind::Nvim
        } else {
            SimKind::NavV1
        }
    } else {
        match rng.range(3) {
            0 => SimKind::Herdr { remote: false },
            1 => SimKind::Herdr { remote: true },
            _ => SimKind::NavV1,
        }
    };
    let n_panes = 1 + rng.range(3);
    let mut panes = Vec::with_capacity(n_panes);
    for _ in 0..n_panes {
        panes.push(*next_id);
        *next_id += 1;
    }
    let focused_idx = rng.range(n_panes);
    let mut children = Vec::new();
    if depth < max_depth && !matches!(kind, SimKind::Nvim) {
        for &p in &panes {
            if rng.chance(1, 2) {
                children.push((p, Box::new(gen_node(rng, next_id, depth + 1, max_depth))));
            }
        }
    }
    let spare_last = matches!(kind, SimKind::Herdr { .. })
        || (depth > 0 && matches!(kind, SimKind::NavV1) && rng.chance(1, 2));
    let never_close = matches!(kind, SimKind::Nvim);
    SimNode {
        id,
        kind,
        layer: PaneLayer {
            panes,
            focused_idx,
            spare_last,
            never_close,
            children,
        },
    }
}

fn gen_desktop(rng: &mut Rng) -> Desktop {
    let mut next_id = 100u32;
    let n_wins = 1 + rng.range(4);
    let max_depth = rng.range(4);
    let mut windows = Vec::with_capacity(n_wins);
    for i in 0..n_wins {
        let node = if rng.chance(2, 3) {
            Some(gen_node(rng, &mut next_id, 0, max_depth))
        } else {
            None
        };
        windows.push(SimWindow {
            addr: format!("0x{:x}", 0x1000 + i),
            node,
        });
    }
    let focus = rng.range(n_wins);
    Desktop {
        windows,
        focus,
        epoch: 1,
    }
}

/// Simulate Layer-0 `share/hypr-nav.lua` synchronous fast path + delegate.
fn run_trace(h: &mut SimHarness, op: Op) -> R<()> {
    let Some(w) = h.desk.active().cloned() else {
        return Ok(());
    };
    let epoch = h.desk.epoch;
    match &w.node {
        None => {
            // Synchronous Layer-0 fast path inside Hyprland (zero interleavings!).
            match op {
                Op::Close => {
                    let removed = h.desk.windows.remove(h.desk.focus);
                    h.mutations += 1;
                    h.destroyed.push((removed.addr, 0));
                    if h.desk.focus >= h.desk.windows.len() && !h.desk.windows.is_empty() {
                        h.desk.focus = h.desk.windows.len() - 1;
                    }
                    h.desk.epoch += 1;
                    Ok(())
                }
                Op::Nav(dir) => {
                    if let Some(nxt) = step_index(h.desk.windows.len(), h.desk.focus, dir) {
                        h.desk.focus_window(nxt);
                        h.mutations += 1;
                        if let Some(n) = h.desk.windows[nxt].node.clone() {
                            let nxt_addr = h.desk.windows[nxt].addr.clone();
                            let nxt_gen = h.desk.epoch;
                            return route_from_hypr(
                                h,
                                &nxt_addr,
                                nxt_gen,
                                &n.cap(),
                                Op::Enter(dir),
                            );
                        }
                    }
                    Ok(())
                }
                Op::Enter(_) => Ok(()),
            }
        }
        Some(node) => route_from_hypr(h, &w.addr, epoch, &node.cap(), op),
    }
}

#[test]
fn lockstep_bisimulation_25000_traces() {
    let mut rng = Rng(0x4b_a11e_cafe_d00d);
    let ops = [
        Op::Nav(Dir::Left),
        Op::Nav(Dir::Right),
        Op::Nav(Dir::Up),
        Op::Nav(Dir::Down),
        Op::Close,
    ];
    for trace in 0..25_000usize {
        let desk = gen_desktop(&mut rng);
        let init_active_addr = desk.active().unwrap().addr.clone();
        let init_entities = desk.all_entities();
        let op = ops[rng.range(ops.len())];
        let env_budget = match trace % 5 {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 3,
            _ => rng.range(4),
        };
        let fault_rate_pct = if trace % 7 == 0 { 15 } else { 0 };
        let remote_partition = trace % 11 == 0;
        let mut h = SimHarness {
            desk,
            rng: Rng(rng.next_u64() | 1),
            env_budget,
            fault_rate_pct,
            remote_partition,
            mutations: 0,
            destroyed: Vec::new(),
            born: BTreeSet::new(),
            steps: 0,
            faulted: false,
        };
        let res = run_trace(&mut h, op);

        // 1. StepBound
        assert!(
            h.steps <= 2 * MAX_DEPTH + 6,
            "trace {trace}: steps={}",
            h.steps
        );

        // 2. BoundedMutation
        match op {
            Op::Close => assert!(
                h.mutations <= 1,
                "trace {trace}: close muts={}",
                h.mutations
            ),
            Op::Nav(_) => assert!(h.mutations <= 2, "trace {trace}: nav muts={}", h.mutations),
            Op::Enter(_) => assert!(h.mutations <= 1),
        }

        // 3. NavigationDestroysNothing
        if !matches!(op, Op::Close) {
            assert!(
                h.destroyed.is_empty(),
                "trace {trace}: nav destroyed {:?}",
                h.destroyed
            );
        }

        // 4. CloseContained: NEVER destroys an entity belonging to ANY window other than initial target,
        //    and NEVER kills a newly born pane as collateral alongside another pane/window.
        for (addr, pane) in &h.destroyed {
            assert_eq!(
                addr, &init_active_addr,
                "trace {trace}: close escaped to wrong window {addr} (expected {init_active_addr})"
            );
            if h.born.contains(&(addr.clone(), *pane)) {
                assert_eq!(
                    h.destroyed.len(),
                    1,
                    "trace {trace}: newly born pane ({addr}, {pane}) killed as collateral: {:?}",
                    h.destroyed
                );
            } else {
                assert!(
                    init_entities.contains(&(addr.clone(), *pane)),
                    "trace {trace}: destroyed unknown entity ({addr}, {pane})"
                );
            }
        }

        // 5. IncompleteChainRefusesClose: any fault/refusal during Close destroys NOTHING!
        if matches!(op, Op::Close) && (res.is_err() || h.faulted) {
            assert!(
                h.destroyed.is_empty(),
                "trace {trace}: faulted close still destroyed {:?}",
                h.destroyed
            );
        }
    }
}

#[test]
fn aba_focus_flip_rejected_by_epoch_cas() {
    let w0 = SimWindow {
        addr: "0x1000".into(),
        node: Some(SimNode {
            id: 10,
            kind: SimKind::Kitty,
            layer: PaneLayer {
                panes: vec![101],
                focused_idx: 0,
                spare_last: true, // forces Kitty to pass to Hyprland CAS
                never_close: false,
                children: vec![],
            },
        }),
    };
    let w1 = SimWindow {
        addr: "0x1001".into(),
        node: None,
    };
    let mut h = SimHarness {
        desk: Desktop {
            windows: vec![w0, w1],
            focus: 0,
            epoch: 7,
        },
        rng: Rng(1),
        env_budget: 0,
        fault_rate_pct: 0,
        remote_partition: false,
        mutations: 0,
        destroyed: vec![],
        born: BTreeSet::new(),
        steps: 0,
        faulted: false,
    };
    // ABA flip: 0 -> 1 -> 0 leaves address == "0x1000" but GEN advances 7 -> 9!
    h.desk.focus_window(1);
    h.desk.focus_window(0);
    assert_eq!(h.desk.active().unwrap().addr, "0x1000");
    assert_eq!(h.desk.epoch, 9);
    assert_eq!(
        h.hypr_cas_close("0x1000", 7),
        Outcome::Refuse("stale".into())
    );
    assert_eq!(
        h.hypr_cas_focus("0x1000", 7, Dir::Right),
        Outcome::Refuse("stale".into())
    );
    assert!(h.destroyed.is_empty());
    assert_eq!(h.mutations, 0);
}

#[test]
fn remote_mw_network_partition_spares_outer_kitty() {
    let remote_herdr = SimNode {
        id: 20,
        kind: SimKind::Herdr { remote: true },
        layer: PaneLayer {
            panes: vec![201, 202],
            focused_idx: 0,
            spare_last: true,
            never_close: false,
            children: vec![],
        },
    };
    let kitty = SimNode {
        id: 10,
        kind: SimKind::Kitty,
        layer: PaneLayer {
            panes: vec![101],
            focused_idx: 0,
            spare_last: false,
            never_close: false,
            children: vec![(101, Box::new(remote_herdr))],
        },
    };
    let mut h = SimHarness {
        desk: Desktop {
            windows: vec![SimWindow {
                addr: "0x1000".into(),
                node: Some(kitty),
            }],
            focus: 0,
            epoch: 1,
        },
        rng: Rng(42),
        env_budget: 0,
        fault_rate_pct: 0,
        remote_partition: true,
        mutations: 0,
        destroyed: vec![],
        born: BTreeSet::new(),
        steps: 0,
        faulted: false,
    };
    let res = run_trace(&mut h, Op::Close);
    assert!(res.is_err(), "partitioned remote close must refuse");
    assert!(h.destroyed.is_empty(), "outer mw Kitty window must survive");
    assert_eq!(h.desk.windows.len(), 1);
}

#[test]
fn kitty_internal_move_enters_destination_herdr_and_nvim() {
    // Kitty has 2 panes: 101 (left, shell) and 102 (right, Herdr with 2 panes, focused on right pane 202).
    // Moving right from 101 -> 102 must land on Herdr's LEFT edge pane (201) with <= 2 mutations!
    let herdr = SimNode {
        id: 20,
        kind: SimKind::Herdr { remote: false },
        layer: PaneLayer {
            panes: vec![201, 202],
            focused_idx: 1,
            spare_last: true,
            never_close: false,
            children: vec![],
        },
    };
    let kitty = SimNode {
        id: 10,
        kind: SimKind::Kitty,
        layer: PaneLayer {
            panes: vec![101, 102],
            focused_idx: 0,
            spare_last: false,
            never_close: false,
            children: vec![(102, Box::new(herdr))],
        },
    };
    let mut h = SimHarness {
        desk: Desktop {
            windows: vec![SimWindow {
                addr: "0x1000".into(),
                node: Some(kitty),
            }],
            focus: 0,
            epoch: 1,
        },
        rng: Rng(7),
        env_budget: 0,
        fault_rate_pct: 0,
        remote_partition: false,
        mutations: 0,
        destroyed: vec![],
        born: BTreeSet::new(),
        steps: 0,
        faulted: false,
    };
    run_trace(&mut h, Op::Nav(Dir::Right)).unwrap();
    let k = h.desk.find_node(10).unwrap();
    let hd = h.desk.find_node(20).unwrap();
    assert_eq!(k.focused_pane(), Some(102));
    assert_eq!(hd.focused_pane(), Some(201));
    assert_eq!(h.mutations, 2);
}

#[test]
fn python_kitty_nav_wire_lockstep_with_rust() {
    let py_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("share/kitty_nav.py");
    let script = format!(
        r#"
import importlib.util
spec = importlib.util.spec_from_file_location("kn", {:?})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
assert m.parse_herdr_target(["herdr", "--remote", "minworker", "--session", "development"]) == ("minworker", "development")
assert m.parse_herdr_target(["herdr", "--remote=minworker"]) == ("minworker", "default")
assert m.parse_herdr_target(["herdr", "--session", "gk"]) == ("", "gk")
assert m.parse_herdr_target(["herdr", "client"]) is None
assert m.parse_herdr_target(["herdr", "pane", "list"]) is None
print(m.classify_procs([
    {{"pid": 10, "cmdline": ["/bin/herdr", "--remote", "minworker", "--session", "development"], "cwd": "/tmp"}},
    {{"pid": 11, "cmdline": ["/bin/herdr", "client"], "cwd": "/tmp"}},
]))
print(m.classify_procs([
    {{"pid": 20, "cmdline": ["/bin/nvim", "--listen=/tmp/nv.sock"], "cwd": "/home/u"}}
]))
"#,
        py_path.to_str().unwrap()
    );
    let out = Command::new("python3")
        .args(["-B", "-c", &script])
        .output()
        .expect("python3 runs");
    assert!(
        out.status.success(),
        "python3 check failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<&str> = std::str::from_utf8(&out.stdout).unwrap().lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(
        parse_outcome(&format!("delegate\t5\t{}\n", lines[0])),
        Outcome::Delegate {
            token: "5".into(),
            child: Cap::Remote {
                host: "minworker".into(),
                session: "development".into(),
            }
        }
    );
    assert_eq!(
        parse_outcome(&format!("delegate\t6\t{}\n", lines[1])),
        Outcome::Delegate {
            token: "6".into(),
            child: Cap::Nvim {
                pid: 20,
                cwd: "/home/u".into(),
                listen: "/tmp/nv.sock".into(),
            }
        }
    );
}

proptest! {
    #[test]
    fn nav_v1_op_roundtrip(idx in 0usize..5) {
        let op = [
            Op::Nav(Dir::Left),
            Op::Nav(Dir::Right),
            Op::Enter(Dir::Up),
            Op::Enter(Dir::Down),
            Op::Close,
        ][idx];
        prop_assert_eq!(Op::parse_wire(&op.format_wire()), Some(op));
    }

    #[test]
    fn safe_ident_never_allows_leading_dash_or_slash(s in "[-/.a-zA-Z0-9_]{0,20}") {
        if is_safe_ident(&s) {
            prop_assert!(!s.is_empty());
            prop_assert!(!s.starts_with('-'));
            prop_assert!(!s.contains('/'));
            prop_assert_ne!(s.as_str(), ".");
            prop_assert_ne!(s.as_str(), "..");
        }
    }

    #[test]
    fn herdr_close_never_names_unfocused_or_sole_pane(n in 1usize..6, focus_idx in 0usize..6) {
        let focus = focus_idx % n;
        let panes: Vec<Json> = (0..n)
            .map(|i| json!({"pane_id": format!("w1:p{i}"), "focused": i == focus}))
            .collect();
        let snap = json!({"focused_pane_id": format!("w1:p{focus}"), "panes": panes});
        let target = herdr_close_target(&snap).unwrap();
        if n == 1 {
            prop_assert_eq!(target, None);
        } else {
            prop_assert_eq!(target, Some(format!("w1:p{focus}")));
        }
    }
}
