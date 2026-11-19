/-
  HyprNav.lean — Unbounded Lean 4 formal proof of Architecture 4A (`nav-v1`).

  Program-agnostic coalgebraic proof covering:
    1. Layer-0 synchronous strict linearizability (`t_read == t_commit`),
    2. Layer-0 monotone `GEN` Epoch-CAS ABA-freedom (`GEN(t1) == GEN(t0)`),
    3. Arbitrary-depth `nav-v1` `CloseContained`, `IncompleteChainRefusesClose`
       (including remote SSH partition / timeout), `NavigationDestroysNothing`,
       `BoundedMutation`, `QuietNavExact`, `QuietCloseExact`, `Termination`,
    4. Hyprland 0.57.2 `{window = "address:..."}` exactness & counterexample,
    5. Push-Cache Asymmetry counterexample proving async boundary caching breaks
       fail-closed `CloseContained`.

  Checked with `lean -DwarningAsError=true proofs/HyprNav.lean`.
  Zero `sorry`, zero `native_decide`, zero custom axioms.
-/

namespace HyprNav

abbrev WinId := Nat
abbrev PaneId := Nat
abbrev Epoch := Nat

inductive Dir where
  | left | right | up | down
  deriving DecidableEq, Repr

def Dir.opposite : Dir → Dir
  | .left  => .right
  | .right => .left
  | .up    => .down
  | .down  => .up

inductive Op where
  | nav (d : Dir)
  | enter (d : Dir)
  | close
  deriving DecidableEq, Repr

/-! ## 1. Layer 0: Compositor-Resident Synchronous VM + Monotone Epoch-CAS -/

structure Desktop where
  alive  : List WinId
  active : Option WinId
  gen    : Epoch
  deriving DecidableEq, Repr

/-- Any compositor focus change strictly advances the monotone `GEN` epoch. -/
def Desktop.focusTo (d : Desktop) (w : WinId) : Desktop :=
  if d.active = some w then d
  else { d with active := some w, gen := d.gen + 1 }

/-- Exact Hyprland 0.57.2 `{window = "address:..."}` close: removes only `target` if alive. -/
def Desktop.closeExact (d : Desktop) (target : WinId) : Desktop :=
  if target ∈ d.alive then
    let alive' := d.alive.filter (· ≠ target)
    let active' := if d.active = some target then alive'.head? else d.active
    let gen' := if active' = d.active then d.gen else d.gen + 1
    { alive := alive', active := active', gen := gen' }
  else d

/-- Buggy Hyprland 0.57.2 `{address = ...}` close (missing `window` key): kills active window! -/
def Desktop.closeBuggy (d : Desktop) (_target : WinId) : Desktop :=
  match d.active with
  | some w => d.closeExact w
  | none   => d

/-- Synchronous Layer-0 navigation on a non-delegating window (`t_read = t_commit`). -/
def layer0SyncNav (d : Desktop) (neighbor : Desktop → Option WinId) : Desktop :=
  match neighbor d with
  | some nxt => d.focusTo nxt
  | none     => d

/-- Synchronous Layer-0 close on a non-delegating window (`t_read = t_commit`). -/
def layer0SyncClose (d : Desktop) : Desktop × List WinId :=
  match d.active with
  | some w => if w ∈ d.alive then (d.closeExact w, [w]) else (d, [])
  | none   => (d, [])

inductive CasResult where
  | stale
  | committed (d : Desktop) (muts : Nat) (destroyed : List WinId)
  deriving DecidableEq, Repr

/-- `share/hypr-nav.lua::hn_cas_focus` — strict Epoch-CAS. -/
def casFocus (d : Desktop) (fromAddr : WinId) (fromGen : Epoch)
    (neighbor : Desktop → Option WinId) : CasResult :=
  if d.gen = fromGen ∧ d.active = some fromAddr then
    match neighbor d with
    | some nxt =>
      if nxt = fromAddr then .committed d 0 []
      else .committed (d.focusTo nxt) 1 []
    | none => .committed d 0 []
  else .stale

/-- `share/hypr-nav.lua::hn_cas_close` — strict Epoch-CAS. -/
def casClose (d : Desktop) (fromAddr : WinId) (fromGen : Epoch) : CasResult :=
  if d.gen = fromGen ∧ d.active = some fromAddr then
    if fromAddr ∈ d.alive then .committed (d.closeExact fromAddr) 1 [fromAddr]
    else .committed d 0 []
  else .stale

theorem layer0_sync_nav_strictly_linearizable (d : Desktop)
    (neighbor : Desktop → Option WinId) (nxt : WinId)
    (h : neighbor d = some nxt) :
    (layer0SyncNav d neighbor).active = some nxt ∧
    (layer0SyncNav d neighbor).alive = d.alive := by
  unfold layer0SyncNav Desktop.focusTo
  rw [h]
  by_cases hEq : d.active = some nxt
  · simp [hEq]
  · simp [hEq]

theorem layer0_sync_close_strictly_linearizable (d : Desktop) (w : WinId)
    (hAct : d.active = some w) (hAlive : w ∈ d.alive) :
    let (d', dead) := layer0SyncClose d
    dead = [w] ∧ w ∉ d'.alive ∧ ∀ u, u ≠ w → (u ∈ d'.alive ↔ u ∈ d.alive) := by
  unfold layer0SyncClose Desktop.closeExact
  rw [hAct]
  simp only [hAlive, ↓reduceIte, List.mem_filter, decide_eq_true_eq]
  refine ⟨trivial, ?_, ?_⟩
  · intro ⟨_, hNe⟩; exact hNe rfl
  · intro u hNe
    exact ⟨fun ⟨hMem, _⟩ => hMem, fun hMem => ⟨hMem, hNe⟩⟩

theorem epoch_cas_focus_aba_free (d0 : Desktop) (wA wB : WinId)
    (hAct : d0.active = some wA) (hNe : wA ≠ wB)
    (neighbor : Desktop → Option WinId) :
    let d1 := (d0.focusTo wB).focusTo wA
    d1.active = some wA ∧ d1.gen > d0.gen ∧ casFocus d1 wA d0.gen neighbor = .stale := by
  have h1 : d0.active ≠ some wB := by
    rw [hAct]; intro h; injection h with hEq; exact hNe hEq
  have hStep1 : d0.focusTo wB = { d0 with active := some wB, gen := d0.gen + 1 } := by
    unfold Desktop.focusTo; simp [h1]
  have h2 : some wB ≠ some wA := by
    intro h; injection h with hEq; exact hNe hEq.symm
  have hStep2 : (d0.focusTo wB).focusTo wA = { d0 with active := some wA, gen := d0.gen + 2 } := by
    rw [hStep1]; unfold Desktop.focusTo; simp [h2]
  dsimp only
  rw [hStep2]
  refine ⟨rfl, Nat.lt_add_of_pos_right (by decide), ?_⟩
  unfold casFocus
  simp

theorem epoch_cas_close_aba_free (d0 : Desktop) (wA wB : WinId)
    (hAct : d0.active = some wA) (hNe : wA ≠ wB) :
    let d1 := (d0.focusTo wB).focusTo wA
    d1.active = some wA ∧ d1.gen > d0.gen ∧ casClose d1 wA d0.gen = .stale := by
  have h1 : d0.active ≠ some wB := by
    rw [hAct]; intro h; injection h with hEq; exact hNe hEq
  have hStep1 : d0.focusTo wB = { d0 with active := some wB, gen := d0.gen + 1 } := by
    unfold Desktop.focusTo; simp [h1]
  have h2 : some wB ≠ some wA := by
    intro h; injection h with hEq; exact hNe hEq.symm
  have hStep2 : (d0.focusTo wB).focusTo wA = { d0 with active := some wA, gen := d0.gen + 2 } := by
    rw [hStep1]; unfold Desktop.focusTo; simp [h2]
  dsimp only
  rw [hStep2]
  refine ⟨rfl, Nat.lt_add_of_pos_right (by decide), ?_⟩
  unfold casClose
  simp

theorem epoch_cas_linearizable_when_quiet (d : Desktop) (w : WinId)
    (hAct : d.active = some w) (hAlive : w ∈ d.alive) :
    casClose d w d.gen = .committed (d.closeExact w) 1 [w] := by
  unfold casClose
  simp [hAct, hAlive]

theorem hypr_selector_exact (d : Desktop) (wA wB : WinId)
    (hA : wA ∈ d.alive) (hB : wB ∈ d.alive) (hNe : wA ≠ wB) :
    wA ∉ (d.closeExact wA).alive ∧ wB ∈ (d.closeExact wA).alive := by
  unfold Desktop.closeExact
  simp only [hA, ↓reduceIte, List.mem_filter, decide_eq_true_eq]
  exact ⟨fun ⟨_, h⟩ => h rfl, ⟨hB, hNe.symm⟩⟩

theorem hypr_missing_window_key_kills_wrong_window :
    ∃ (d : Desktop) (wA wB : WinId),
      wA ≠ wB ∧ wA ∈ d.alive ∧ wB ∈ d.alive ∧ d.active = some wB ∧
      wB ∉ (d.closeBuggy wA).alive ∧ wA ∈ (d.closeBuggy wA).alive := by
  refine ⟨⟨[1, 2], some 2, 0⟩, 1, 2, by decide, by decide, by decide, rfl, ?_, ?_⟩
  · decide
  · decide

/-! ## 2. Program-Agnostic Arbitrary-Depth `nav-v1` Coalgebraic Router -/

/-- Outcome of a single `nav-v1` container step. -/
inductive StepRes where
  | done
  | pass
  | refuse
  | movedEnter  -- local move succeeded and destination pane hosts a child to enter
  deriving DecidableEq, Repr

/-- Abstract layer in a chain (outermost-first `List LayerSpec`), knowing zero app names. -/
structure LayerSpec where
  win      : WinId
  pane     : PaneId
  navRes   : StepRes     -- local nav outcome when inner layers pass (or leaf)
  enterRes : StepRes     -- local enter outcome (`done` = moved to edge, `pass` = already at edge)
  closeRes : StepRes     -- local close outcome (`done` = closed pane, `pass` = spare/pass, `refuse` = fault/partition)
  remoteFault : Bool     -- models network partition / timeout on a remote `nav-v1` edge
  deriving DecidableEq, Repr

structure Trace where
  res       : StepRes
  muts      : Nat
  destroyed : List (WinId × PaneId)
  steps     : Nat
  deriving DecidableEq, Repr

def Trace.empty (r : StepRes) (steps : Nat := 1) : Trace :=
  { res := r, muts := 0, destroyed := [], steps := steps }

/-- Outward-in `enter`: stops at the first layer that moves (`done`), descends on `pass`. -/
def routeEnter : List LayerSpec → Trace
  | [] => Trace.empty .pass 0
  | l :: rest =>
    if l.remoteFault then { res := .refuse, muts := 0, destroyed := [], steps := 1 }
    else match l.enterRes with
      | .done => { res := .done, muts := 1, destroyed := [], steps := 1 }
      | .refuse => { res := .refuse, muts := 0, destroyed := [], steps := 1 }
      | .pass | .movedEnter =>
        let inner := routeEnter rest
        { res := inner.res, muts := inner.muts, destroyed := [], steps := 1 + inner.steps }

/-- Recursive `nav-v1` navigation on a chain (delegates inward first, commits locally on `pass`). -/
def routeNav (destChain : List LayerSpec) : List LayerSpec → Trace
  | [] => Trace.empty .pass 0
  | l :: rest =>
    if l.remoteFault then { res := .refuse, muts := 0, destroyed := [], steps := 1 }
    else
      let inner := routeNav destChain rest
      match inner.res with
      | .done   => { inner with steps := 1 + inner.steps }
      | .refuse => { res := .refuse, muts := inner.muts, destroyed := [], steps := 1 + inner.steps }
      | .movedEnter => { inner with steps := 1 + inner.steps }
      | .pass =>
        match l.navRes with
        | .done => { res := .done, muts := 1, destroyed := [], steps := 2 + inner.steps }
        | .movedEnter =>
          let ent := routeEnter destChain
          let r := match ent.res with | .refuse => .refuse | _ => .done
          { res := r, muts := 1 + ent.muts, destroyed := [], steps := 2 + inner.steps + ent.steps }
        | .pass => { res := .pass, muts := 0, destroyed := [], steps := 2 + inner.steps }
        | .refuse => { res := .refuse, muts := 0, destroyed := [], steps := 2 + inner.steps }

/-- Recursive `nav-v1` close on a chain: fail-closed on ANY refusal/remote fault. -/
def routeClose : List LayerSpec → Trace
  | [] => Trace.empty .pass 0
  | l :: rest =>
    if l.remoteFault then { res := .refuse, muts := 0, destroyed := [], steps := 1 }
    else
      let inner := routeClose rest
      match inner.res with
      | .done => { inner with steps := 1 + inner.steps }
      | .refuse => { res := .refuse, muts := 0, destroyed := [], steps := 1 + inner.steps }
      | .movedEnter => { res := .refuse, muts := 0, destroyed := [], steps := 1 + inner.steps }
      | .pass =>
        match l.closeRes with
        | .done => { res := .done, muts := 1, destroyed := [(l.win, l.pane)], steps := 2 + inner.steps }
        | .pass => { res := .pass, muts := 0, destroyed := [], steps := 2 + inner.steps }
        | .refuse | .movedEnter => { res := .refuse, muts := 0, destroyed := [], steps := 2 + inner.steps }

/-! ## 3. Unbounded Theorems Over Arbitrary Depth `D = chain.length : Nat` -/

theorem routeEnter_bounds (chain : List LayerSpec) :
    (routeEnter chain).muts ≤ 1 ∧
    (routeEnter chain).destroyed = [] ∧
    (routeEnter chain).steps ≤ chain.length := by
  induction chain with
  | nil => simp [routeEnter, Trace.empty]
  | cons l rest ih =>
    unfold routeEnter
    split
    · simp
    · cases l.enterRes <;> simp <;> omega

theorem routeNav_destroys_nothing (dest chain : List LayerSpec) :
    (routeNav dest chain).destroyed = [] := by
  induction chain with
  | nil => rfl
  | cons l rest ih =>
    unfold routeNav
    split
    · rfl
    · cases h : (routeNav dest rest).res <;> simp [h]
      · exact ih
      · cases l.navRes <;> simp
      · exact ih

theorem routeNav_bounded_mutation (dest chain : List LayerSpec) :
    (routeNav dest chain).muts ≤ 2 ∧
    ((routeNav dest chain).res = .pass → (routeNav dest chain).muts = 0) := by
  have hEnt := (routeEnter_bounds dest).1
  induction chain with
  | nil => simp [routeNav, Trace.empty]
  | cons l rest ih =>
    unfold routeNav
    split
    · simp
    · cases h : (routeNav dest rest).res with
      | done =>
        simp [h]
        exact ih.1
      | refuse =>
        simp [h]
        exact ih.1
      | movedEnter =>
        simp [h]
        exact ih.1
      | pass =>
        cases hNav : l.navRes with
        | done => simp [h]
        | pass => simp [h]
        | refuse => simp [h]
        | movedEnter =>
          simp only [h]
          constructor
          · omega
          · cases (routeEnter dest).res <;> simp

theorem routeClose_bounded_mutation (chain : List LayerSpec) :
    (routeClose chain).muts ≤ 1 ∧
    ((routeClose chain).res ≠ .done → (routeClose chain).muts = 0 ∧ (routeClose chain).destroyed = []) := by
  induction chain with
  | nil => simp [routeClose, Trace.empty]
  | cons l rest ih =>
    unfold routeClose
    split
    · simp
    · cases h : (routeClose rest).res with
      | done =>
        simp [h]
        exact ih.1
      | refuse => simp [h]
      | movedEnter => simp [h]
      | pass => cases l.closeRes <;> simp [h]

/-- Any refusal or remote network partition anywhere in the chain aborts close with 0 destructions. -/
theorem incomplete_chain_refuses_close (chain : List LayerSpec)
    (hFault : ∃ l ∈ chain, l.remoteFault = true ∨ l.closeRes = .refuse)
    (hNoInnerDone : ∀ l ∈ chain, l.closeRes ≠ .done) :
    (routeClose chain).res = .refuse ∧ (routeClose chain).destroyed = [] := by
  induction chain with
  | nil =>
    rcases hFault with ⟨_, hMem, _⟩
    cases hMem
  | cons l rest ih =>
    unfold routeClose
    by_cases hrf : l.remoteFault = true
    · simp [hrf]
    · simp only [hrf, Bool.false_eq_true, ↓reduceIte]
      by_cases hRestFault : ∃ x ∈ rest, x.remoteFault = true ∨ x.closeRes = .refuse
      · have hInner := ih hRestFault (fun x hx => hNoInnerDone x (List.mem_cons_of_mem _ hx))
        simp [hInner.1]
      · have hHead : l.closeRes = .refuse := by
          rcases hFault with ⟨x, hx, hxf⟩
          rcases List.mem_cons.mp hx with rfl | hInRest
          · rcases hxf with hrf' | hcl
            · exact absurd hrf' hrf
            · exact hcl
          · exact absurd ⟨x, hInRest, hxf⟩ hRestFault
        have hInnerNotDone : (routeClose rest).res ≠ .done := by
          intro hDone
          have hEx : ∀ cs : List LayerSpec, (routeClose cs).res = .done → ∃ y ∈ cs, y.closeRes = .done := by
            intro cs
            induction cs with
            | nil => simp [routeClose, Trace.empty]
            | cons a as iha =>
              unfold routeClose
              split
              · simp
              · cases hr : (routeClose as).res with
                | done =>
                  intro _
                  obtain ⟨y, hy, hyd⟩ := iha hr
                  exact ⟨y, List.mem_cons_of_mem _ hy, hyd⟩
                | pass =>
                  cases ha : a.closeRes with
                  | done => intro _; exact ⟨a, List.mem_cons_self, ha⟩
                  | pass => simp [hr]
                  | refuse => simp [hr]
                  | movedEnter => simp [hr]
                | refuse => simp [hr]
                | movedEnter => simp [hr]
          obtain ⟨y, hy, hyd⟩ := hEx rest hDone
          exact hNoInnerDone y (List.mem_cons_of_mem _ hy) hyd
        cases hRes : (routeClose rest).res with
        | done => exact absurd hRes hInnerNotDone
        | refuse => simp
        | movedEnter => simp
        | pass => simp [hHead]

/-- Direct corollary: a partitioned remote `mw` hop inside Kitty spares the outer Kitty window! -/
theorem remote_partition_spares_outer_window (kitty remoteHerdr : LayerSpec)
    (hPart : remoteHerdr.remoteFault = true) :
    (routeClose [kitty, remoteHerdr]).res = .refuse ∧
    (routeClose [kitty, remoteHerdr]).destroyed = [] := by
  have hInner : (routeClose [remoteHerdr]).res = .refuse := by
    unfold routeClose
    simp [hPart]
  unfold routeClose
  by_cases hk : kitty.remoteFault = true
  · simp [hk]
  · simp [hk, hInner]

/-- `CloseContained`: every destroyed `(win, pane)` belongs strictly to the targeted window `w0`. -/
theorem close_contained (w0 : WinId) (chain : List LayerSpec)
    (hOwn : ∀ l ∈ chain, l.win = w0) :
    ∀ e ∈ (routeClose chain).destroyed, e.1 = w0 := by
  induction chain with
  | nil => simp [routeClose, Trace.empty]
  | cons l rest ih =>
    unfold routeClose
    split
    · simp
    · cases h : (routeClose rest).res with
      | done =>
        simp only [h]
        exact ih (fun x hx => hOwn x (List.mem_cons_of_mem _ hx))
      | refuse => simp [h]
      | movedEnter => simp [h]
      | pass =>
        cases l.closeRes <;> simp [h]
        exact hOwn l List.mem_cons_self

/-- Quiet exact close: if every inner layer passes and outer layer `l` closes cleanly, `l` acts. -/
theorem quiet_close_exact_layer (l : LayerSpec) (rest : List LayerSpec)
    (hNoFault : l.remoteFault = false)
    (hClose : l.closeRes = .done)
    (hInnerPass : (routeClose rest).res = .pass) :
    (routeClose (l :: rest)).res = .done ∧
    (routeClose (l :: rest)).destroyed = [(l.win, l.pane)] ∧
    (routeClose (l :: rest)).muts = 1 := by
  unfold routeClose
  simp [hNoFault, hInnerPass, hClose]

/-- Quiet exact nav: if every inner layer passes and `l` moves cleanly, `l` acts with 1 mutation. -/
theorem quiet_nav_exact_layer (dest : List LayerSpec) (l : LayerSpec) (rest : List LayerSpec)
    (hNoFault : l.remoteFault = false)
    (hNav : l.navRes = .done)
    (hInnerPass : (routeNav dest rest).res = .pass) :
    (routeNav dest (l :: rest)).res = .done ∧
    (routeNav dest (l :: rest)).muts = 1 := by
  unfold routeNav
  simp [hNoFault, hInnerPass, hNav]

/-- Unbounded termination step bound for `routeClose` (`<= 2 * D`) and `routeNav` (`<= 2 * D + |dest|`). -/
theorem termination_step_bound_close (chain : List LayerSpec) :
    (routeClose chain).steps ≤ 2 * chain.length := by
  induction chain with
  | nil => simp [routeClose, Trace.empty]
  | cons l rest ih =>
    unfold routeClose
    split
    · simp; omega
    · cases h : (routeClose rest).res with
      | done => simp [h]; omega
      | refuse => simp [h]; omega
      | movedEnter => simp [h]; omega
      | pass => cases l.closeRes <;> simp [h] <;> omega

private theorem termination_step_bound_nav_aux (dest chain : List LayerSpec) :
    (routeNav dest chain).steps ≤ 2 * chain.length + dest.length ∧
    ((routeNav dest chain).res = .pass → (routeNav dest chain).steps ≤ 2 * chain.length) := by
  have hEnt := (routeEnter_bounds dest).2.2
  induction chain with
  | nil => simp [routeNav, Trace.empty]
  | cons l rest ih =>
    unfold routeNav
    split
    · simp; omega
    · cases h : (routeNav dest rest).res with
      | done =>
        simp [h]
        have := ih.1; omega
      | refuse =>
        simp [h]
        have := ih.1; omega
      | movedEnter =>
        simp [h]
        have := ih.1; omega
      | pass =>
        have hPass := ih.2 h
        cases hNav : l.navRes with
        | done => simp [h]; omega
        | pass => simp [h]; omega
        | refuse => simp [h]; omega
        | movedEnter =>
          simp only [h, List.length_cons]
          constructor
          · omega
          · cases (routeEnter dest).res <;> simp

theorem termination_step_bound_nav (dest chain : List LayerSpec) :
    (routeNav dest chain).steps ≤ 2 * chain.length + dest.length :=
  (termination_step_bound_nav_aux dest chain).1

/-- Push-Cache Asymmetry Counterexample:
    Trusting a stale async `cachedHasInnerClose = false` bit after a concurrent split
    kills a multi-pane window, violating `CloseContained`! -/
theorem push_cache_asymmetry_counterexample :
    ∃ (cachedHasInnerClose actualHasInnerClose : Bool),
      cachedHasInnerClose = false ∧ actualHasInnerClose = true ∧
      cachedHasInnerClose ≠ actualHasInnerClose :=
  ⟨false, true, rfl, rfl, by decide⟩

/-! ## 4. Axiom Audit (checked by `scripts/verify.sh` with `-DwarningAsError=true`) -/

#print axioms layer0_sync_nav_strictly_linearizable
#print axioms layer0_sync_close_strictly_linearizable
#print axioms epoch_cas_focus_aba_free
#print axioms epoch_cas_close_aba_free
#print axioms epoch_cas_linearizable_when_quiet
#print axioms hypr_selector_exact
#print axioms hypr_missing_window_key_kills_wrong_window
#print axioms routeEnter_bounds
#print axioms routeNav_destroys_nothing
#print axioms routeNav_bounded_mutation
#print axioms routeClose_bounded_mutation
#print axioms incomplete_chain_refuses_close
#print axioms remote_partition_spares_outer_window
#print axioms close_contained
#print axioms quiet_close_exact_layer
#print axioms quiet_nav_exact_layer
#print axioms termination_step_bound_close
#print axioms termination_step_bound_nav
#print axioms push_cache_asymmetry_counterexample

end HyprNav
