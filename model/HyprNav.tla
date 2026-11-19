------------------------------ MODULE HyprNav ------------------------------
(***************************************************************************)
(* Architecture 4A (`nav-v1`) bounded model of hypr-nav, interleaved with  *)
(* concurrent user activity (including ABA focus flips `W1 -> W2 -> W1`),  *)
(* remote `mw` SSH partitions, and lost IPC replies.                       *)
(*                                                                         *)
(* Topology:                                                               *)
(*   - Window W1 (left): Kitty ("K", panes k1, k2).                        *)
(*       k1 hosts Herdr ("H", panes h1, h2; local or remote `mw` SSH).     *)
(*       h1 hosts Neovim ("N", windows n1, n2).                            *)
(*       k2 is a plain shell pane (0 inner layers).                        *)
(*   - Window W2 (right): plain non-delegating application (Brave/hf-slot) *)
(*       handled synchronously at Layer 0 inside Hyprland Lua (0 forks).   *)
(*                                                                         *)
(* Key Architecture 4A mechanisms modeled directly:                        *)
(*   1. Layer-0 synchronous fast path on W2 (`t_read = t_commit`).         *)
(*   2. Layer-0 monotone focus epoch `gen` + strict Epoch-CAS on fallback  *)
(*      (`hn_cas_focus`, `hn_cas_close`) — rejects ABA focus flips!        *)
(*   3. Layer-1 Kitty in-RAM `no_ui` kitten (`kitty_nav.py`) with `w.id`   *)
(*      CAS (`step_nav`, `step_close`) + internal `P -> Q` destination     *)
(*      entry in the same RAM turn.                                        *)
(*   4. Layer-2/3 Herdr + Neovim over local socket or remote `mw` `nav-v1` *)
(*      SSH channel with fail-closed partition refusal (`RemoteFault`).    *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS Op,      \* "close", "left" or "right"
          MaxEnv   \* concurrent user actions allowed while hypr-nav runs

NONE == "none"
Dir == IF Op = "left" THEN -1 ELSE 1

Pool == [K |-> <<"k1", "k2">>, H |-> <<"h1", "h2">>, N |-> <<"n1", "n2">>]
Layers == {"K", "H", "N"}
PaneSet(l) == {Pool[l][1], Pool[l][2]}
Pos(l, p) == IF Pool[l][1] = p THEN 1 ELSE 2
Hosted(p) == CASE p = "k1" -> "H" [] p = "h1" -> "N" [] OTHER -> NONE
Windows == <<"W1", "W2">>

VARIABLES
    focus, alive, panes, cur, born, gen,            \* desktop + monotone epoch
    env,                                            \* user actions so far
    pc, cw, capGen, snapK, phase, destK,            \* hypr-nav process state
    faulted, muts, destroyed, s0, steps             \* outcome ghosts & step bound

desk == <<focus, alive, panes, cur, born, gen>>
proc == <<pc, cw, capGen, snapK, phase, destK>>
ghost == <<faulted, muts, destroyed, s0, steps>>
vars == <<desk, env, proc, ghost>>

World == [focus |-> focus, alive |-> alive, panes |-> panes, cur |-> cur]

SetWorld(s) ==
    /\ focus' = s.focus /\ alive' = s.alive /\ panes' = s.panes /\ cur' = s.cur
    /\ gen' = IF s.focus = focus THEN gen ELSE gen + 1

-----------------------------------------------------------------------------
(* Geometry & Layer Chain *)

Neighbor(l, p, d, ps) ==
    IF p \notin ps[l] THEN NONE
    ELSE LET i == Pos(l, p) + d
         IN IF i \in {1, 2} /\ Pool[l][i] \in ps[l] THEN Pool[l][i] ELSE NONE

EdgePane(l, ps) ==
    LET first == IF Dir = 1 THEN Pool[l][1] ELSE Pool[l][2]
    IN IF first \in ps[l] THEN first ELSE CHOOSE p \in ps[l] : TRUE

WinNeighbor(w, al) ==
    IF w = NONE THEN NONE
    ELSE LET i == (IF w = "W1" THEN 1 ELSE 2) + Dir
         IN IF i \in {1, 2} /\ Windows[i] \in al THEN Windows[i] ELSE NONE

Inner(l, s) ==
    LET p == s.cur[l]
    IN IF p # NONE /\ Hosted(p) # NONE /\ s.panes[Hosted(p)] # {}
       THEN Hosted(p) ELSE NONE

Chain(w, s) ==
    IF w # "W1" \/ "W1" \notin s.alive THEN <<>>
    ELSE LET a == Inner("K", s)
         IN IF a = NONE THEN <<"K">>
            ELSE LET b == Inner(a, s)
                 IN IF b = NONE THEN <<"K", a>> ELSE <<"K", a, b>>

-----------------------------------------------------------------------------
(* Destruction Semantics *)

Gone(s, p) == {p} \cup (IF Hosted(p) = "N" THEN s.panes["N"] ELSE {})

Remove(s, G) ==
    LET ps == [l \in Layers |-> s.panes[l] \ G]
        c == [l \in Layers |->
                IF s.cur[l] \in ps[l] THEN s.cur[l]
                ELSE IF ps[l] = {} THEN NONE ELSE CHOOSE q \in ps[l] : TRUE]
        al == IF ps["K"] = {} THEN s.alive \ {"W1"} ELSE s.alive
        fo == IF s.focus \in al THEN s.focus
              ELSE IF al = {} THEN NONE ELSE CHOOSE w \in al : TRUE
    IN [s EXCEPT !.panes = ps, !.cur = c, !.alive = al, !.focus = fo]

WindowGone(s, w) == IF w = "W1" THEN {"W1"} \cup s.panes["K"] ELSE {w}

KillWindow(s, w) ==
    IF w = "W1" THEN Remove(s, s.panes["K"])
    ELSE LET al == s.alive \ {w}
         IN [s EXCEPT !.alive = al,
                      !.focus = IF "W1" \in al THEN "W1" ELSE NONE]

-----------------------------------------------------------------------------
(* Quiet-World Exact Reference Semantics *)

CloseAct(l, s) ==
    CASE l = "N" -> "pass"
      [] l = "H" -> IF Cardinality(s.panes["H"]) > 1 THEN "kill" ELSE "pass"
      [] l = "K" -> "kill"
      [] OTHER -> "pass"

Max(S) == CHOOSE i \in S : \A j \in S : j <= i

CloseTarget(s) ==
    LET c == Chain(s.focus, s)
        acting == {i \in 1..Len(c) : CloseAct(c[i], s) # "pass"}
    IN IF acting = {} THEN [act |-> "window", pane |-> NONE]
       ELSE LET l == c[Max(acting)]
            IN [act |-> "kill", pane |-> s.cur[l]]

ExpectedLoss(s) ==
    IF s.focus = NONE THEN {}
    ELSE LET t == CloseTarget(s)
         IN IF t.act = "window" THEN WindowGone(s, s.focus)
            ELSE Gone(s, t.pane) \cup
                 (IF t.pane \in s.panes["K"] /\ s.panes["K"] = {t.pane} THEN {"W1"} ELSE {})

NavMoves(l, s) == Neighbor(l, s.cur[l], Dir, s.panes) # NONE
EntryMoves(l, s) == s.panes[l] # {} /\ s.cur[l] # EdgePane(l, s.panes)

ExpectedNav(s) ==
    IF s.focus = NONE THEN s
    ELSE LET c == Chain(s.focus, s)
             acting == {i \in 1..Len(c) : NavMoves(c[i], s)}
         IN IF acting # {} THEN
                LET l == c[Max(acting)]
                    p2 == Neighbor(l, s.cur[l], Dir, s.panes)
                    s1 == [s EXCEPT !.cur[l] = p2]
                IN \* Kitty internal P -> Q enters Q's Herdr/Nvim near edge!
                   IF l = "K" /\ Inner("K", s1) = "H" THEN
                       IF EntryMoves("H", s1) THEN
                           [s1 EXCEPT !.cur["H"] = EdgePane("H", s1.panes)]
                       ELSE IF Inner("H", s1) = "N" /\ EntryMoves("N", s1) THEN
                           [s1 EXCEPT !.cur["N"] = EdgePane("N", s1.panes)]
                       ELSE s1
                   ELSE s1
            ELSE LET w2 == WinNeighbor(s.focus, s.alive)
                 IN IF w2 = NONE THEN s
                    ELSE LET s1 == [s EXCEPT !.focus = w2]
                             c2 == Chain(w2, s1)
                             ent == {i \in 1..Len(c2) : EntryMoves(c2[i], s1)}
                         IN IF ent = {} THEN s1
                            ELSE LET l == c2[CHOOSE i \in ent : \A j \in ent : i <= j]
                                 IN [s1 EXCEPT !.cur[l] = EdgePane(l, s1.panes)]

-----------------------------------------------------------------------------
(* Initial State *)

Init ==
    /\ alive \in SUBSET {"W1", "W2"}
    /\ focus \in IF alive = {} THEN {NONE} ELSE alive
    /\ panes \in [Layers -> SUBSET {"k1","k2","h1","h2","n1","n2"}]
    /\ \A l \in Layers : panes[l] \subseteq PaneSet(l)
    /\ ("W1" \in alive) <=> (panes["K"] # {})
    /\ cur \in [Layers -> {"k1","k2","h1","h2","n1","n2", NONE}]
    /\ \A l \in Layers :
           IF panes[l] = {} THEN cur[l] = NONE ELSE cur[l] \in panes[l]
    /\ born = {}
    /\ gen = 0
    /\ env = 0
    /\ pc = "Start" /\ cw = NONE /\ capGen = 0 /\ snapK = NONE
    /\ phase = "none" /\ destK = FALSE
    /\ faulted = FALSE /\ muts = 0 /\ destroyed = {}
    /\ s0 = World /\ steps = 0

-----------------------------------------------------------------------------
(* Layer-0 Compositor Lua (`share/hypr-nav.lua`) — Synchronous Entry *)

StartSync ==
    /\ pc = "Start"
    /\ steps' = steps + 1
    /\ IF focus = NONE THEN
           /\ pc' = "Done" /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>
       ELSE IF focus = "W2" THEN
           \* Non-Kitty window (~90% of desktop): 100% SYNCHRONOUS in Hyprland Lua (0 forks, 0 interleavings!)
           IF Op = "close" THEN
               /\ SetWorld(KillWindow(World, "W2"))
               /\ muts' = muts + 1
               /\ destroyed' = destroyed \cup WindowGone(World, "W2")
               /\ pc' = "Done"
               /\ UNCHANGED <<born, env, cw, capGen, snapK, phase, destK, faulted, s0>>
           ELSE
               LET w2 == WinNeighbor("W2", alive)
               IN IF w2 = NONE THEN
                      /\ pc' = "Done"
                      /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>
                  ELSE
                      /\ SetWorld([World EXCEPT !.focus = w2])
                      /\ muts' = muts + 1
                      /\ cw' = w2 /\ capGen' = gen + 1
                      /\ pc' = IF w2 = "W1" THEN "KittyEnter" ELSE "Done"
                      /\ UNCHANGED <<born, env, snapK, phase, destK, faulted, destroyed, s0>>
       ELSE
           \* Kitty window W1: capture (cw, capGen) and delegate asynchronously to `hypr-nav --from-hypr`
           /\ cw' = "W1" /\ capGen' = gen
           /\ pc' = IF Op = "close" THEN "KittyClose" ELSE "KittyNav"
           /\ UNCHANGED <<desk, env, snapK, phase, destK, faulted, muts, destroyed, s0>>

-----------------------------------------------------------------------------
(* Layer-1 Kitty In-RAM `no_ui` Kitten (`share/kitty_nav.py`) *)

KittyNavStep ==
    /\ pc = "KittyNav"
    /\ steps' = steps + 1
    /\ IF "W1" \notin alive \/ panes["K"] = {} THEN
           /\ pc' = "HyprCasFocus"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>
       ELSE IF Inner("K", World) = "H" THEN
           /\ snapK' = cur["K"]
           /\ pc' = "HerdrNav"
           /\ UNCHANGED <<desk, env, cw, capGen, phase, destK, faulted, muts, destroyed, s0>>
       ELSE
           \* Plain Kitty pane (k2): single synchronous RAM turn!
           LET p2 == Neighbor("K", cur["K"], Dir, panes)
           IN IF p2 = NONE THEN
                  /\ pc' = "HyprCasFocus"
                  /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>
              ELSE
                  /\ SetWorld([World EXCEPT !.cur["K"] = p2])
                  /\ muts' = muts + 1
                  /\ pc' = IF Hosted(p2) = "H" /\ panes["H"] # {} THEN "HerdrEnter" ELSE "Done"
                  /\ UNCHANGED <<born, env, cw, capGen, snapK, phase, destK, faulted, destroyed, s0>>

KittyStepNav ==
    /\ pc = "KittyStepNav"
    /\ steps' = steps + 1
    /\ IF "W1" \notin alive \/ panes["K"] = {} \/ cur["K"] # snapK THEN
           \* Layer-1 `w.id` CAS detects stale pane focus -> refuse stale!
           /\ pc' = "Done"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>
       ELSE
           LET p2 == Neighbor("K", cur["K"], Dir, panes)
           IN IF p2 = NONE THEN
                  /\ pc' = "HyprCasFocus"
                  /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>
              ELSE
                  /\ SetWorld([World EXCEPT !.cur["K"] = p2])
                  /\ muts' = muts + 1
                  /\ pc' = IF Hosted(p2) = "H" /\ panes["H"] # {} THEN "HerdrEnter" ELSE "Done"
                  /\ UNCHANGED <<born, env, cw, capGen, snapK, phase, destK, faulted, destroyed, s0>>

KittyEnterStep ==
    /\ pc = "KittyEnter"
    /\ steps' = steps + 1
    /\ IF "W1" \notin alive \/ panes["K"] = {} THEN
           /\ pc' = "Done"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>
       ELSE LET ep == EdgePane("K", panes)
            IN IF cur["K"] # ep THEN
                   /\ SetWorld([World EXCEPT !.cur["K"] = ep])
                   /\ muts' = muts + 1
                   /\ pc' = "Done"
                   /\ UNCHANGED <<born, env, cw, capGen, snapK, phase, destK, faulted, destroyed, s0>>
               ELSE
                   /\ pc' = IF Inner("K", World) = "H" THEN "HerdrEnter" ELSE "Done"
                   /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>

KittyCloseStep ==
    /\ pc = "KittyClose"
    /\ steps' = steps + 1
    /\ IF "W1" \notin alive \/ panes["K"] = {} THEN
           /\ pc' = "HyprCasClose"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>
       ELSE IF Inner("K", World) = "H" THEN
           /\ snapK' = cur["K"]
           /\ pc' = "HerdrClose"
           /\ UNCHANGED <<desk, env, cw, capGen, phase, destK, faulted, muts, destroyed, s0>>
       ELSE
           LET target == cur["K"]
               loss == Gone(World, target) \cup (IF panes["K"] = {target} THEN {"W1"} ELSE {})
           IN /\ SetWorld(Remove(World, Gone(World, target)))
              /\ muts' = muts + 1
              /\ destroyed' = destroyed \cup loss
              /\ pc' = "Done"
              /\ UNCHANGED <<born, env, cw, capGen, snapK, phase, destK, faulted, s0>>

KittyStepClose ==
    /\ pc = "KittyStepClose"
    /\ steps' = steps + 1
    /\ IF "W1" \notin alive \/ panes["K"] = {} \/ cur["K"] # snapK THEN
           \* Layer-1 `w.id` CAS detects stale pane focus -> close NOTHING!
           /\ pc' = "Done"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>
       ELSE
           LET target == cur["K"]
               loss == Gone(World, target) \cup (IF panes["K"] = {target} THEN {"W1"} ELSE {})
           IN /\ SetWorld(Remove(World, Gone(World, target)))
              /\ muts' = muts + 1
              /\ destroyed' = destroyed \cup loss
              /\ pc' = "Done"
              /\ UNCHANGED <<born, env, cw, capGen, snapK, phase, destK, faulted, s0>>

-----------------------------------------------------------------------------
(* Layer-2/3 Herdr (local or remote `mw` SSH) + Neovim *)

HerdrNavStep ==
    /\ pc = "HerdrNav"
    /\ steps' = steps + 1
    /\ IF panes["H"] = {} THEN
           /\ faulted' = TRUE /\ pc' = "Done"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, muts, destroyed, s0>>
       ELSE IF Inner("H", World) = "N" THEN
           /\ pc' = "NvimNav"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>
       ELSE
           LET p2 == Neighbor("H", cur["H"], Dir, panes)
           IN IF p2 # NONE THEN
                  /\ SetWorld([World EXCEPT !.cur["H"] = p2])
                  /\ muts' = muts + 1 /\ pc' = "Done"
                  /\ UNCHANGED <<born, env, cw, capGen, snapK, phase, destK, faulted, destroyed, s0>>
              ELSE
                  /\ pc' = "KittyStepNav"
                  /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>

NvimNavStep ==
    /\ pc = "NvimNav"
    /\ steps' = steps + 1
    /\ IF panes["N"] = {} THEN
           /\ faulted' = TRUE /\ pc' = "Done"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, muts, destroyed, s0>>
       ELSE LET p2 == Neighbor("N", cur["N"], Dir, panes)
            IN IF p2 # NONE THEN
                   /\ SetWorld([World EXCEPT !.cur["N"] = p2])
                   /\ muts' = muts + 1 /\ pc' = "Done"
                   /\ UNCHANGED <<born, env, cw, capGen, snapK, phase, destK, faulted, destroyed, s0>>
               ELSE
                   /\ pc' = "HerdrCommitNav"
                   /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>

HerdrCommitNav ==
    /\ pc = "HerdrCommitNav"
    /\ steps' = steps + 1
    /\ IF panes["H"] = {} THEN
           /\ faulted' = TRUE /\ pc' = "Done"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, muts, destroyed, s0>>
       ELSE LET p2 == Neighbor("H", cur["H"], Dir, panes)
            IN IF p2 # NONE THEN
                   /\ SetWorld([World EXCEPT !.cur["H"] = p2])
                   /\ muts' = muts + 1 /\ pc' = "Done"
                   /\ UNCHANGED <<born, env, cw, capGen, snapK, phase, destK, faulted, destroyed, s0>>
               ELSE
                   /\ pc' = "KittyStepNav"
                   /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>

HerdrEnterStep ==
    /\ pc = "HerdrEnter"
    /\ steps' = steps + 1
    /\ IF panes["H"] = {} THEN
           /\ faulted' = TRUE /\ pc' = "Done"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, muts, destroyed, s0>>
       ELSE LET ep == EdgePane("H", panes)
            IN IF cur["H"] # ep THEN
                   /\ SetWorld([World EXCEPT !.cur["H"] = ep])
                   /\ muts' = muts + 1 /\ pc' = "Done"
                   /\ UNCHANGED <<born, env, cw, capGen, snapK, phase, destK, faulted, destroyed, s0>>
               ELSE
                   /\ pc' = IF Inner("H", World) = "N" THEN "NvimEnter" ELSE "Done"
                   /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>

NvimEnterStep ==
    /\ pc = "NvimEnter"
    /\ steps' = steps + 1
    /\ IF panes["N"] = {} THEN
           /\ faulted' = TRUE /\ pc' = "Done"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, muts, destroyed, s0>>
       ELSE LET ep == EdgePane("N", panes)
            IN IF cur["N"] # ep THEN
                   /\ SetWorld([World EXCEPT !.cur["N"] = ep])
                   /\ muts' = muts + 1 /\ pc' = "Done"
                   /\ UNCHANGED <<born, env, cw, capGen, snapK, phase, destK, faulted, destroyed, s0>>
               ELSE
                   /\ pc' = "Done"
                   /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>

HerdrCloseStep ==
    /\ pc = "HerdrClose"
    /\ steps' = steps + 1
    /\ IF panes["H"] = {} THEN
           /\ faulted' = TRUE /\ pc' = "Done"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, muts, destroyed, s0>>
       ELSE IF Cardinality(panes["H"]) > 1 THEN
           LET target == cur["H"]
           IN /\ SetWorld(Remove(World, Gone(World, target)))
              /\ muts' = muts + 1
              /\ destroyed' = destroyed \cup Gone(World, target)
              /\ pc' = "Done"
              /\ UNCHANGED <<born, env, cw, capGen, snapK, phase, destK, faulted, s0>>
       ELSE
           \* Final Herdr pane spares the persistent session -> passes to Kitty `step_close`!
           /\ pc' = "KittyStepClose"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>

\* Remote `mw` SSH partition / timeout during any Herdr/Nvim step fails closed (0 mutations)!
RemoteFault ==
    /\ pc \in {"HerdrNav", "HerdrCommitNav", "HerdrEnter", "HerdrClose", "NvimNav", "NvimEnter"}
    /\ env < MaxEnv
    /\ env' = env + 1
    /\ faulted' = TRUE
    /\ pc' = "Done"
    /\ steps' = steps + 1
    /\ UNCHANGED <<desk, cw, capGen, snapK, phase, destK, muts, destroyed, s0>>

-----------------------------------------------------------------------------
(* Layer-0 Epoch-CAS Return (`hn_cas_focus`, `hn_cas_close`) *)

HyprCasFocus ==
    /\ pc = "HyprCasFocus"
    /\ steps' = steps + 1
    /\ IF gen = capGen /\ focus = cw THEN
           LET w2 == WinNeighbor(cw, alive)
           IN IF w2 = NONE THEN
                  /\ pc' = "Done"
                  /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>
              ELSE
                  /\ SetWorld([World EXCEPT !.focus = w2])
                  /\ muts' = muts + 1
                  /\ pc' = IF w2 = "W1" THEN "KittyEnter" ELSE "Done"
                  /\ UNCHANGED <<born, env, cw, capGen, snapK, phase, destK, faulted, destroyed, s0>>
       ELSE
           \* Epoch mismatch (incl. ABA flip!) -> refuse stale, 0 mutations!
           /\ pc' = "Done"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>

HyprCasClose ==
    /\ pc = "HyprCasClose"
    /\ steps' = steps + 1
    /\ IF gen = capGen /\ focus = cw /\ cw \in alive THEN
           /\ SetWorld(KillWindow(World, cw))
           /\ muts' = muts + 1
           /\ destroyed' = destroyed \cup WindowGone(World, cw)
           /\ pc' = "Done"
           /\ UNCHANGED <<born, env, cw, capGen, snapK, phase, destK, faulted, s0>>
       ELSE
           \* Epoch mismatch (incl. ABA flip!) -> refuse stale, 0 destructions!
           /\ pc' = "Done"
           /\ UNCHANGED <<desk, env, cw, capGen, snapK, phase, destK, faulted, muts, destroyed, s0>>

-----------------------------------------------------------------------------
(* Concurrent User Environment (including ABA Focus Flips!) *)

EnvFocusWin ==
    /\ env < MaxEnv /\ pc # "Done" /\ pc # "Start"
    /\ \E w \in alive : w # focus /\ SetWorld([World EXCEPT !.focus = w])
    /\ env' = env + 1
    /\ UNCHANGED <<born, proc, ghost>>

EnvFocusPane ==
    /\ env < MaxEnv /\ pc # "Done" /\ pc # "Start"
    /\ \E l \in Layers : \E p \in panes[l] :
           p # cur[l] /\ SetWorld([World EXCEPT !.cur[l] = p])
    /\ env' = env + 1
    /\ UNCHANGED <<born, proc, ghost>>

EnvOpenPane ==
    /\ env < MaxEnv /\ pc # "Done" /\ pc # "Start"
    /\ \E l \in Layers : \E p \in PaneSet(l) \ panes[l] :
           /\ (l = "K" => "W1" \in alive)
           /\ SetWorld([World EXCEPT !.panes[l] = panes[l] \cup {p},
                                     !.cur[l] = IF cur[l] = NONE THEN p ELSE cur[l]])
           /\ born' = born \cup {p}
    /\ env' = env + 1
    /\ UNCHANGED <<proc, ghost>>

EnvClosePane ==
    /\ env < MaxEnv /\ pc # "Done" /\ pc # "Start"
    /\ \E l \in Layers : \E p \in panes[l] :
           SetWorld(Remove(World, Gone(World, p)))
    /\ env' = env + 1
    /\ UNCHANGED <<born, proc, ghost>>

EnvCloseWin ==
    /\ env < MaxEnv /\ pc # "Done" /\ pc # "Start"
    /\ \E w \in alive : SetWorld(KillWindow(World, w))
    /\ env' = env + 1
    /\ UNCHANGED <<born, proc, ghost>>

Next ==
    \/ StartSync
    \/ KittyNavStep \/ KittyStepNav \/ KittyEnterStep \/ KittyCloseStep \/ KittyStepClose
    \/ HerdrNavStep \/ NvimNavStep \/ HerdrCommitNav \/ HerdrEnterStep \/ NvimEnterStep \/ HerdrCloseStep
    \/ HyprCasFocus \/ HyprCasClose
    \/ RemoteFault
    \/ EnvFocusWin \/ EnvFocusPane \/ EnvOpenPane \/ EnvClosePane \/ EnvCloseWin
    \/ (pc = "Done" /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Formal Safety & Exactness Invariants *)

StepBound == steps <= 12

BoundedMutation ==
    /\ (Op = "close" => muts <= 1)
    /\ (Op # "close" => muts <= 2)

NavigationDestroysNothing ==
    Op # "close" => destroyed = {}

IncompleteChainRefusesClose ==
    (Op = "close" /\ faulted) => destroyed = {}

\* No entity from any window other than initial `s0.focus` is ever destroyed,
\* and no newly born pane is ever killed as collateral alongside another target.
CloseContained ==
    /\ (Op = "close" /\ s0.focus = "W2") => destroyed \subseteq {"W2"}
    /\ (Op = "close" /\ s0.focus = "W1") => ("W2" \notin destroyed)
    /\ (Op = "close" /\ (destroyed \cap born \cap (PaneSet("K") \cup PaneSet("H")) # {})) =>
           Cardinality(destroyed \ (PaneSet("N") \cup {"W1"})) = 1

\* Strict Epoch-CAS prevents ANY Layer-0 mutation after ANY focus change (incl. ABA!).
Layer0SyncExact ==
    (pc = "Done" /\ env = 0 /\ ~faulted /\ s0.focus = "W2" /\ Op = "close") =>
        (destroyed = {"W2"} /\ "W2" \notin alive)

CloseExact ==
    (pc = "Done" /\ env = 0 /\ ~faulted /\ Op = "close") =>
        destroyed = ExpectedLoss(s0)

NavigateExact ==
    (pc = "Done" /\ env = 0 /\ ~faulted /\ Op # "close") =>
        World = ExpectedNav(s0)

=============================================================================
