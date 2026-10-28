------------------------------ MODULE HyprNav ------------------------------
(***************************************************************************)
(* Bounded model of hypr-nav's routing protocol, interleaved with user     *)
(* activity and lost IPC replies.  Each process step stands for one IPC    *)
(* exchange in the Rust code (named in comments); user actions may land    *)
(* between any two of them.                                                *)
(*                                                                         *)
(* Fixed topology.  Window W1 (left) is Kitty with panes k1,k2.  k1 runs a *)
(* Herdr client (session panes h1,h2), k2 a tmux client (panes t1,t2), and *)
(* h1 runs Neovim (windows n1,n2).  W2 (right) is a plain application.     *)
(* Panes in a layer are ordered left to right.  Herdr and tmux sessions    *)
(* outlive their clients; Kitty panes and Neovim windows do not.           *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS Op,     \* "close", "left" or "right"
          MaxEnv  \* user actions allowed while hypr-nav runs

NONE == "none"
Dir == IF Op = "left" THEN -1 ELSE 1

Pool == [K |-> <<"k1", "k2">>, H |-> <<"h1", "h2">>,
         T |-> <<"t1", "t2">>, N |-> <<"n1", "n2">>]
Layers == {"K", "H", "T", "N"}
PaneSet(l) == {Pool[l][1], Pool[l][2]}
Pos(l, p) == IF Pool[l][1] = p THEN 1 ELSE 2
LayerOf(p) == CHOOSE l \in Layers : p \in PaneSet(l)
Hosted(p) == CASE p = "k1" -> "H" [] p = "k2" -> "T" [] p = "h1" -> "N"
                  [] OTHER -> NONE
Windows == <<"W1", "W2">>

VARIABLES
    focus, alive, panes, cur, named, attached, born,  \* the desktop
    env,                                              \* user actions so far
    pc, cw, phase, res, nxt, cap, k, complete, snap,  \* hypr-nav
    lost, degraded, muts, destroyed, cands, seen, s0, \* outcome ghosts
    steps                                             \* hypr-nav steps taken

desk == <<focus, alive, panes, cur, named, attached, born>>
proc == <<pc, cw, phase, res, nxt, cap, k, complete, snap>>
ghost == <<lost, degraded, muts, destroyed, s0>>
vars == <<desk, env, proc, ghost, cands, seen, steps>>

World == [focus |-> focus, alive |-> alive, panes |-> panes, cur |-> cur,
          named |-> named, attached |-> attached]

SetWorld(s) ==
    /\ focus' = s.focus /\ alive' = s.alive /\ panes' = s.panes
    /\ cur' = s.cur /\ named' = s.named /\ attached' = s.attached

-----------------------------------------------------------------------------
(* Geometry *)

Neighbor(l, p, d, ps) ==
    IF p \notin ps[l] THEN NONE
    ELSE LET i == Pos(l, p) + d
         IN IF i \in {1, 2} /\ Pool[l][i] \in ps[l] THEN Pool[l][i] ELSE NONE

\* The pane on the edge entered when moving in Dir.
EdgePane(l, ps) ==
    LET first == IF Dir = 1 THEN Pool[l][1] ELSE Pool[l][2]
    IN IF first \in ps[l] THEN first ELSE CHOOSE p \in ps[l] : TRUE

WinNeighbor(w, al) ==
    IF w = NONE THEN NONE
    ELSE LET i == (IF w = "W1" THEN 1 ELSE 2) + Dir
         IN IF i \in {1, 2} /\ Windows[i] \in al THEN Windows[i] ELSE NONE

-----------------------------------------------------------------------------
(* Layer chain: follow each focused pane's foreground process inward. *)

Inner(l, s) ==
    LET p == s.cur[l]
    IN IF p # NONE /\ Hosted(p) # NONE /\ (Hosted(p) = "T" => s.attached)
          /\ s.panes[Hosted(p)] # {}
       THEN Hosted(p) ELSE NONE

\* Outermost first.
Chain(w, s) ==
    IF w # "W1" \/ "W1" \notin s.alive THEN <<>>
    ELSE LET a == Inner("K", s)
         IN IF a = NONE THEN <<"K">>
            ELSE LET b == Inner(a, s)
                 IN IF b = NONE THEN <<"K", a>> ELSE <<"K", a, b>>

-----------------------------------------------------------------------------
(* Destruction *)

\* Closing a pane kills it and any Neovim inside; servers survive clients.
Gone(s, p) == {p} \cup (IF Hosted(p) = "N" THEN s.panes["N"] ELSE {})

Remove(s, G) ==
    LET ps == [l \in Layers |-> s.panes[l] \ G]
        c == [l \in Layers |->
                IF s.cur[l] \in ps[l] THEN s.cur[l]
                ELSE IF ps[l] = {} THEN NONE ELSE CHOOSE q \in ps[l] : TRUE]
        al == IF ps["K"] = {} THEN s.alive \ {"W1"} ELSE s.alive
        fo == IF s.focus \in al THEN s.focus
              ELSE IF al = {} THEN NONE ELSE CHOOSE w \in al : TRUE
    IN [s EXCEPT !.panes = ps, !.cur = c, !.alive = al, !.focus = fo,
                 !.attached = s.attached /\ "k2" \notin G]

WindowGone(s, w) == IF w = "W1" THEN {"W1"} \cup s.panes["K"] ELSE {w}

KillWindow(s, w) ==
    IF w = "W1" THEN Remove(s, s.panes["K"])
    ELSE LET al == s.alive \ {w}
         IN [s EXCEPT !.alive = al,
                      !.focus = IF "W1" \in al THEN "W1" ELSE NONE]

-----------------------------------------------------------------------------
(* What a keypress should do, decided from the desktop at the press. *)

CloseAct(l, s) ==
    CASE l = "N" -> "pass"
      [] l = "H" -> IF Cardinality(s.panes["H"]) > 1 THEN "kill" ELSE "pass"
      [] l = "T" -> IF s.named \/ Cardinality(s.panes["T"]) = 1
                    THEN "detach" ELSE "kill"
      [] l = "K" -> "kill"    \* Kitty closes the OS window with its last pane
      [] OTHER -> "pass"

Max(S) == CHOOSE i \in S : \A j \in S : j <= i
Min(S) == CHOOSE i \in S : \A j \in S : i <= j

\* Innermost layer that acts, else the window.
CloseTarget(s) ==
    LET c == Chain(s.focus, s)
        acting == {i \in 1..Len(c) : CloseAct(c[i], s) # "pass"}
    IN IF acting = {} THEN [act |-> "window", pane |-> NONE]
       ELSE LET l == c[Max(acting)]
            IN [act |-> CloseAct(l, s), pane |-> s.cur[l]]

ExpectedLoss(s) ==
    LET t == CloseTarget(s)
    IN CASE t.act = "window" -> WindowGone(s, s.focus)
         [] t.act = "detach" -> {}
         [] OTHER -> Gone(s, t.pane)

\* Neovim windows opened later inside the target pane die with it.
Permitted(s) ==
    LET t == CloseTarget(s)
    IN ExpectedLoss(s)
       \cup (IF t.act = "kill" /\ Hosted(t.pane) = "N" THEN PaneSet("N") ELSE {})

EntryMoves(l, s) ==
    IF l = "N" THEN Cardinality(s.panes["N"]) > 1
    ELSE s.cur[l] # EdgePane(l, s.panes)

\* Innermost layer with a neighbour moves; else Hyprland moves and the
\* outermost destination layer off its entered edge lands on it.
ExpectedNav(s) ==
    LET c == Chain(s.focus, s)
        movable == {i \in 1..Len(c) : Neighbor(c[i], s.cur[c[i]], Dir, s.panes) # NONE}
    IN IF movable # {}
       THEN LET l == c[Max(movable)]
            IN [s EXCEPT !.cur[l] = Neighbor(l, s.cur[l], Dir, s.panes)]
       ELSE LET w == WinNeighbor(s.focus, s.alive)
            IN IF w = NONE THEN s
               ELSE LET s1 == [s EXCEPT !.focus = w]
                        d == Chain(w, s1)
                        ent == {i \in 1..Len(d) : EntryMoves(d[i], s1)}
                    IN IF ent = {} THEN s1
                       ELSE LET l == d[Min(ent)]
                            IN [s1 EXCEPT !.cur[l] = EdgePane(l, s1.panes)]

-----------------------------------------------------------------------------
NoCap == [pane |-> NONE, nb |-> NONE, keep |-> FALSE,
          edge |-> FALSE, e |-> NONE]

NonEmpty(l) == (SUBSET PaneSet(l)) \ {{}}

Init ==
    /\ panes \in [K : NonEmpty("K"), H : NonEmpty("H"),
                  T : NonEmpty("T"), N : NonEmpty("N")]
    /\ cur \in [K : panes["K"], H : panes["H"], T : panes["T"], N : panes["N"]]
    /\ named \in BOOLEAN
    /\ attached = TRUE
    /\ alive = {"W1", "W2"}
    /\ focus \in alive
    /\ born = UNION {panes[l] : l \in Layers}
    /\ env = 0
    /\ pc = "capture" /\ cw = NONE /\ phase = "source" /\ res = <<>>
    /\ nxt = NONE /\ cap = [l \in Layers |-> NoCap] /\ k = 0
    /\ complete = TRUE /\ snap = NONE
    /\ lost = FALSE /\ degraded = FALSE /\ muts = 0 /\ destroyed = {}
    /\ cands = {} /\ seen = {} /\ s0 = World /\ steps = 0

-----------------------------------------------------------------------------
(* The user, concurrently *)

Env ==
    /\ env < MaxEnv /\ pc # "done"
    /\ env' = env + 1
    /\ UNCHANGED <<proc, ghost>>
    /\ \/ \E w \in alive \ {focus} :
            focus' = w /\ UNCHANGED <<alive, panes, cur, named, attached, born>>
       \/ \E l \in Layers : \E p \in panes[l] \ {cur[l]} :
            /\ cur' = [cur EXCEPT ![l] = p]
            /\ UNCHANGED <<focus, alive, panes, named, attached, born>>
       \/ \E l \in Layers : \E p \in PaneSet(l) \ born :
            /\ l = "K" => "W1" \in alive
            /\ l = "N" => panes["N"] # {}
            /\ panes' = [panes EXCEPT ![l] = @ \cup {p}]
            /\ cur' = [cur EXCEPT ![l] = p]
            /\ born' = born \cup {p}
            /\ UNCHANGED <<focus, alive, named, attached>>
       \/ \E l \in Layers : \E p \in panes[l] :
            /\ l \in {"H", "T"} => Cardinality(panes[l]) > 1
            /\ SetWorld(Remove(World, Gone(World, p)))
            /\ UNCHANGED born

-----------------------------------------------------------------------------
(* hypr-nav *)

Abort == pc' = "done"

\* One mutating request.  Rejected requests change nothing; a lost reply
\* may or may not have taken effect, and routing stops either way.
Mutate(valid, s, loss, next) ==
    /\ UNCHANGED <<born, env, cw, phase, res, nxt, cap, k, complete, snap,
                   degraded, s0>>
    /\ IF ~valid
       THEN Abort /\ UNCHANGED <<focus, alive, panes, cur, named, attached,
                                 lost, muts, destroyed>>
       ELSE \E outcome \in {"ack", "lost-applied", "lost"} :
              /\ IF outcome = "lost"
                 THEN UNCHANGED <<focus, alive, panes, cur, named, attached,
                                  muts, destroyed>>
                 ELSE SetWorld(s) /\ muts' = muts + 1
                      /\ destroyed' = destroyed \cup loss
              /\ lost' = (outcome # "ack")
              /\ pc' = IF outcome = "ack" THEN next ELSE "done"

\* main.rs: hypr.active() at the press.
Capture ==
    /\ pc = "capture"
    /\ UNCHANGED <<desk, env, phase, res, cap, k, complete, snap, lost,
                   degraded, muts, destroyed>>
    /\ IF focus = NONE
       THEN Abort /\ UNCHANGED <<cw, nxt, s0>>
       ELSE /\ cw' = focus /\ s0' = World
            /\ nxt' = IF focus = "W1" THEN "K" ELSE NONE
            /\ pc' = "attach"

\* main.rs layers(): one read per layer, outermost first.  Kitty: `ls`;
\* tmux: `list-clients`; Herdr: `pane.process_info`; Neovim: socket only.
Attach ==
    /\ pc = "attach"
    /\ UNCHANGED <<desk, env, cw, phase, snap, lost, muts, destroyed,
                   s0>>
    /\ IF nxt = NONE
       THEN /\ pc' = "still"
            /\ k' = IF phase = "source" THEN Len(res) ELSE 1
            /\ UNCHANGED <<res, nxt, cap, complete, degraded>>
       ELSE /\ UNCHANGED k
            /\ \E ok \in BOOLEAN :
                 IF ~ok \/ (nxt = "T" /\ ~attached)
                 THEN \* The read failed: the chain ends incomplete here.
                      /\ complete' = FALSE /\ degraded' = ~ok
                      /\ nxt' = NONE /\ pc' = "attach"
                      /\ res' = IF nxt = "H" THEN Append(res, "H") ELSE res
                      /\ UNCHANGED cap
                 ELSE /\ UNCHANGED <<complete, degraded, pc>>
                      /\ CASE nxt = "K" ->
                              IF "W1" \notin alive
                              THEN nxt' = NONE /\ UNCHANGED <<res, cap>>
                              ELSE /\ cap' = [cap EXCEPT !["K"] =
                                        [NoCap EXCEPT
                                           !.pane = cur["K"],
                                           !.nb = Neighbor("K", cur["K"], Dir, panes),
                                           !.edge = cur["K"] = EdgePane("K", panes),
                                           !.e = EdgePane("K", panes)]]
                                   /\ res' = Append(res, "K")
                                   /\ nxt' = Inner("K", World)
                           [] nxt = "T" ->
                              /\ cap' = [cap EXCEPT !["T"] =
                                    [NoCap EXCEPT
                                       !.pane = cur["T"],
                                       !.keep = named \/ Cardinality(panes["T"]) = 1,
                                       !.edge = Neighbor("T", cur["T"], Dir, panes) = NONE]]
                              /\ res' = Append(res, "T") /\ nxt' = NONE
                           [] nxt = "H" ->
                              /\ cap' = [cap EXCEPT !["H"] = [NoCap EXCEPT !.pane = cur["H"]]]
                              /\ res' = Append(res, "H")
                              /\ nxt' = Inner("H", World)
                           [] OTHER ->
                              /\ res' = IF panes["N"] # {} THEN Append(res, "N") ELSE res
                              /\ nxt' = NONE /\ UNCHANGED cap

\* Each action is decided from one read of the layer performing it and
\* names what that read saw (or the layer decides and acts in one request),
\* so only Hyprland's relative move needs the source window still focused.  Close
\* refuses an incomplete chain.  Entry ends after its last layer.
Still ==
    /\ pc = "still"
    /\ UNCHANGED <<desk, env, cw, phase, res, nxt, cap, k, complete, snap,
                   ghost>>
    /\ pc' = IF phase = "entry" /\ k > Len(res) THEN "done"
             ELSE IF phase = "source" /\ Op = "close" /\ ~complete THEN "done"
             ELSE IF phase = "source" /\ Op # "close" /\ k = 0 /\ focus # cw
                  THEN "done"
             ELSE "do"

Pass ==
    /\ k' = IF phase = "source" THEN k - 1 ELSE k + 1
    /\ pc' = "still"
    /\ UNCHANGED <<desk, env, cw, phase, res, nxt, cap, complete, snap, ghost>>

ReadFails == Abort /\ UNCHANGED <<desk, env, cw, phase, res, nxt, cap, k,
                                  complete, snap, lost, muts, destroyed,
                                  s0>> /\ degraded' = TRUE

ReadThen(next, value) ==
    /\ pc' = next /\ snap' = value
    /\ UNCHANGED <<desk, env, cw, phase, res, nxt, cap, k, complete, ghost>>

KillPane(p) == Mutate(p \in panes[LayerOf(p)], Remove(World, Gone(World, p)),
                      Gone(World, p), "done")

Focus(l, p, next) == Mutate(p \in panes[l], [World EXCEPT !.cur[l] = p], {}, next)

\* close: herdr.rs close(), tmux.rs close(), kitty.rs close(), then the
\* Hyprland window.
CloseDo ==
    /\ pc = "do" /\ Op = "close"
    /\ IF k = 0
       THEN Mutate(cw \in alive, KillWindow(World, cw), WindowGone(World, cw), "done")
       ELSE LET l == res[k] IN
            CASE l = "N" -> Pass
              [] l = "H" -> \E ok \in BOOLEAN :          \* session.snapshot
                              IF ~ok THEN ReadFails
                              ELSE IF Cardinality(panes["H"]) = 1 THEN Pass
                              ELSE ReadThen("hclose", cur["H"])
              [] l = "T" -> IF cap["T"].keep
                            THEN Mutate(attached, [World EXCEPT !.attached = FALSE],
                                        {}, "done")
                            ELSE KillPane(cap["T"].pane)
              [] OTHER -> KillPane(cap["K"].pane)        \* close-window id:<captured>

HClose == pc = "hclose" /\ KillPane(snap)                     \* pane.close

\* navigate: innermost first, then Hyprland's relative move.
NavDo ==
    /\ pc = "do" /\ Op # "close" /\ phase = "source"
    /\ IF k = 0
       THEN LET w == WinNeighbor(focus, alive)
            IN Mutate(TRUE, [World EXCEPT !.focus = IF w = NONE THEN focus ELSE w],
                      {}, "entry")
       ELSE LET l == res[k] IN
            CASE l \in {"N", "H"} ->  \* wincmd / pane.focus_direction: the
                                       \* server decides and moves at once
                   LET nb == Neighbor(l, cur[l], Dir, panes)
                   IN IF nb # NONE THEN Focus(l, nb, "done")
                      ELSE \E ok \in BOOLEAN : IF ok THEN Pass ELSE ReadFails
              [] l = "T" ->                  \* select-pane -t <captured> -L/-R
                   IF cap["T"].edge THEN Pass
                   ELSE LET from == cap["T"].pane
                            to == IF Neighbor("T", from, Dir, panes) # NONE
                                  THEN Neighbor("T", from, Dir, panes) ELSE cur["T"]
                        IN Mutate(from \in panes["T"],
                                  [World EXCEPT !.cur["T"] = to], {}, "done")
              [] OTHER ->                    \* focus-window id:<neighbour>
                   IF cap["K"].nb = NONE THEN Pass ELSE Focus("K", cap["K"].nb, "done")

\* main.rs: after an acknowledged move, resolve the destination afresh.
Entry ==
    /\ pc = "entry"
    /\ UNCHANGED <<desk, env, k, complete, snap, ghost>>
    /\ IF focus = cw \/ focus = NONE
       THEN Abort /\ UNCHANGED <<cw, phase, res, nxt, cap>>
       ELSE /\ cw' = focus /\ phase' = "entry" /\ res' = <<>>
            /\ cap' = [l \in Layers |-> NoCap]
            /\ nxt' = IF focus = "W1" THEN "K" ELSE NONE
            /\ pc' = "attach"

\* enter(): outermost first, stopping at the first layer that moves.
EnterDo ==
    /\ pc = "do" /\ phase = "entry"
    /\ LET l == res[k] IN
       CASE l = "K" -> IF cap["K"].edge THEN Pass ELSE Focus("K", cap["K"].e, "done")
         [] l = "T" -> \E ok \in BOOLEAN :                     \* list-panes
                         IF ~ok THEN ReadFails
                         ELSE IF cap["T"].pane = EdgePane("T", panes) THEN Pass
                         ELSE ReadThen("tenter", EdgePane("T", panes))
         [] l = "H" -> \E ok \in BOOLEAN :                     \* pane.layout
                         IF ~ok THEN ReadFails
                         ELSE IF cur["H"] = EdgePane("H", panes) THEN Pass
                         ELSE ReadThen("henter", EdgePane("H", panes))
         [] OTHER -> IF Cardinality(panes["N"]) <= 1           \* 999wincmd
                     THEN \E ok \in BOOLEAN : IF ok THEN Pass ELSE ReadFails
                     ELSE Focus("N", EdgePane("N", panes), "done")

TEnter == pc = "tenter" /\ Focus("T", snap, "done")            \* select-pane
HEnter == pc = "henter" /\ Focus("H", snap, "done")            \* pane.focus

Done == pc = "done" /\ UNCHANGED vars

Proc == Capture \/ Attach \/ Still \/ CloseDo \/ HClose \/ NavDo \/ Entry
        \/ EnterDo \/ TEnter \/ HEnter

NextWorld == [focus |-> focus', alive |-> alive', panes |-> panes',
              cur |-> cur', named |-> named', attached |-> attached']

\* Ghost: what a close would destroy if it ran atomically at each instant
\* from the press until hypr-nav finishes.
\* and every pane that was the focused pane of its layer at some instant.
Track ==
    /\ cands' = IF pc = "done" THEN cands ELSE cands \cup {Permitted(NextWorld)}
    /\ seen' = IF pc = "done" THEN seen
              ELSE seen \cup ({cur'[l] : l \in Layers} \ {NONE})

Next == /\ \/ Proc /\ steps' = steps + 1
           \/ (Env \/ Done) /\ UNCHANGED steps
        /\ Track

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties *)

Quiet == env = 0 /\ ~lost /\ ~degraded

\* Contained close, under any interleaving: at most one pane (with any Neovim
\* inside it) that was focused in its layer during the keypress, or a
\* window that has no pane layer.  Never a Kitty window wholesale.
CloseContained ==
    Op = "close" /\ destroyed # {} =>
        \/ \E p \in seen : destroyed \subseteq {p} \cup
                (IF Hosted(p) = "N" THEN PaneSet("N") ELSE {})
        \/ destroyed = {"W2"}

\* Linearizable close: it destroys what an atomic close at one instant during
\* the keypress would destroy.  Holds with one concurrent user action; two
\* independent focus changes in different layers can defeat any reader that
\* cannot snapshot all layers atomically (see README).
CloseLinearizable ==
    Op = "close" /\ destroyed # {} => \E S \in cands : destroyed \subseteq S

\* One close is at most one mutation; navigation at most a move and an entry.
BoundedMutation == muts <= IF Op = "close" THEN 1 ELSE 2

NavigationDestroysNothing == Op # "close" => destroyed = {}

\* Undisturbed, every keypress does exactly what was expected at the press.
CloseExact ==
    (Op = "close" /\ pc = "done" /\ Quiet) =>
        /\ destroyed = ExpectedLoss(s0)
        /\ CloseTarget(s0).act = "detach" => ~attached

NavigateExact ==
    (Op # "close" /\ pc = "done" /\ Quiet) =>
        /\ focus = ExpectedNav(s0).focus
        /\ cur = ExpectedNav(s0).cur

\* Termination as safety: TLC's deadlock check shows hypr-nav can always
\* step until done (user actions are finite), and this bound shows it cannot
\* step forever: two chain resolutions and one action per layer.
StepBound == steps <= 24
=============================================================================
