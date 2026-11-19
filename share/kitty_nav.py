"""hypr-nav Layer 1: in-process no_ui Kitty kitten speaking nav-v1."""

import os

OPP = {"left": "right", "right": "left", "up": "down", "down": "up"}


def _clean(s: str) -> str:
    return s.replace("\t", " ").replace("\r", " ").replace("\n", " ")


def parse_herdr_target(argv: list[str]) -> tuple[str, str] | None:
    i, session, remote, pos = 1, "", "", []
    while i < len(argv):
        a = argv[i]
        if a in ("--session", "--remote", "--remote-keybindings"):
            if i + 1 >= len(argv):
                return None
            if a == "--session":
                session = argv[i + 1]
            elif a == "--remote":
                remote = argv[i + 1]
            i += 2
        elif a.startswith("--session="):
            session, i = a[10:], i + 1
        elif a.startswith("--remote="):
            remote, i = a[9:], i + 1
        elif a.startswith("--remote-keybindings=") or a == "--handoff":
            i += 1
        elif a.startswith("-"):
            return None
        else:
            pos.append(a)
            i += 1
    if remote:
        return None if pos else (remote, session or "default")
    if not pos:
        return ("", session or "default")
    return ("", session or pos[2]) if len(pos) == 3 and pos[:2] == ["session", "attach"] else None


def classify_procs(procs: list[dict], runtime_dir: str = "") -> str | None:
    if runtime_dir:
        for p in procs:
            pid = p.get("pid", 0)
            if pid > 0 and os.path.exists(f"{runtime_dir}/nav-{pid}.sock"):
                return f"nav\t{_clean(f'{runtime_dir}/nav-{pid}.sock')}"
    for p in procs:
        argv = p.get("cmdline") or []
        if argv and argv[0].rsplit("/", 1)[-1] == "herdr":
            t = parse_herdr_target(argv)
            if t is not None:
                return f"remote\t{_clean(t[0])}\t{_clean(t[1])}" if t[0] else f"herdr\t{_clean(t[1])}"
    for p in procs:
        argv = p.get("cmdline") or []
        if argv and argv[0].rsplit("/", 1)[-1] == "nvim":
            # Rust owns `--listen` parsing once; forward raw argv fields.
            return "\t".join(["nvim", str(p.get("pid", 0)), _clean(p.get("cwd") or ""), *(_clean(a) for a in argv)])
    return None


def _inner_cap(w) -> str | None:
    fd = getattr(w.child, "child_fd", None)
    if fd is None:
        return None
    try:
        pgrp = os.tcgetpgrp(fd)
    except OSError:
        return None
    if pgrp <= 0:
        return None
    rt = os.environ.get("XDG_RUNTIME_DIR", "")
    if rt and os.path.exists(f"{rt}/nav-{pgrp}.sock"):
        return f"nav\t{_clean(f'{rt}/nav-{pgrp}.sock')}"
    try:
        argv = [a.decode("utf-8", "replace") for a in open(f"/proc/{pgrp}/cmdline", "rb").read().split(b"\0") if a]
        procs = [{"pid": pgrp, "cmdline": argv, "cwd": os.readlink(f"/proc/{pgrp}/cwd")}] if argv else None
    except OSError:
        procs = None
    return classify_procs(procs if procs is not None else w.child.foreground_processes, rt)


def _locate_os_window(boss, wm_class: str, xdg_tag: str):
    from kitty.fast_data_types import current_focused_os_window_id

    tms = [tm for tm in boss.os_window_map.values() if tm is not None]
    cands = [tm for tm in tms if tm.wm_class == wm_class and (not xdg_tag or tm.wm_name == xdg_tag)] if wm_class else tms
    if len(cands) == 1:
        return cands[0], None
    if not cands:
        return None, f"no OS window matches class={wm_class!r} tag={xdg_tag!r}"
    fid = current_focused_os_window_id()
    foc = [tm for tm in cands if tm.os_window_id == fid]
    return (foc[0], None) if len(foc) == 1 else (None, f"{len(cands)} OS windows match tag={xdg_tag!r}")


def _edge_group_id(tab, start_win, direction: str) -> int | None:
    opp, cl, cur, seen, gid = OPP[direction], tab.current_layout, start_win, {start_win.id}, None
    while cands := cl.neighbors_for_any_window(cur, tab.windows).get(opp):
        cand_gid = tab.most_recent_group(cands)
        nxt = tab.windows.active_window_in_group_id(cand_gid)
        if nxt is None or nxt.id in seen:
            break
        seen.add(nxt.id)
        cur, gid = nxt, cand_gid
    return gid


def _move_local(tab, direction: str) -> str:
    nid = tab.neighboring_group_id(direction)
    if nid is None:
        return "pass"
    tab.windows.set_active_group(nid)
    cap2 = _inner_cap(tab.active_window) if tab.active_window is not None else None
    return f"enter\t{cap2}" if cap2 else "done"


def main(args):
    pass


try:
    from kittens.tui.handler import result_handler
except ImportError:
    def result_handler(**_kw):
        return lambda fn: fn


@result_handler(no_ui=True)
def handle_result(args, answer, target_window_id, boss):
    if len(args) < 2:
        return "refuse\tmissing op"
    op = args[1]
    if op in ("nav", "enter"):
        direction, wm_class, xdg_tag, expected = args[2], args[3], args[4], None
    elif op == "step_nav":
        direction, expected, wm_class, xdg_tag = args[2], int(args[3]), args[4], args[5]
    elif op == "close":
        direction, wm_class, xdg_tag, expected = "", args[2], args[3], None
    elif op == "step_close":
        direction, expected, wm_class, xdg_tag = "", int(args[2]), args[3], args[4]
    else:
        return f"refuse\tunknown op {op}"

    tm, err = _locate_os_window(boss, wm_class, xdg_tag)
    if err:
        return f"refuse\t{_clean(err)}"
    tab = tm.active_tab
    w = tab.active_window if tab is not None else None
    if tab is None or w is None:
        return "refuse\tno active Kitty pane"
    if expected is not None and w.id != expected:
        return "refuse\tstale"
    if op == "nav":
        cap = _inner_cap(w)
        return f"delegate\t{w.id}\t{cap}" if cap else _move_local(tab, direction)
    if op == "step_nav":
        return _move_local(tab, direction)
    if op == "enter":
        gid = _edge_group_id(tab, w, direction)
        if gid is not None:
            tab.windows.set_active_group(gid)
            return "done"
        cap = _inner_cap(w)
        return f"enter\t{cap}" if cap else "pass"
    if op == "close":
        cap = _inner_cap(w)
        if cap:
            return f"delegate\t{w.id}\t{cap}"
    boss.close_windows_no_confirm([w])
    return "done"
