#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

poll_until() {
  local tries="$1"; shift
  for ((i = 0; i < tries; i++)); do
    if "$@"; then return 0; fi
    sleep 0.05
  done
  echo "FAIL: timed out waiting for predicate: $*" >&2
  return 1
}

echo "=== [Stage 1] Rust fmt, clippy (#![forbid(unsafe_code)]), release build, Python syntax ==="
python3 -B -c 'import ast, sys; ast.parse(open(sys.argv[1]).read())' "$REPO_DIR/share/kitty_nav.py"
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --release --offline
BIN="$REPO_DIR/target/release/hypr-nav"
echo "[PASS] fmt, clippy, release build, and share/kitty_nav.py syntax"

echo "=== [Stage 2] Timer-audit & non-test sleep/try_wait production audit ==="
if command -v timer-audit >/dev/null 2>&1; then
  TA_OUT="$(timer-audit "$REPO_DIR/src" --json)"
  printf '%s\n' "$TA_OUT"
  python3 - "$TA_OUT" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
assert d.get("findings") == [], f"timer-audit findings: {d}"
PY
fi
python3 - "$REPO_DIR" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1]) / "src"
bad = []
checked_lines = 0
for p in sorted(root.glob("*.rs")):
    if p.name == "bisim.rs":
        continue
    text = p.read_text()
    m = re.search(r'(?m)^#\[cfg\(test\)\]\s*\nmod\s+', text)
    prod = text[:m.start()] if m else text
    checked_lines += len(prod.splitlines())
    for lineno, line in enumerate(prod.splitlines(), 1):
        if re.search(r'\b(thread::sleep|try_wait)\b', line):
            bad.append(f"{p.name}:{lineno}: {line.strip()}")
if bad:
    print("FAIL: polling/sleep found in production code:", file=sys.stderr)
    for b in bad:
        print(" ", b, file=sys.stderr)
    sys.exit(1)
assert checked_lines > 400, f"sanity check failed: only checked {checked_lines} prod lines"
print(f"[PASS] Zero thread::sleep or try_wait across {checked_lines} production lines of src/*.rs")
PY

echo "=== [Stage 3] Unit, proptest, live nvim, Python lockstep, 25k bisimulation, & 6 TLC configs ==="
cargo test --bin hypr-nav
cargo test --test model
echo "[PASS] Rust tests, 25,000-trace Layer B bisimulation, and 6 TLC configs (MaxEnv=1 & 2)"

echo "=== [Stage 4] Unbounded Lean 4 formal proof & axiom audit ==="
LEAN_BIN="$(command -v lean 2>/dev/null || ls -1 /nix/store/*-lean4-*/bin/lean 2>/dev/null | tail -n1 || true)"
[[ -x "$LEAN_BIN" ]] || { echo "FAIL: lean4 not found" >&2; exit 1; }
LEAN_OUT="$("$LEAN_BIN" -DwarningAsError=true "$REPO_DIR/proofs/HyprNav.lean" 2>&1)"
printf '%s\n' "$LEAN_OUT"
python3 - "$LEAN_OUT" <<'PY'
import re, sys
out = sys.argv[1]
lines = [l.strip() for l in out.splitlines() if "depends on axioms:" in l or "does not depend on any axioms" in l]
assert len(lines) >= 19, f"expected >= 19 audited theorems, got {len(lines)}"
allowed = {"propext", "Classical.choice", "Quot.sound"}
for line in lines:
    assert "sorryAx" not in line, f"sorryAx found: {line}"
    assert "ofReduceBool" not in line and "trustCompiler" not in line, f"native_decide found: {line}"
    m = re.search(r'\[([^\]]+)\]', line)
    if m:
        axioms = {a.strip() for a in m.group(1).split(",")}
        extra = axioms - allowed
        assert not extra, f"disallowed axioms {extra} in: {line}"
print(f"[PASS] Lean 4 (-DwarningAsError=true): {len(lines)} theorems, zero sorryAx/native_decide/custom axioms")
PY

echo "=== [Stage 5a] Stripped-env (env -i) & CLI surface rejection checks ==="
set +e
OUT_STRIP="$(timeout 2s env -i "$BIN" left 2>&1)"
RC_STRIP=$?
OUT_ALIAS="$(timeout 2s env -i "$BIN" h 2>&1)"
RC_ALIAS=$?
set -e
[[ "$RC_STRIP" -eq 1 && "$OUT_STRIP" == *"HYPRLAND_INSTANCE_SIGNATURE is unset"* ]] || {
  echo "FAIL: stripped-env check rc=$RC_STRIP out=$OUT_STRIP" >&2; exit 1
}
[[ "$RC_ALIAS" -eq 1 && "$OUT_ALIAS" == *"usage: hypr-nav <left|right|up|down|close>"* ]] || {
  echo "FAIL: alias rejection check rc=$RC_ALIAS out=$OUT_ALIAS" >&2; exit 1
}
echo "[PASS] Stripped-env exit & h/j/k/l alias removal verified"

echo "=== [Stage 5b] Isolated live Herdr 0.9.5 + Neovim + loopback OpenSSH ControlMaster --herdr proof ==="
HERDR_BIN="$(command -v herdr 2>/dev/null || echo /home/joebutler/.local/bin/herdr)"
if [[ -x "$HERDR_BIN" ]] && command -v sshd >/dev/null 2>&1 && command -v ssh-keygen >/dev/null 2>&1; then
  python3 - "$BIN" "$HERDR_BIN" <<'PY'
import json, os, shutil, socket, subprocess, sys, tempfile, time

bin_path, herdr_bin = sys.argv[1], sys.argv[2]
tmp = tempfile.mkdtemp(prefix="hn-v5b-")
procs = []
cm_path = os.path.join(tmp, "cm-%C")
port = None
try:
    for d in ("home", "cfg", "rt"):
        os.mkdir(os.path.join(tmp, d))
    base_env = {
        "PATH": os.environ["PATH"],
        "HOME": f"{tmp}/home",
        "XDG_CONFIG_HOME": f"{tmp}/cfg",
        "XDG_RUNTIME_DIR": f"{tmp}/rt",
        "TERM": "xterm-256color",
    }
    # 1. Start isolated Herdr 0.9.5 server with 2 panes + live nvim with 2 splits in w1:p2
    srv = subprocess.Popen([herdr_bin, "--session", "vremote", "server"], env=base_env,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(srv)
    hsock = os.path.join(tmp, "cfg", "herdr", "sessions", "vremote", "herdr.sock")
    for _ in range(100):
        if os.path.exists(hsock): break
        time.sleep(0.05)
    assert os.path.exists(hsock), "herdr server socket never appeared"

    def hcall(method, params=None):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2.0); s.connect(hsock)
        s.sendall((json.dumps({"id": "v", "method": method, "params": params or {}}) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            c = s.recv(65536)
            if not c: break
            buf += c
        s.close()
        return json.loads(buf.decode())

    hcall("workspace.create", {"name": "w", "cwd": "/tmp"})
    hcall("pane.split", {"direction": "right", "cwd": "/tmp"})
    hcall("pane.focus", {"pane_id": "w1:p2"})
    nv_sock = os.path.join(tmp, "nv.sock")
    nvim_bin = shutil.which("nvim")
    hcall("pane.send_text", {"pane_id": "w1:p2", "text": f"{nvim_bin} -u NONE --listen {nv_sock} -c vsplit\r"})
    for _ in range(80):
        if os.path.exists(nv_sock): break
        time.sleep(0.05)
    assert os.path.exists(nv_sock), "remote nvim inside herdr did not start"

    # 2. Start isolated loopback OpenSSH sshd + HYPR_NAV_SSH wrapper using ControlMaster -> `hypr-nav --herdr`
    hkey, ukey = os.path.join(tmp, "hkey"), os.path.join(tmp, "ukey")
    subprocess.check_call(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hkey])
    subprocess.check_call(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", ukey])
    auth = os.path.join(tmp, "auth")
    shutil.copy(ukey + ".pub", auth)
    os.chmod(auth, 0o600)
    ts = socket.socket(); ts.bind(("127.0.0.1", 0)); port = ts.getsockname()[1]; ts.close()
    sshd_cfg = os.path.join(tmp, "sshd_config")
    with open(sshd_cfg, "w") as f:
        f.write(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {hkey}\nAuthorizedKeysFile {auth}\n"
                f"PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nPidFile {tmp}/sshd.pid\n")
    sshd = subprocess.Popen([shutil.which("sshd"), "-D", "-f", sshd_cfg],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(sshd)
    for _ in range(50):
        try:
            c = socket.create_connection(("127.0.0.1", port), timeout=0.1); c.close(); break
        except OSError:
            time.sleep(0.05)

    ssh_wrap = os.path.join(tmp, "ssh_wrap.sh")
    with open(ssh_wrap, "w") as f:
        f.write(f"""#!/usr/bin/env bash
set -euo pipefail
sess="$2"
shift 2
op_args="$(printf ' %q' "$@")"
exec ssh -p {port} -i "{ukey}" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes \
  -o ControlMaster=auto -o "ControlPath={cm_path}" -o ControlPersist=5s \
  -T 127.0.0.1 \
  "XDG_CONFIG_HOME='{tmp}/cfg' XDG_RUNTIME_DIR='{tmp}/rt' HOME='{tmp}/home' '{bin_path}' --herdr '$sess'$op_args"
""")
    os.chmod(ssh_wrap, 0o755)

    cli_env = dict(base_env, HYPR_NAV_SSH=ssh_wrap)

    def run_remote(op_args):
        return subprocess.run([bin_path, "--from-hypr", *op_args, "0x1000", "1", "remote", "loopback", "vremote"],
                              env=cli_env, capture_output=True, text=True, timeout=5)

    # 3. Drive remote Neovim (2 splits in w1:p2) + remote Herdr (w1:p2 -> w1:p1) over stateless --herdr + ControlMaster!
    assert run_remote(["nav", "right"]).returncode == 0
    assert run_remote(["nav", "left"]).returncode == 0
    assert run_remote(["nav", "left"]).returncode == 0
    snap = hcall("session.snapshot")["result"]["snapshot"]
    assert snap["focused_pane_id"] == "w1:p1", f"expected Herdr focus moved to w1:p1, got {snap['focused_pane_id']}"

    # 4. Close remote Herdr pane w1:p1 -> only 1 pane remains (w1:p2); next close must SPARE final pane!
    assert run_remote(["close"]).returncode == 0
    snap2 = hcall("session.snapshot")["result"]["snapshot"]
    assert len(snap2["panes"]) == 1, f"expected 1 pane left, got {len(snap2['panes'])}"

    # 5. Kill sshd + ControlMaster -> verify fail-closed refusal on `close` (exits non-zero) & final pane survives!
    subprocess.run(["ssh", "-p", str(port), "-o", f"ControlPath={cm_path}", "-O", "exit", "127.0.0.1"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sshd.kill(); sshd.wait(timeout=2)
    res_dead = run_remote(["close"])
    assert res_dead.returncode != 0, f"expected fail-closed refusal on dead sshd, got rc={res_dead.returncode}"
    assert len(hcall("session.snapshot")["result"]["snapshot"]["panes"]) == 1
finally:
    if port is not None:
        subprocess.run(["ssh", "-p", str(port), "-o", f"ControlPath={cm_path}", "-O", "exit", "127.0.0.1"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for p in reversed(procs):
        try: p.kill(); p.wait(timeout=2)
        except Exception: pass
    shutil.rmtree(tmp, ignore_errors=True)
PY
  echo "[PASS] Isolated live Herdr 0.9.5 + Neovim + loopback OpenSSH ControlMaster --herdr & partition refusal"
else
  echo "[SKIP] herdr or sshd/ssh-keygen not found"
fi

echo "=== [Stage 5c] Isolated live Hyprland 0.57.2 (hypr-nav.lua) + Kitty 0.50.0 (kitty_nav.py) + nav-v1 app ==="
HOST_UID="$(id -u)"
PARENT_WL="/run/user/${HOST_UID}/wayland-1"
if [[ -S "$PARENT_WL" ]] && command -v Hyprland >/dev/null 2>&1 && command -v kitty >/dev/null 2>&1; then
  TMP="$(mktemp -d /tmp/hn-vhl.XXXX)"
  HYPR_PID=""
  PIDS=()
  cleanup_hypr() {
    for p in "${PIDS[@]:-}"; do
      if [[ -n "$p" ]]; then
        kill -KILL "$p" 2>/dev/null || true
        wait "$p" 2>/dev/null || true
      fi
    done
    if [[ -n "$HYPR_PID" ]] && kill -0 "$HYPR_PID" 2>/dev/null; then
      [[ -n "${SIG:-}" ]] && XDG_RUNTIME_DIR="$TMP/r" hyprctl --instance "$SIG" dispatch 'hl.dsp.exit()' >/dev/null 2>&1 || true
      kill -TERM "$HYPR_PID" 2>/dev/null || true
      wait "$HYPR_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
  }
  trap cleanup_hypr EXIT
  mkdir -p "$TMP/r" "$TMP/h" "$TMP/c"
  ln -s "$PARENT_WL" "$TMP/r/wayland-parent"
  cat > "$TMP/hl.lua" <<EOF
hl.monitor({ output = "WAYLAND-1", mode = "1280x800@60", position = "0x0", scale = 1 })
hl.config({
  general = { layout = "dwindle" },
  animations = { enabled = false },
  misc = { disable_hyprland_logo = true, disable_splash_rendering = true, disable_autoreload = true },
})
_G.hyprNav = dofile("$REPO_DIR/share/hypr-nav.lua")
EOF
  cat > "$TMP/kitty.conf" <<EOF
allow_remote_control socket-only
listen_on unix:$TMP/r/kitty
enabled_layouts splits
confirm_os_window_close 0
EOF
  env -i PATH="/run/wrappers/bin:/run/current-system/sw/bin:/etc/profiles/per-user/joebutler/bin:/usr/bin:/bin" \
    HOME="$TMP/h" XDG_CONFIG_HOME="$TMP/c" XDG_RUNTIME_DIR="$TMP/r" \
    HYPR_NAV_BIN="$BIN" HYPR_NAV_KITTEN="$REPO_DIR/share/kitty_nav.py" \
    WAYLAND_DISPLAY="wayland-parent" AQ_NO_KMS_REQUIREMENT=1 AQ_NO_MODIFIERS=1 \
    HYPRLAND_NO_SD_NOTIFY=1 HYPRLAND_NO_SD_VARS=1 HYPRLAND_NO_SD_TARGET=1 HYPRLAND_NO_CRASHREPORTER=1 \
    Hyprland --config "$TMP/hl.lua" >"$TMP/hypr.log" 2>&1 </dev/null &
  HYPR_PID=$!
  SIG=""
  has_hypr_sock() {
    local cand
    cand="$(ls -1 "$TMP/r/hypr" 2>/dev/null | head -n1 || true)"
    [[ -n "$cand" && -S "$TMP/r/hypr/$cand/.socket.sock" ]] && SIG="$cand"
  }
  poll_until 100 has_hypr_sock
  CHILD_WL="$(ls -1 "$TMP/r" | grep '^wayland-' | grep -v '^wayland-parent$' | grep -v '\.lock$' | head -n1)"
  # Never touch live user D-Bus/systemd env!
  unset DBUS_SESSION_BUS_ADDRESS NOTIFY_SOCKET
  export XDG_RUNTIME_DIR="$TMP/r" HYPRLAND_INSTANCE_SIGNATURE="$SIG" WAYLAND_DISPLAY="$CHILD_WL"
  export HYPR_NAV_BIN="$BIN" HYPR_NAV_KITTEN="$REPO_DIR/share/kitty_nav.py"

  has_client_title() { hyprctl -j clients | grep -q "\"$1\""; }
  client_titles() { hyprctl -j clients | python3 -c 'import json,sys; print(sorted(w["title"] for w in json.load(sys.stdin)))'; }
  active_addr() { hyprctl -j activewindow | python3 -c 'import json,sys; print(json.load(sys.stdin).get("address", ""))'; }
  active_addr_is() { [[ "$(active_addr)" == "$1" ]]; }
  titles_are() { [[ "$(client_titles)" == "$1" ]]; }
  has_kitty_sock() { [[ -n "$(find "$TMP/r" -maxdepth 1 -name 'kitty-*' -type s -print -quit)" ]]; }
  kitty_panes_eq() { [[ "$(kitty @ --to "unix:$KSOCK" ls | python3 -c 'import json,sys; print(len(json.load(sys.stdin)[0]["tabs"][0]["windows"]))')" == "$1" ]]; }
  kitty_focused_id() { kitty @ --to "unix:$KSOCK" ls | python3 -c 'import json,sys; print([w["id"] for w in json.load(sys.stdin)[0]["tabs"][0]["windows"] if w["is_focused"]][0])'; }
  kitty_focused_is_not() { [[ "$(kitty_focused_id)" != "$1" ]]; }
  kitty_focused_is() { [[ "$(kitty_focused_id)" == "$1" ]]; }

  # 1. Spawn remotely controllable 2-pane Kitty (winK) + two plain windows (winA, winB)
  kitty --config "$TMP/kitty.conf" --os-window-tag="kitty-verify" --class kitty -T winK -e sh -c 'exec tail -f /dev/null' >/dev/null 2>&1 </dev/null &
  PIDS+=("$!")
  poll_until 80 has_client_title "winK"
  poll_until 80 has_kitty_sock
  KSOCK="$(find "$TMP/r" -maxdepth 1 -name 'kitty-*' -type s -print -quit)"
  kitty @ --to "unix:$KSOCK" launch --type=window --location=vsplit sh -c 'exec tail -f /dev/null' >/dev/null
  poll_until 40 kitty_panes_eq 2

  kitty --config NONE -o confirm_os_window_close=0 --class plain -T winA -e sh -c 'exec tail -f /dev/null' >/dev/null 2>&1 </dev/null &
  PIDS+=("$!")
  poll_until 80 has_client_title "winA"
  kitty --config NONE -o confirm_os_window_close=0 --class plain -T winB -e sh -c 'exec tail -f /dev/null' >/dev/null 2>&1 </dev/null &
  PIDS+=("$!")
  poll_until 80 has_client_title "winB"

  ADDR_K="$(hyprctl -j clients | python3 -c 'import json,sys; print([w["address"] for w in json.load(sys.stdin) if w["class"]=="kitty"][0])')"
  ADDR_A="$(hyprctl -j clients | python3 -c 'import json,sys; print([w["address"] for w in json.load(sys.stdin) if w["title"]=="winA"][0])')"
  PID_A="$(hyprctl -j clients | python3 -c 'import json,sys; print([w["pid"] for w in json.load(sys.stdin) if w["title"]=="winA"][0])')"
  ADDR_B="$(hyprctl -j clients | python3 -c 'import json,sys; print([w["address"] for w in json.load(sys.stdin) if w["title"]=="winB"][0])')"

  # 2. Prove universal zero-shim `$XDG_RUNTIME_DIR/nav-<pid>.sock` routing on winA!
  NAV_LOG="$TMP/nav_v1.log"
  python3 - "$TMP/r/nav-${PID_A}.sock" "$NAV_LOG" <<'PY' &
import os, socket, sys
sock_path, log_path = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path); s.listen(4)
for reply in ("done\n", "pass\n"):
    c, _ = s.accept()
    req = c.recv(256).decode().strip()
    with open(log_path, "a") as f: f.write(req + "\n")
    c.sendall(reply.encode())
    c.close()
s.close(); os.unlink(sock_path)
PY
  PIDS+=("$!")
  poll_until 40 test -S "$TMP/r/nav-${PID_A}.sock"
  hyprctl dispatch "hl.dsp.focus({window = \"address:$ADDR_A\"})" >/dev/null
  poll_until 40 active_addr_is "$ADDR_A"
  # First call: nav-v1 server returns `done` -> focus remains on winA!
  hyprctl repl 'hyprNav.nav("left")(); return "ok"' >/dev/null
  poll_until 40 grep -qx "nav left" "$NAV_LOG"
  [[ "$(active_addr)" == "$ADDR_A" ]] || { echo "FAIL: nav-v1 done should stay on winA" >&2; exit 1; }
  # Second call: nav-v1 server returns `pass` -> Hyprland Epoch-CAS moves focus off winA!
  hyprctl repl 'hyprNav.nav("left")(); return "ok"' >/dev/null
  poll_until 40 bash -c '[[ "$(wc -l < "'"$NAV_LOG"'")" -ge 2 ]]'
  poll_until 40 bash -c '[[ "$(hyprctl -j activewindow | python3 -c "import json,sys; print(json.load(sys.stdin).get(\"address\",\"\"))")" != "'"$ADDR_A"'" ]]'

  # 3. Prove ABA focus flip `winB -> winK -> winB` rejected by monotone GEN Epoch-CAS!
  hyprctl dispatch "hl.dsp.focus({window = \"address:$ADDR_B\"})" >/dev/null
  poll_until 40 active_addr_is "$ADDR_B"
  GEN0="$(hyprctl repl 'return tostring(_G.__hn_gen)')"
  hyprctl dispatch "hl.dsp.focus({window = \"address:$ADDR_K\"})" >/dev/null
  poll_until 40 active_addr_is "$ADDR_K"
  hyprctl dispatch "hl.dsp.focus({window = \"address:$ADDR_B\"})" >/dev/null
  poll_until 40 active_addr_is "$ADDR_B"
  RES_ABA_CLOSE="$(hyprctl repl "return hn_cas_close(\"$ADDR_B\", $GEN0)")"
  RES_ABA_FOCUS="$(hyprctl repl "return hn_cas_focus(\"$ADDR_B\", $GEN0, \"left\")")"
  [[ "$RES_ABA_CLOSE" == *"stale"* && "$RES_ABA_FOCUS" == *"stale"* ]] || {
    echo "FAIL: ABA Epoch-CAS did not reject stale gen=$GEN0: close=$RES_ABA_CLOSE focus=$RES_ABA_FOCUS" >&2; exit 1
  }

  # 4. Prove Layer-0 synchronous fast-path close on plain winB (0 forks!)
  hyprctl repl 'hyprNav.close(); return "ok"' >/dev/null
  poll_until 40 titles_are "['winA', 'winK']"

  # 5. Prove Layer-1 in-RAM Kitty `share/kitty_nav.py` via real `hyprNav` + compiled `hypr-nav`:
  hyprctl dispatch "hl.dsp.focus({window = \"address:$ADDR_K\"})" >/dev/null
  poll_until 40 active_addr_is "$ADDR_K"
  P_BEFORE="$(kitty_focused_id)"
  "$BIN" left
  poll_until 40 kitty_focused_is_not "$P_BEFORE"
  "$BIN" right
  poll_until 40 kitty_focused_is "$P_BEFORE"
  "$BIN" close
  poll_until 40 kitty_panes_eq 1

  # Close remaining plain winA via standalone CLI `hypr-nav close`
  hyprctl dispatch "hl.dsp.focus({window = \"address:$ADDR_A\"})" >/dev/null
  poll_until 40 active_addr_is "$ADDR_A"
  "$BIN" close
  poll_until 40 titles_are "['winK']"

  cleanup_hypr
  trap - EXIT
  echo "[PASS] Isolated live Hyprland 0.57.2 (hypr-nav.lua) + Kitty 0.50.0 (kitty_nav.py) + nav-v1 app"
else
  echo "[SKIP] Isolated live Hyprland proof skipped (no $PARENT_WL or Hyprland/kitty missing)"
fi

echo "=== ALL HYPR-NAV VERIFICATION GATES PASSED ==="
