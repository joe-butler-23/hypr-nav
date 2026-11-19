-- hypr-nav Layer 0: compositor-resident synchronous nav/close and monotone Epoch-CAS.
-- Chezmoi owns binds; dofile() returns `{ nav = function(dir) -> fn, close = fn }`.

local RT = os.getenv("XDG_RUNTIME_DIR") or "/tmp"
local BIN = os.getenv("HYPR_NAV_BIN") or "/run/current-system/sw/bin/hypr-nav"
local DIRS = { left = true, right = true, up = true, down = true }

_G.__hn_gen = _G.__hn_gen or 0
if not _G.__hn_hooked then
  _G.__hn_hooked = true
  hl.on("window.active", function() _G.__hn_gen = _G.__hn_gen + 1 end)
end

local function addr_of(w)
  local hex = tostring(w and w.address or ""):match("^%s*0?[xX]?([0-9a-fA-F]+)%s*$")
  return hex and ("0x" .. hex:lower()) or ""
end

local function clean(s) return tostring(s or ""):gsub("[\t\r\n]", " ") end
local function shq(s) return "'" .. tostring(s or ""):gsub("'", "'\\''") .. "'" end

-- Zero-fork AF_UNIX check in Lua 5.5: live socket -> ENXIO (6), missing -> ENOENT (2).
local function has_sock(path)
  local f, _, code = io.open(path, "r")
  if f then f:close(); return true end
  return code == 6
end

local function target_cap(w)
  local pid = w and tonumber(w.pid) or 0
  if not pid or pid <= 0 then return nil, nil end
  local nav = string.format("%s/nav-%d.sock", RT, pid)
  if has_sock(nav) then return "nav", nav end
  return has_sock(string.format("%s/kitty-%d", RT, pid)) and "kitty" or nil, nil
end

local function spawn_delegate(op, dir, w, kind, sock)
  local p = { shq(BIN), "--from-hypr", op }
  if dir then p[#p + 1] = dir end
  p[#p + 1] = addr_of(w)
  p[#p + 1] = tostring(_G.__hn_gen)
  p[#p + 1] = kind
  if kind == "nav" then
    p[#p + 1] = shq(sock)
  else
    p[#p + 1] = tostring(tonumber(w.pid) or 0)
    p[#p + 1] = shq(clean(w.class))
    p[#p + 1] = shq(clean(w.xdg_tag))
  end
  hl.exec_cmd(table.concat(p, " "))
end

local function dispatch_nav(dir)
  if not DIRS[dir] then return end
  local w = hl.get_active_window()
  if not w then hl.dispatch(hl.dsp.focus({ direction = dir })); return end
  local kind, sock = target_cap(w)
  if kind then spawn_delegate("nav", dir, w, kind, sock); return end
  local from = addr_of(w)
  hl.dispatch(hl.dsp.focus({ direction = dir }))
  local nxt = hl.get_active_window()
  if nxt and addr_of(nxt) ~= from then
    local nk, ns = target_cap(nxt)
    if nk then spawn_delegate("enter", dir, nxt, nk, ns) end
  end
end

local function dispatch_close()
  local w = hl.get_active_window()
  if not w then return end
  local kind, sock = target_cap(w)
  if kind then spawn_delegate("close", nil, w, kind, sock); return end
  local from = addr_of(w)
  if from ~= "" then hl.dispatch(hl.dsp.window.close({ window = "address:" .. from })) end
end

function hn_cli(op)
  if op == "close" then dispatch_close(); return "done" end
  if DIRS[op] then dispatch_nav(op); return "done" end
  return "refuse\tusage: hypr-nav <left|right|up|down|close>"
end

function hn_cas_focus(from_addr, from_gen, dir)
  if not DIRS[dir] then return "refuse\tinvalid direction" end
  local cur = hl.get_active_window()
  if _G.__hn_gen ~= tonumber(from_gen) or addr_of(cur) ~= from_addr then return "refuse\tstale" end
  hl.dispatch(hl.dsp.focus({ direction = dir }))
  local nxt = hl.get_active_window()
  if not nxt or addr_of(nxt) == from_addr then return "done" end
  local kind, sock = target_cap(nxt)
  if kind == "nav" then return "enter\tnav\t" .. clean(sock) end
  if kind == "kitty" then
    return table.concat({ "enter", "kitty", tostring(tonumber(nxt.pid) or 0), clean(nxt.class), clean(nxt.xdg_tag) }, "\t")
  end
  return "done"
end

function hn_cas_close(from_addr, from_gen)
  local cur = hl.get_active_window()
  if _G.__hn_gen ~= tonumber(from_gen) or addr_of(cur) ~= from_addr then return "refuse\tstale" end
  hl.dispatch(hl.dsp.window.close({ window = "address:" .. from_addr }))
  return "done"
end

return { nav = function(dir) return function() dispatch_nav(dir) end end, close = dispatch_close }
