--[[============================================================================
  dump_payload.lua  —  sandbox harness / behaviour dumper for VM-obfuscated Lua
  ----------------------------------------------------------------------------
  Target: 0e35b94b-777.lua  (custom Lua VM obfuscator, ends with `):a()(...)`)

  WHY THIS INSTEAD OF A "DECODE" SCRIPT
  -------------------------------------
  The obfuscator does NOT store your original source and then `load()` it once.
  It compiles the program to its own bytecode and INTERPRETS it opcode-by-opcode.
  So there is no single decoded string to grab. What you CAN recover cheaply is
  the *behaviour*: every global it touches, every URL/webhook/key it uses, and
  every nested `loadstring(...)` it runs. This harness fakes the whole
  environment, runs the file, and logs all of that.

  HOW TO RUN  (⚠ ISOLATED VM ONLY — this executes untrusted code)
  ---------------------------------------------------------------
     lua5.1 dump_payload.lua              # needs Lua 5.1 / LuaJIT (uses setfenv)
  It looks for ./0e35b94b-777.lua next to it. Output goes to stdout and to
  ./dump.log. Nested code passed to loadstring() is written to ./nested_XX.lua.

  If the payload is Roblox/Luau-specific it may error when it hits an API this
  fake env doesn't model — the log up to that point still shows what it wanted.
  Add missing fields to FAKE below and re-run.
============================================================================]]

local TARGET = "0e35b94b-777.lua"
local logf = assert(io.open("dump.log", "w"))
local nested_n = 0
local realprint = print                              -- capture before we override globals
local realtb = (type(debug) == "table") and debug.traceback or function() return "" end

local function log(...)
  local parts = {}
  for i = 1, select("#", ...) do parts[i] = tostring((select(i, ...))) end
  local line = table.concat(parts, "\t")
  realprint(line); logf:write(line, "\n"); logf:flush()
end

-- A proxy object: records every index/call/concat and keeps working (chainable),
-- so the payload can walk deep API chains (game:GetService(...):FindFirstChild...)
-- without crashing, while we log the whole path.
local function proxy(path)
  local t = {}
  return setmetatable(t, {
    __index = function(_, k)
      log("INDEX ", path .. "." .. tostring(k))
      return proxy(path .. "." .. tostring(k))
    end,
    __newindex = function(_, k, v)
      log("SET   ", path .. "." .. tostring(k) .. " = " .. tostring(v))
    end,
    __call = function(_, ...)
      local args = {}
      for i = 1, select("#", ...) do args[i] = tostring((select(i, ...))) end
      log("CALL  ", path .. "(" .. table.concat(args, ", ") .. ")")
      return proxy(path .. "()")
    end,
    __concat  = function(a, b) return tostring(a) .. tostring(b) end,
    __tostring = function() return "<" .. path .. ">" end,
  })
end

-- Capture code the payload tries to compile/run at runtime.
local real_load = loadstring or load   -- Lua 5.1: loadstring takes a string; load takes a reader fn
local function capture_loadstring(src, chunkname)
  if type(src) == "string" then
    nested_n = nested_n + 1
    local fn = "nested_" .. string.format("%02d", nested_n) .. ".lua"
    local f = io.open(fn, "w"); if f then f:write(src); f:close() end
    log("LOADSTRING", "captured " .. #src .. " bytes -> " .. fn)
  else
    log("LOADSTRING", "non-string arg: " .. tostring(src))
  end
  -- return a harmless runnable stub so the chain continues
  return function(...) log("RUN-NESTED", chunkname or "?"); return proxy("nested") end
end

-- Minimal but permissive fake environment. Extend as needed for your target.
local FAKE = {}
FAKE.print        = function(...) log("print", ...) end
FAKE.warn         = function(...) log("warn", ...) end
FAKE.tostring     = tostring
FAKE.tonumber     = tonumber
FAKE.type         = type
FAKE.pcall        = pcall
FAKE.xpcall       = xpcall
FAKE.select       = select
FAKE.error        = function(m) log("error", m) end
FAKE.assert       = function(v, m, ...)
  if v then return v, m, ... end
  log("assert-fail", "arg1type=" .. type(v), "msg=" .. tostring(m), realtb("", 2))
  return proxy("assert-recovered")   -- keep the chain alive so we see what follows
end
FAKE.ipairs       = ipairs
FAKE.pairs        = pairs
FAKE.next         = next
FAKE.rawget       = rawget
FAKE.rawset       = rawset
FAKE.rawequal     = rawequal
FAKE.rawlen       = rawlen
FAKE.unpack       = unpack or table.unpack
FAKE.setmetatable = setmetatable
FAKE.getmetatable = getmetatable
FAKE.collectgarbage = function(...) return 0 end
FAKE.string = string
FAKE.table  = table
FAKE.math   = math
FAKE.os     = { time = os.time, clock = os.clock, date = os.date, getenv = function() return nil end }
-- The obfuscator needs a `bit` library. Use the host's if present (LuaJIT /
-- Lua 5.2 bit32), otherwise build a portable 32-bit shim in pure arithmetic so
-- plain Lua 5.3 / 5.4 works too.
local function make_bit()
  local host = rawget(_G, "bit") or rawget(_G, "bit32")
  if host then return host end
  local M2 = 4294967296            -- 2^32
  local function norm(x) x = x % M2; return x end
  local function bitop(a, b, f)
    a, b = norm(a), norm(b); local r, p = 0, 1
    for _ = 1, 32 do
      local abit, bbit = a % 2, b % 2
      if f(abit, bbit) == 1 then r = r + p end
      a = (a - abit) / 2; b = (b - bbit) / 2; p = p * 2
    end
    return r
  end
  local B = {}
  function B.band(a, b, ...) local r = bitop(a, b, function(x, y) return (x == 1 and y == 1) and 1 or 0 end)
    for _, v in ipairs({ ... }) do r = B.band(r, v) end return r end
  function B.bor(a, b, ...)  local r = bitop(a, b, function(x, y) return (x == 1 or y == 1) and 1 or 0 end)
    for _, v in ipairs({ ... }) do r = B.bor(r, v) end return r end
  function B.bxor(a, b, ...) local r = bitop(a, b, function(x, y) return (x ~= y) and 1 or 0 end)
    for _, v in ipairs({ ... }) do r = B.bxor(r, v) end return r end
  function B.bnot(a)        return norm(-1 - norm(a)) end
  function B.lshift(a, n)   return norm(norm(a) * 2 ^ (n % 32)) end
  function B.rshift(a, n)   return math.floor(norm(a) / 2 ^ (n % 32)) end
  function B.arshift(a, n)  local x = norm(a); if x >= M2 / 2 then x = x - M2 end
    return math.floor(x / 2 ^ (n % 32)) % M2 end
  function B.rol(a, n) n = n % 32; a = norm(a) return norm(B.lshift(a, n) + B.rshift(a, 32 - n)) end
  function B.ror(a, n) n = n % 32; a = norm(a) return norm(B.rshift(a, n) + B.lshift(a, 32 - n)) end
  function B.tobit(a)  a = norm(a); if a >= M2 / 2 then a = a - M2 end return a end
  function B.tohex(a)  return string.format("%08x", norm(a)) end
  function B.bswap(a)  a = norm(a)
    local b0, b1, b2, b3 = a % 256, math.floor(a / 256) % 256, math.floor(a / 65536) % 256, math.floor(a / 16777216) % 256
    return b0 * 16777216 + b1 * 65536 + b2 * 256 + b3 end
  return B
end
FAKE.bit    = make_bit()
FAKE.bit32  = FAKE.bit
FAKE.load        = capture_loadstring
FAKE.loadstring  = capture_loadstring
FAKE.require     = function(id) log("require", id); return proxy("require(" .. tostring(id) .. ")") end

-- Common Roblox / exploit globals routed through the logging proxy.
for _, name in ipairs({
  "game", "workspace", "Game", "Workspace", "script", "shared", "_G",
  "getgenv", "getrenv", "getfenv", "setfenv", "syn", "http", "request",
  "http_request", "syn_request", "identifyexecutor", "getexecutorname",
  "readfile", "writefile", "isfile", "listfiles", "hookfunction", "getgc",
  "getreg", "debug", "task", "Instance", "Vector3", "CFrame", "Color3",
  "Enum", "UserInputService", "RunService", "Players", "HttpService",
}) do
  FAKE[name] = proxy(name)
end
FAKE._G = FAKE                       -- payload's _G points back at the sandbox
setmetatable(FAKE, { __index = function(_, k)   -- log any global we forgot
  log("MISSING-GLOBAL", tostring(k)); return proxy(tostring(k))
end })

-- Load the target file's source and run it inside the sandbox.
local src = assert(io.open(TARGET, "r")):read("*a")
local chunk, err
if setfenv then                                  -- Lua 5.1 / LuaJIT
  chunk, err = real_load(src, "@" .. TARGET)
  if chunk then setfenv(chunk, FAKE) end
else                                             -- Lua 5.2 / 5.3 / 5.4
  chunk, err = load(src, "@" .. TARGET, "t", FAKE)
end
if not chunk then log("COMPILE-ERROR", err); logf:close(); return end
-- The payload also reads some names from the REAL global table (not just its
-- _ENV), so mirror the whole fake environment into _G and give _G the same
-- missing-global logger. (Harmless: we run the untrusted chunk last.)
for k, v in pairs(FAKE) do rawset(_G, k, v) end
rawset(_G, "bit",   FAKE.bit)
rawset(_G, "bit32", FAKE.bit)
setmetatable(_G, getmetatable(FAKE))
log("bit-check", "FAKE.bit=" .. type(FAKE.bit),
    "FAKE.bit.bor=" .. type(FAKE.bit and FAKE.bit.bor),
    "FAKE.bit.rshift=" .. type(FAKE.bit and FAKE.bit.rshift))
log("=== running payload in sandbox ===")
local ok, e = pcall(chunk)
log("=== payload returned ===", "ok=" .. tostring(ok), e and ("err=" .. tostring(e)) or "")
logf:close()
