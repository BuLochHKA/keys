# Deobfuscation notes — `0e35b94b-777.lua`

Reverse-engineering notes for the uploaded file. TL;DR: it is a **custom
virtual-machine (VM) obfuscator**. The original Lua source is **not present** in
the file — it was compiled to a private bytecode that the ~200 helper functions
interpret at runtime. Below is a map of the machine, the string-pool format, and
how to recover behaviour.

---

## 1. Top-level shape

```lua
return({ o=…, yk=…, VW=string.char, …≈200 fields…, d={34440, 622006669, …} }):a()(...)
```

* One big table literal of ~200 fields is built, then its method **`a`** is
  called, and the result is immediately invoked with `(...)` (the script args).
* Field **names are meaningless** (`o`, `yk`, `QU`, `AW`, `Ck`…) and reused
  across scopes to defeat readability.
* Numeric indices are written as arithmetic over a constant pool to hide their
  real values, e.g.
  ```lua
  M[0X549f] = (-2340008114 + (((z.d[4] <= z.d[2] and Z or z.d[0X4]) < z.d[0X4]
               and z.d[0X009] or z.d[4]) - z.d[6] + z.d[0X3]))
  ```
  These fold to plain constants at runtime; they carry no logic.

## 2. Library aliases (the VM's toolbox)

Grepping the table for direct stdlib bindings gives the primitives the VM uses:

| Field | Value          | Role in the VM                         |
|-------|----------------|----------------------------------------|
| `VW`  | `string.char`  | build strings from decoded byte values |
| `fW`  | `string.sub`   | slice the bytecode stream              |
| `C`   | `string.gsub`  | transform the printable-encoded blobs  |
| `z`   | `string.byte`  | read a byte out of a chunk             |
| `L`   | `bit`          | bitwise decode (XOR/shift with keys)   |
| `JW`  | `getmetatable` | metatable tricks / env access          |

`string.char` + `string.byte` + `bit` + `gsub` together = a **byte-level
decoder**: the printable blobs (see §4) are turned back into raw bytecode bytes.

## 3. The constant table `d`

```lua
d = {34440, 622006669, 246353689, 428318671, 3809042592,
     1779922615, 3087271938, 1755833546, 3873577099}
```

`z.d[n]` appears throughout the index-arithmetic and in the number decoders
(`rk`, `Bk`, `rk = function(z,z,M,Z,S) return z*(0X2^(S-1023))*(Z/(2^0x34)+M) end`
is an **IEEE-754 double reassembler**). `d` is the key material the folded
constants and float decoders are built from.

## 4. Bytecode stream + readers (the deserializer)

The program is stored as **printable-ASCII-encoded blobs** — 82 string literals
like:

```
'I)5qWe(q9[@$ciCQ)rLgc!!iV(!!0b5^]DLV!!1FI*s0Oa#PS8?!nRLq#EJo…'
```

They are not text; they are the packed bytecode/constants. Two readers pull
values out of the resulting byte stream:

* **Byte reader** — `M[0X1F]()` returns the next raw byte (0–255).
* **Var-int reader (base-128 / LEB128)** — reconstructed near the tail:
  ```lua
  M[39] = function()
    local n, shift = 0, 1
    repeat
      local b = M[0X1F]()               -- next byte
      if M[35] ~= M[0x1d] then
        n = n + ((b > 0x7f and b - 128 or b) * shift)
        shift = shift * 0x80            -- 7 bits per byte, little-endian
      end
    until b < 0x80                      -- high bit clear = last byte
    return n
  end
  ```
  This is how instruction fields, jump offsets and constant indices are read.

* **Float reader** — `rk(...)`/`Bk(...)` rebuild doubles from mantissa+exponent
  (`... * 2^(exp-1023) * (mant/2^52 + 1)`), i.e. numeric constants in the pool.

## 5. Entry method `a` — the loader

```lua
a = function(z)
  local M, Z, S = {}
  S, Z = z:R(Z,S,M); S = z:X(S,Z,M); S = z:B(Z,S,M); S = z:c(Z,S,M)
  S = z:y(M,S); S = z:s(S,M,Z); S = z:b(S,M); S = z:A(S,Z,M)
  S = z:Ck(Z,S,M); S = z:Wk(S,M,Z); S = z:Qk(Z,M,S); S = z:Ak(S,M,Z)
  local A,L,T,O; O,T,A,S,L = z:uW(Z,O,L,A,S,T,M)
  local j; j,S = z:YW(A,Z,O,j,M,S)
  …
  -- eventually returns the closure that runs the dispatch loop
end
```

`M` is the **VM state object**: `M[0x8]` = register/upvalue bank, `M[0x1F]` =
byte reader, `M[39]` = var-int reader, `M[0x2A]` = the top-level proto, etc.
The `R,X,B,c,y,s,b,A,Ck,Wk,Qk,Ak,uW,YW` chain **deserializes** the blobs into
instruction arrays + constant arrays, then hands back the runnable closure.

## 6. The dispatch loop (the interpreter core)

The heart is a giant opcode switch on a handler id `h`, over registers `r`,
constants `K`/`Y`, and helpers. A representative slice (note `loadstring` is
itself just one opcode the compiled program can invoke):

```lua
… if h==0x150 then (r)[o[N]] = r[R[N]] .. u[N]      -- CONCAT
  elseif h==0x151 then (r)[I[N]] = K[N] == r[o[N]]  -- EQ
  elseif …          P = P[c]; F = F[P]              -- table walk (GETTABLE)
  elseif h==0x13e then F = K[N]; w = w - F           -- SUB
  elseif …          r[I[N]] = loadstring             -- load builtin into a reg
  elseif h==0x141 then (r)[I[N]] = Y[N]^r[R[N]]      -- POW
  … (hundreds of arithmetic-obfuscated cases) … end
```

* `r`  – register file          * `K`,`Y` – constant pools
* `o`,`R`,`I`,`u`,`N` – operand fields decoded from the instruction
* the `if/elseif` fan-out over `h` = the equivalent of a Lua `OP_*` switch.

## 7. What is (and isn't) recoverable

* **Recoverable statically:** the VM structure above; the fact there is **no
  plaintext** (no URLs, webhooks, keys, or messages) outside the encoded blobs —
  all real strings live *inside* the bytecode and only exist after the VM's
  decoder runs. The one plaintext URL in the file
  (`i.ebayimg.com/…/s-l1200.png`) is a decoy constant.
* **NOT recoverable by pretty-printing:** the original source. Getting it back
  means **devirtualization** — emulating this specific VM, tracing executed
  opcodes, and lifting them to Lua. That yields a *functional reconstruction*,
  not the pristine original, and is a per-obfuscator project.
* **Cheapest useful recovery = behaviour:** run it in a sandbox that fakes the
  environment and logs every global access, URL, key and nested `loadstring`.
  That is what **`dump_payload.lua`** (in this repo) does.

## 8. Files in this branch

| File                          | What it is                                              |
|-------------------------------|---------------------------------------------------------|
| `0e35b94b-777.beautified.lua` | The loader reformatted/indented for reading.            |
| `dump_payload.lua`            | Sandbox harness — logs behaviour, captures nested code. |
| `DEOBFUSCATION_NOTES.md`      | This document.                                          |

> ⚠ Run `dump_payload.lua` only in an isolated VM/container — it executes
> untrusted code. It needs Lua 5.1 or LuaJIT (uses `setfenv`).
