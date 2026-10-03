# Binary hardening checks

These checks run against an ELF executable or shared object. Each section lists
what the mitigation protects against, how checksec detects it, every value it
can report (with color), and how to enable it.

See [Understanding output](../output.md) for what the colors and `Unknown` /
`N/A` mean. The **key** under each heading is the report key used in JSON/YAML
output and with [`--fail-if`](../usage.md#ci-gating).

!!! info "Color shorthand used below"
    <span style="display:inline-block;width:0.9em;height:0.9em;border-radius:50%;background:#2e7d32;vertical-align:middle"></span> green ·
    <span style="display:inline-block;width:0.9em;height:0.9em;border-radius:50%;background:#f9a825;vertical-align:middle"></span> yellow ·
    <span style="display:inline-block;width:0.9em;height:0.9em;border-radius:50%;background:#c62828;vertical-align:middle"></span> red ·
    <span style="display:inline-block;width:0.9em;height:0.9em;border-radius:50%;border:1px solid #888;vertical-align:middle"></span> plain (info) ·
    _italic_ (N/A)

---

## RELRO

**Key:** `relro`

**Protects against:** overwriting the GOT (Global Offset Table) and other
runtime relocations to hijack control flow.

**How checksec detects it:** looks for a `PT_GNU_RELRO` segment (Partial) and a
`DT_BIND_NOW` / `DF_BIND_NOW` flag in the dynamic section (Full). Any present
`DT_BIND_NOW` entry counts as bind-now regardless of its value.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Full RELRO` | green | GOT is mapped read-only and bound at startup. |
| `Partial RELRO` | yellow | Some sections are read-only, but the GOT is still writable (lazy binding). |
| `No RELRO` | red | No RELRO protection. |
| `N/A` | _italic_ | Not a dynamically-linked object. |

**Enable:**
```bash
gcc -Wl,-z,relro,-z,now      # Full RELRO
gcc -Wl,-z,relro             # Partial RELRO only
```

---

## Stack Canary

**Key:** `canary`

**Protects against:** stack-buffer-overflow attacks that overwrite the saved
return address.

**How checksec detects it:** scans the symbol table for the stack-guard symbols
`__stack_chk_fail`, `__stack_chk_guard`, or `__intel_security_cookie`.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Canary Found` | green | Stack-protector instrumentation is present. |
| `No Canary Found` | red | No stack canary. |

**Enable:**
```bash
gcc -fstack-protector-strong   # recommended
gcc -fstack-protector-all      # every function (higher overhead)
```

!!! note
    Stripped binaries can hide the symbol; checksec reports based on the symbols
    it can see. A binary with no vulnerable buffers may legitimately lack a
    canary even when the flag was passed.

---

## CFI

**Key:** `cfi`

**Protects against:** control-flow hijacking (ROP/JOP) by enforcing forward-edge
(indirect call) and backward-edge (return) control-flow integrity in hardware.

**How checksec detects it:** parses the `.note.gnu.property` `GNU_PROPERTY_*`
bits, dispatched by architecture, and falls back to Clang-CFI symbol detection.

CFI is **architecture-specific** — the value names the relevant feature pair:

| Arch | Feature pair | Both | One | Neither |
|------|--------------|:----:|:---:|:-------:|
| x86 / x86-64 | Shadow stack + IBT | `SHSTK & IBT` (green) | `… & NO …` (yellow) | `NO SHSTK & NO IBT` (red) |
| ARM (aarch64) | PAC + BTI (+FwdPAC) | see policy below | `… & NO …` (yellow) | `NO PAC & NO BTI` (red) |
| RISC-V | Zicfilp + Zicfiss | `Zicfilp & Zicfiss` (green) | `… & NO …` (yellow) | `NO Zicfilp & NO Zicfiss` (red) |

On AArch64 the two PAC edges are reported as separate tokens:

- `PAC` — return-address signing (backward edge), from
  `-mbranch-protection=pac-ret`, recorded in `GNU_PROPERTY_AARCH64_FEATURE_1_AND`.
- `FwdPAC` — function-pointer signing (forward edge), from LLVM 19+
  `-fptrauth-calls`, recorded in `GNU_PROPERTY_AARCH64_FEATURE_PAUTH`
  (0xc0000001, PAuth ABI). A binary built with both shows
  `PAC & FwdPAC & BTI`.

The AArch64 status uses four levels, by forward/backward granularity:

| Status | Condition |
|:------:|-----------|
| `great` (bold green) | fine-grained forward CFI (`FwdPAC`) **and** backward CFI (`PAC`) |
| `green` | coarse-grained forward CFI (`BTI`) **and** backward CFI (`PAC`) |
| `yellow` | only one of forward/backward enabled |
| `red` | neither enabled |

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Unknown` | yellow | No CFI properties found, or the architecture isn't recognized. |

**Enable:**
```bash
gcc -fcf-protection=full                 # x86: shadow stack + IBT
gcc -mbranch-protection=standard         # ARM: PAC (return-address) + BTI
clang -fptrauth-calls                    # ARM: FwdPAC (LLVM 19+, forward-edge)
gcc -fcf-protection -march=...zicfilp_zicfiss   # RISC-V
```

---

## NX

**Key:** `nx`

**Protects against:** executing injected code from the stack or heap (W^X for
data pages).

**How checksec detects it:** inspects the `PT_GNU_STACK` program header's
permission flags.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `NX enabled` | green | Stack is non-executable. |
| `No GNU_STACK` | yellow | No `PT_GNU_STACK` header — permissions are toolchain/loader-dependent. |
| `NX disabled` | red | Stack is executable (`RWX`). |
| `N/A` | _italic_ | Not applicable to this object. |

**Enable:** NX is the default. Avoid `-z execstack`; use `-z noexecstack` to be
explicit. A `No GNU_STACK` result often means an assembly object didn't declare
`.note.GNU-stack`.

---

## PIE

**Key:** `pie`

**Protects against:** defeats ASLR bypasses by making the executable itself
load-address-independent.

**How checksec detects it:** examines the ELF type (`ET_DYN` vs `ET_EXEC`), the
`DF_1_PIE` flag, and the presence of a `PT_INTERP` segment.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `PIE Enabled` | green | Position-independent executable. |
| `Static PIE` | green | Statically linked PIE (no interpreter). |
| `DSO` | plain | A shared library (`.so`) — PIE doesn't apply the same way. |
| `REL` | yellow | A relocatable object file (`.o`). |
| `PIE Disabled` | red | Fixed-load-address executable. |

**Enable:**
```bash
gcc -fPIE -pie
```

---

## RPATH

**Key:** `rpath`

**Protects against:** library-injection / hijacking via unsafe runtime library
search paths baked into the binary (`DT_RPATH`).

**How checksec detects it:** reads `DT_RPATH` entries and classifies each path.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `No RPATH` | green | No `DT_RPATH` set. |
| `RPATH [path]` | plain | Safe absolute path(s). |
| `RPATH [path] ($ORIGIN)` | yellow | Uses `$ORIGIN` or a nonexistent dir — context-dependent. |
| `RPATH [path] (relative)` | red | Relative, empty (cwd), or world-writable path — insecure. |

**Enable / remediate:** prefer no rpath at all. If you must set one, use a
trusted absolute path, and prefer `RUNPATH` over `RPATH`
(`-Wl,--enable-new-dtags`).

---

## RUNPATH

**Key:** `runpath`

**Protects against:** the same library-hijacking risk as RPATH, for the newer
`DT_RUNPATH` entry (which is searched *after* `LD_LIBRARY_PATH`).

**How checksec detects it:** identical classification to RPATH, applied to
`DT_RUNPATH`.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `No RUNPATH` | green | No `DT_RUNPATH` set. |
| `RUNPATH [path]` | plain | Safe absolute path(s). |
| `RUNPATH [path] ($ORIGIN)` | yellow | `$ORIGIN`/nonexistent — context-dependent. |
| `RUNPATH [path] (relative)` | red | Relative/empty/world-writable — insecure. |

**Enable / remediate:** same guidance as RPATH — ideally none, otherwise a
trusted absolute path.

---

## Symbols

**Key:** `symbols`

**Protects against:** information leakage — a fully populated symbol table makes
reverse engineering and exploit development easier.

**How checksec detects it:** counts entries in the ELF symbol table.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `No Symbols` | green | Stripped — no symbol table. |
| `N symbols` | red | `N` symbols are present (not stripped). |

**Enable (strip):**
```bash
strip -s ./myapp        # strip an existing binary
gcc -s ...              # strip at link time
```

---

## SafeStack

**Key:** `safestack`

**Protects against:** stack-based memory corruption by moving unsafe local
buffers onto a separate, isolated "unsafe stack" (Clang SafeStack).

**How checksec detects it:** scans for the SafeStack runtime symbols.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `SafeStack Found` | green | Compiled with SafeStack. |
| `No SafeStack Found` | red | SafeStack not present. |

**Enable:**
```bash
clang -fsanitize=safe-stack
```

---

## Stack Clash

**Key:** `stack_clash`

**Protects against:** "stack clash" attacks where a large stack allocation jumps
the guard page into adjacent memory.

**How checksec detects it:** prefers authoritative
[annobin](https://sourceware.org/annobin/) notes; if absent, falls back to a
heuristic scan for the per-page stack-probe instruction pattern.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Enabled` | green | annobin notes confirm `-fstack-clash-protection`. |
| `Likely Enabled` | green | Heuristic found stack-probe instructions. |
| `Disabled` | red | annobin notes confirm it was **not** used. |
| `No Probes` | yellow | No annobin notes and no probes found — indeterminate. |
| `Unknown` | yellow | Could not classify. |

**Enable:**
```bash
gcc -fstack-clash-protection
```

---

## W^X segment

**Key:** `separate_code`

**Protects against:** having a single memory segment that is both writable and
executable (`W^X` violation), which eases code injection.

**How checksec detects it:** verifies no `PT_LOAD` segment is simultaneously
writable (`PF_W`) and executable (`PF_X`).

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Enabled` | green | No writable+executable segment. |
| `WX Segment` | red | A segment is both writable and executable. |
| `N/A` | _italic_ | No loadable segments (e.g. a relocatable `.o`). |

**Enable:**
```bash
gcc -Wl,-z,separate-code     # default in modern GNU ld
ld.lld --rosegment           # LLVM lld
```

---

## Selfrando

**Key:** `selfrando`

**Protects against:** function-level address leaks, by randomizing function
layout at load time (the [Selfrando](https://github.com/runsafesecurity/selfrando)
project).

**How checksec detects it:** looks for the `.txtrp` section that Selfrando adds.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Enabled` | green | Selfrando instrumentation present. |
| `No Selfrando` | plain | Not present (the common case). |

**Note:** Selfrando is a specialized, largely historical tool; most binaries
will report `No Selfrando`, which is informational rather than bad.

---

## Sanitizers

**Key:** `sanitizers`

**Protects against:** nothing in production — sanitizers are **build-time
bug-finding** tools. checksec reports them so you don't accidentally ship a
sanitizer-instrumented build.

**How checksec detects it:** scans for compiler-rt symbol prefixes
(`__asan_`, `__ubsan_handle_`, `__msan_`, `__tsan_`, `__lsan_`).

| Value | Color | Meaning |
|-------|:-----:|---------|
| `ASAN` / `UBSAN` / `MSAN` / `TSAN` / `LSAN` (joined by `+`) | plain | The active sanitizer set. |
| `None` | plain | No sanitizers detected. |

**Note:** a non-`None` result on a production binary is usually a packaging
mistake — sanitizer builds are slower and expose internals. Build release
artifacts **without** `-fsanitize=...`.
