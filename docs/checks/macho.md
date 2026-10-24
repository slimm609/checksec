# Mach-O hardening checks

These checks run against a Mach-O executable, dylib, bundle, or object file,
thin or universal ("fat"). A universal file produces one report per slice,
named `<path> [<arch>]`. Each section lists what the mitigation protects
against, how checksec detects it, every value it can report (with color), and
how to enable it.

See [Understanding output](../output.md) for what the colors and `Unknown` /
`N/A` mean. The **key** under each heading is the report key used in JSON/YAML
output and with [`--fail-if`](../usage.md#ci-gating). For ELF binaries see
[ELF hardening checks](binary.md).

!!! info "Color shorthand used below"
    <span style="display:inline-block;width:0.9em;height:0.9em;border-radius:50%;background:#2e7d32;vertical-align:middle"></span> green ·
    <span style="display:inline-block;width:0.9em;height:0.9em;border-radius:50%;background:#f9a825;vertical-align:middle"></span> yellow ·
    <span style="display:inline-block;width:0.9em;height:0.9em;border-radius:50%;background:#c62828;vertical-align:middle"></span> red ·
    <span style="display:inline-block;width:0.9em;height:0.9em;border-radius:50%;border:1px solid #888;vertical-align:middle"></span> plain (info) ·
    _italic_ (N/A)

## Core keys shared with ELF

These keys exist on both formats and mean the same thing. `--fail-if` on any of
them gates ELF and Mach-O reports alike. Every other key on this page is
Mach-O-only and is skipped for ELF reports (and vice versa for ELF-only keys
such as `relro`).

| Key | Column | Meaning on both formats |
|-----|--------|-------------------------|
| `pie` | PIE | Position-independent executable |
| `nx` | NX | Non-executable stack |
| `canary` | Stack Canary | Stack protector runtime present |
| `symbols` | Symbols | Defined symbols left in the symbol table |
| `rpath` | RPATH | Library search paths baked into the binary |
| `separate_code` | W^X Seg | No segment both writable and executable |
| `cfi` | CFI | Hardware control-flow integrity (PAC on Darwin) |
| `fortify_source` | FORTIFY | Checked `*_chk` libc variants in use |
| `sanitizers` | Sanitizers | Sanitizer runtime linked in |

!!! note "Structure, not trust"
    `signature` reports what the embedded signature *is* (Developer ID with a team
    id, ad-hoc, linker-signed, absent). checksec does not verify the CMS
    signature, the certificate chain, or page hashes. Use `codesign --verify`
    for that.

!!! note "arm64 vs arm64e"
    `cfi = NO PAC` is the normal result for third-party arm64 binaries; the
    arm64e ABI with pointer authentication is used by Apple's own binaries.
    It is reported yellow so the key keeps ELF semantics, not because every
    arm64 app is a defect.

!!! note "Defaults on Apple clang"
    `-fstack-protector-strong` and `_FORTIFY_SOURCE=2` are on by default, so
    `No Canary Found` or `FORTIFY = No` on a macOS binary usually means the
    default was disabled explicitly or no function qualified.

---

## PIE

**Key:** `pie`

**Protects against:** fixed-address code reuse; ASLR can only slide an image
that is position independent.

**How checksec detects it:** the `MH_PIE` flag (0x200000) in
`mach_header.flags`, interpreted by file type.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `PIE Enabled` | green | `MH_EXECUTE` with `MH_PIE`. |
| `PIE Disabled` | red | `MH_EXECUTE` without `MH_PIE`. |
| `DSO` | plain | `MH_DYLIB` or `MH_BUNDLE` (always position independent). |
| `Object` | yellow | `MH_OBJECT`. |
| `N/A` | _italic_ | Other file types (`MH_DYLINKER`, `MH_KEXT_BUNDLE`, ...). |

**Enable:** default since macOS 10.7 for x86_64, mandatory on arm64.

```bash
clang -Wl,-pie -o app app.c
```

## NX

**Key:** `nx`

**Protects against:** executing injected code from the stack.

**How checksec detects it:** the `MH_ALLOW_STACK_EXECUTION` flag (0x20000).

| Value | Color | Meaning |
|-------|:-----:|---------|
| `NX enabled` | green | Flag clear; the stack is non-executable. |
| `NX disabled` | red | Flag set; the stack is executable. |

**Enable:** drop `-Wl,-allow_stack_execute`. The heap is always
non-executable on x86_64 and arm64; `MH_NO_HEAP_EXECUTION` is i386-only and
not reported.

## Stack Canary

**Key:** `canary`

**Protects against:** stack buffer overflows that overwrite the saved return
address.

**How checksec detects it:** looks for `___stack_chk_fail` or
`___stack_chk_guard` among the symbol table entries.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Canary Found` | green | The stack protector runtime is referenced. |
| `No Canary Found` | red | No stack protector symbols. |

**Enable:** on by default with Apple clang.

```bash
clang -fstack-protector-strong -o app app.c
```

## Symbols

**Key:** `symbols`

**Protects against:** easy reverse engineering; a symbol table names every
function and global.

**How checksec detects it:** counts `nlist` entries that are defined
(`N_TYPE != N_UNDF`) and not debugging stabs (`N_STAB == 0`). Imports are
excluded, and so are symbols marked `N_REFERENCED_DYNAMICALLY` (the
linker-synthesized `__mh_execute_header`, which `strip` must keep), so a fully
stripped executable that still imports libSystem reports `No Symbols`.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `No Symbols` | green | No defined symbols remain. |
| `N symbols` | red | `N` defined symbols remain (for example `2 symbols`). |

**Enable:** `strip -x` (locals) or `strip` for executables. Dylibs keep
exports in the export trie regardless, which is correct and not reported as a
leak here.

```bash
strip app
```

## RPATH

**Key:** `rpath`

**Protects against:** library hijacking through a search path an attacker can
write to.

**How checksec detects it:** reads every `LC_RPATH` and classifies each entry
with the same rules as the ELF check. The worst entry decides the color; all
entries are shown joined with `:`. `LC_LOAD_DYLIB` entries are not reported
here.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `No RPATH` | green | No `LC_RPATH`. |
| `RPATH [<paths>]` | plain | Every entry is an existing absolute directory that is not world-writable. |
| `RPATH [<paths>] (@-relative)` | yellow | An `@executable_path/...`, `@loader_path/...`, or `@rpath/...` entry (context-dependent, like `$ORIGIN`). |
| `RPATH [<paths>] (nonexistent)` | yellow | An absolute entry that does not exist on the scanning host. |
| `RPATH [<paths>] (relative)` / `(empty)` / `(world-writable)` | red | An entry an attacker can likely control. |

**Enable:** use absolute, root-owned paths, or `@loader_path` relative to a
location you control; remove stale entries.

```bash
install_name_tool -delete_rpath <path> app
```

## W^X segment

**Key:** `separate_code`

**Protects against:** pages that are writable and executable at once, which
turn any write primitive into code execution.

**How checksec detects it:** any `LC_SEGMENT(_64)` whose `initprot` has both
`VM_PROT_WRITE` and `VM_PROT_EXECUTE`. Object files hold one unnamed rwx
segment by construction and report `N/A`.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Enabled` | green | No segment is both writable and executable. |
| `WX Segment` | red | At least one segment is mapped writable and executable. |
| `N/A` | _italic_ | No segments, or an `MH_OBJECT`. |

**Enable:** the default linker layout never produces one; remove custom
`-segprot` flags that add `w` and `x` to the same segment.

## CFI (PAC)

**Key:** `cfi`

**Protects against:** return-oriented and jump-oriented programming, by
signing code pointers with pointer authentication.

**How checksec detects it:** the CPU type and subtype of the slice. BTI,
SHSTK, and IBT are not used on Darwin.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `PAC` | green | arm64e slice; pointer authentication ABI. |
| `NO PAC` | yellow | arm64 slice; see the "arm64 vs arm64e" note above. |
| `N/A` | _italic_ | x86_64 or i386; no hardware CFI on Darwin. |

**Enable:**

```bash
clang -arch arm64e -o app app.c
```

## FORTIFY

**Key:** `fortify_source`

**Protects against:** buffer overflows in common libc calls, by routing them
through bounds-checked `___*_chk` variants.

**How checksec detects it:** looks at imported symbols. The fortifiable list
is the ELF list spelled with Darwin's leading underscore (`_strcpy` plain,
`___strcpy_chk` checked).

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Yes` | green | At least one `___*_chk` import. |
| `No` | red | Fortifiable functions imported, none checked. |
| `N/A` | _italic_ | No fortifiable functions imported. |

**Enable:** on by default with Apple clang at `-O1` and above.

```bash
clang -O2 -D_FORTIFY_SOURCE=2 -o app app.c
```

## Sanitizers

**Key:** `sanitizers`

**Protects against:** nothing in production; sanitizers are build-time
bug-finding tools. checksec reports them so you don't ship an instrumented
build.

**How checksec detects it:** the same compiler-rt prefix scan as ELF over the
symbol table, with Darwin's leading underscore.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `ASAN` / `UBSAN` / `MSAN` / `TSAN` / `LSAN` (joined by `+`) | green | The active sanitizer set. |
| `None` | plain | No sanitizers detected. |

**Enable:** build release artifacts **without** `-fsanitize=...`.

## Signature

**Key:** `signature`

**Protects against:** tampering and untrusted code; on macOS a signature is
also the prerequisite for the hardened runtime and entitlements.

**How checksec detects it:** parses the `LC_CODE_SIGNATURE` SuperBlob
(`0xfade0cc0`) and its CodeDirectory (`0xfade0c02`). The team id is read from
the CodeDirectory when its version is at least 0x20200. See the "Structure,
not trust" note above.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Signed [<team id>]` | green | CMS blob present and non-empty, with a team id. |
| `Signed` | green | CMS blob present, no team id. |
| `Ad-hoc` | yellow | `CS_ADHOC` (0x2) or an empty or missing CMS blob. |
| `Linker-signed` | yellow | `CS_LINKER_SIGNED` (0x20000); implies ad-hoc. |
| `Unsigned` | red | No `LC_CODE_SIGNATURE`. |
| `Malformed` | yellow | Load command present, blob unparsable. |

**Enable:**

```bash
codesign -s "<identity>" --options runtime app
```

## Hardened Runtime

**Key:** `hardened_runtime`

**Protects against:** runtime injection. Without the hardened runtime,
`DYLD_INSERT_LIBRARIES`, unsigned dylib loading, and `task_for_pid` from any
same-user process all work, which is exactly what runtime reverse-engineering
tooling relies on.

**How checksec detects it:** `CS_RUNTIME` (0x10000) in the CodeDirectory
flags.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Enabled` | green | Hardened runtime requested. |
| `Disabled` | red | Signed without the hardened runtime. |
| `N/A` | _italic_ | Unsigned or malformed signature. |

**Enable:**

```bash
codesign -s "<identity>" --options runtime app
```

## Entitlements

**Key:** `entitlements`

**Protects against:** entitlements that quietly undo the hardened runtime.

**How checksec detects it:** reads the XML entitlements blob (`0xfade7171`,
special slot 5) or, if absent, the DER blob (`0xfade7172`, slot 7), and
collects top-level boolean-true keys. Only the entitlements below are
reported, by their short label, in this order:

| Entitlement | Label | Why it matters |
|-------------|-------|----------------|
| `com.apple.security.get-task-allow` | `get-task-allow` | Any same-user process can attach a debugger. |
| `com.apple.security.cs.disable-library-validation` | `disable-library-validation` | Unsigned or differently-signed dylibs load. |
| `com.apple.security.cs.allow-dyld-environment-variables` | `allow-dyld-environment-variables` | `DYLD_INSERT_LIBRARIES` works. |
| `com.apple.security.cs.debugger` | `debugger` | Can attach to other processes. |
| `com.apple.security.cs.allow-unsigned-executable-memory` | `allow-unsigned-executable-memory` | JIT-style RWX pages. |
| `com.apple.security.cs.allow-jit` | `allow-jit` | `MAP_JIT` pages (less severe). |

| Value | Color | Meaning |
|-------|:-----:|---------|
| `None` | green | Signed, no risky entitlement. |
| comma-joined labels | red | Any of the first four entitlements above. |
| comma-joined labels | yellow | Worst is `allow-unsigned-executable-memory`. |
| `allow-jit` | plain | Only `allow-jit`. |
| `N/A` | _italic_ | Unsigned or malformed signature. |

**Enable:** remove the entitlement from the `.entitlements` file used at
signing time; `get-task-allow` is added by Xcode for Debug builds only.

## Encrypted

**Key:** `encrypted`

**Protects against:** nothing directly; this is App Store FairPlay. It is
reported so a researcher knows before trying to read `__TEXT`.

**How checksec detects it:** `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64`
with `cryptid != 0`.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Encrypted` | plain | The text segment is FairPlay-encrypted. |
| `Not encrypted` | plain | No encryption. |

**Enable:** informational only.

## Fixups

**Key:** `fixups`

**Protects against:** overwriting lazily-bound symbol pointers (the RELRO
analogue). Modern dyld makes `__DATA_CONST` read-only after applying chained
fixups, which removes the writable `__la_symbol_ptr` table.

**How checksec detects it:** `LC_DYLD_CHAINED_FIXUPS`, then the `MH_BINDATLOAD`
header flag, then the presence of a `__la_symbol_ptr` section.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Chained fixups` | green | `LC_DYLD_CHAINED_FIXUPS` present. |
| `Bind at load` | green | No chained fixups, and `MH_BINDATLOAD` set or no `__la_symbol_ptr` section. |
| `Lazy binding` | yellow | `__la_symbol_ptr` section present. |
| `N/A` | _italic_ | `MH_OBJECT`. |

**Enable:** target macOS 12+ with a current linker (`-fixup_chains` is the
default), or bind at load.

```bash
clang -Wl,-bind_at_load -o app app.c
```

## DYLD Env

**Key:** `dyld_env`

**Protects against:** a shipped binary re-enabling library injection against
itself. `LC_DYLD_ENVIRONMENT` lets a binary set `DYLD_*` variables for itself.

**How checksec detects it:** every `LC_DYLD_ENVIRONMENT` load command.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `None` | green | No `LC_DYLD_ENVIRONMENT`. |
| `<VAR>=<value>` list (joined by `; `) | red | The variables the binary sets. |
| `(malformed)` | red | The load command is present but unreadable. |

**Enable:** remove `-Wl,-dyld_env,...` from the link line.

## Restrict

**Key:** `restrict`

**Protects against:** `DYLD_*` injection on older systems. A legacy
pre-hardened-runtime mechanism that tells dyld to ignore `DYLD_*` variables.

**How checksec detects it:** a `__RESTRICT,__restrict` section.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `Enabled` | green | The section is present. |
| `No Restrict` | plain | Not present; informational because `hardened_runtime` supersedes it. |

**Enable:**

```bash
clang -Wl,-sectcreate,__RESTRICT,__restrict,/dev/null -o app app.c
```

## ARC

**Key:** `arc`

**Protects against:** Objective-C use-after-free and over-release from manual
reference counting.

**How checksec detects it:** if there is an `__objc_imageinfo` section, checks
whether an ARC runtime entry point (`_objc_release`, `_objc_retain`,
`_objc_storeStrong`, `_objc_autoreleaseReturnValue`, and related calls) is
imported.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `ARC` | green | Objective-C code using ARC. |
| `No ARC` | yellow | Objective-C code without ARC runtime imports. |
| `N/A` | _italic_ | No Objective-C image info. |

**Enable:**

```bash
clang -fobjc-arc -o app app.m
```

## Min OS

**Key:** `min_os`

**Protects against:** nothing; it is the deployment target, reported because
every other field's fix advice depends on it.

**How checksec detects it:** the platform and `minos` from `LC_BUILD_VERSION`,
falling back to `LC_VERSION_MIN_MACOSX` / `_IPHONEOS` / `_TVOS` / `_WATCHOS`.
The load command must be full size (24 bytes for `build_version_command`, 16
for `version_min_command`), otherwise the value is `Unknown`.

| Value | Color | Meaning |
|-------|:-----:|---------|
| `<platform> <version>` | plain | For example `macOS 13.0` or `iOS 16.0`. |
| `Unknown` | yellow | No version load command, or a truncated one. |

**Enable:**

```bash
clang -mmacosx-version-min=13.0 -o app app.c
```

!!! note "Test fixtures"
    The Mach-O fixtures in `tests/binaries/output/macho/` are built on a macOS
    host with `tests/binaries/build_macho_fixtures.sh` and committed, so the
    test suite runs on Linux without an Apple toolchain.
