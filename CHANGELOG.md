# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- AArch64 forward-edge PAC detection: `GNU_PROPERTY_AARCH64_FEATURE_PAUTH` (0xc0000001, PAuth ABI) emitted by LLVM 19+ `-fptrauth-calls` is now parsed and reported as a `FwdPAC` token, distinct from the `PAC` token (return-address signing via `-mbranch-protection=pac-ret`). A binary with both shows `PAC & FwdPAC & BTI`; the reserved (0, 0) "incompatible" FEATURE_PAUTH tuple is not counted.
- New `StatusGreat` ("great", bold green) result level, used by the AArch64 CFI check: fine-grained forward CFI (FwdPAC) + backward CFI (PAC) = great, coarse-grained forward CFI (BTI) + backward CFI = green, only one edge = yellow, neither = red. `--fail-if` accepts `great` in addition to `green`.

## [3.2.0]
### Added
- SafeStack detection for ELF binaries.
- CFI hardening detection extended to i386 CET and RISC-V Zicfilp/Zicfiss (Zicfilp landing pads, Zicfiss shadow stack), covering RV32 and RV64.
- Sanitizer detection (ASAN, UBSAN, MSAN, TSAN, LSAN) by compiler-rt symbol prefix scan.
- Selfrando detection via the `.txtrp` section (restores a checksec.bash check lost in the v3 port).
- W^X segment check (`SeparateCode`): asserts no `PT_LOAD` segment is both writable and executable, as guaranteed by `ld -z separate-code` / `lld --rosegment`.
- Stack-clash protection detection via annobin `.gnu.build.attributes` notes (authoritative on RHEL/Fedora/CentOS toolchains; reports Unknown otherwise).
- RPATH/RUNPATH inspection that classifies each entry: relative/empty/world-writable as bad, `$ORIGIN` or nonexistent as warning, safe absolute as info.
- annobin-based FORTIFY/GLIBCXX assertion detection.
- CSV output format restored (dropped in the v3 Go port).
- Restored `listfile`, `procLibs`, per-process Seccomp, and the Fortify breakdown.
- `--fail-if` CI gate: exit non-zero when a required check is not in a good state.
- Parallel directory scanning (`RunListChecksParallel`) over a bounded worker pool (default `GOMAXPROCS`).
- `--no-warnings` and `--color` flags; warnings now include filename context.
### Fixed
- Full RELRO detection now uses presence semantics for `DT_BIND_NOW`: any entry in the dynamic section is treated as bind-now, regardless of its `d_val`. Linkers that set a nonzero (spec-unused) value previously caused Full RELRO binaries to be misclassified as Partial or No RELRO.
- CFI `.note.gnu.property` payload parsing: the GNU note wrapper is now validated and sliced out before walking properties, fixing a false negative where IBT+SHSTK binaries were reported as "NO SHSTK & NO IBT".
- PIE detection now distinguishes PIE executables (`DF_1_PIE` or `PT_INTERP` present) from shared libraries (reported as DSO), and reports static-PIE binaries as "Static PIE" rather than "PIE Enabled".
- NX: a missing `PT_GNU_STACK` now reports "No GNU_STACK" instead of being conflated with an RWX (NX-disabled) stack.
- Canary detection now also matches `__stack_chk_guard` and `__intel_security_cookie`, restoring parity with checksec.bash for static/ICC binaries.
- CFI is no longer dropped from XML output.
- `ParseProcMaps` now propagates scanner errors and raises the token limit to 1 MiB so long mapping paths no longer truncate.
- `proc` command now validates the PID up front and fails with a clear error on non-numeric input.
- Fortify error returns and CFI note parser desync corrected.
- `procAll` now skips kernel threads (kthreadd and its children) and non-ELF files instead of crashing on dangling `/proc/<pid>/exe` symlinks.
- Improved error messages in the `proc` command.
### Changed
- Typed output pipeline: a uniform `Result{Value, Status}` return type for all binary checks and a single `fileFields` registry (column order, JSON keys, XML elements, table headers) — adding a check is now one line, and the "field silently dropped from one format" bug class is structurally prevented.
- Check functions (RELRO, RPATH, RUNPATH, SYMBOLS, Fortify) now return errors instead of calling `os.Exit(1)` directly, making error paths testable and consistent.
- Extracted pure helper functions from CFI, Fortify, and dynamic scan logic to enable property-based testing.
- Property-based tests (via `pgregory.net/rapid`) for CFI note parsing, dynamic section scanning, and Fortify helpers; fixture-backed unit tests raise `pkg/` coverage to 80.6%. CI now enforces an 80% coverage floor.
### Performance
- Each target ELF is opened exactly once per `RunFileChecks` (1 `os.Open` + 1 `elf.NewFile`) instead of ~9 reopens; a recursive scan of `/usr/bin` drops from ~18k to ~2k open syscalls.
### Dependencies
- Added `pgregory.net/rapid` for property-based testing.
- Bumped `github.com/u-root/u-root` to 0.16.0, `github.com/fatih/color` to 1.19.0, and `github.com/opencontainers/selinux`.
- Updated Ubuntu base image from 24.04 to 26.04.

## [3.1.0]
### Added
- CFI hardening checks for ARM PAC/BTI and x86 SHSTK/IBT ELF binaries.
- CLI flags to hide headers and banners, plus clearer usage examples for `dir` and `file`.
- Fatal/warning output helper that routes diagnostics to stderr.
### Changed
- RELRO detection now accounts for DF_1_NOW and uses bitmasking for BIND_NOW.
- Kernel module handling reports NX/RELRO as N/A and marks relocatables as `REL`.
- Stripped and static binaries are parsed via dynamic sections to avoid missing Canary/FORTIFY/RELRO.
- Recursive scans skip unreadable directories instead of aborting.
### Fixed
- Avoid crashes on static binaries without symbol tables and improve error handling across file printers.
### Dependencies
- Updated dependencies, including `github.com/opencontainers/selinux`, `github.com/spf13/cobra` (1.10.1), `github.com/u-root/u-root` (0.15.0), and `sigs.k8s.io/yaml` (1.6.0).

## [3.0.2] - 2025-03-10
### Changed
- Updated GoReleaser configuration for the v3 module artifacts.

## [3.0.1] - 2025-03-10
### Added
- Additional Linux kernel checks and configuration discovery from `/boot`.
### Fixed
- Skip invalid PIDs when scanning processes and avoid crashes on broken symlinks.
- Corrected spelling for the disable flag and cleaned up release artifacts.
### Dependencies
- Bumped `github.com/spf13/cobra` to 1.9.1.

## [3.0.0] - 2024-12-15
### Added
- Introduced the Go-based `checksec` CLI with module path support for `go install`.
- Added SELinux policy checks, Fortify process checks, and extra sysctl coverage.
- Added verbose output for more detailed diagnostics.
### Changed
- Updated release targets (macOS and Linux), Docker images, and workflows; removed legacy 2.x sources.
- Adjusted RELRO checks to align with compiler/OS behavior and fixed GoReleaser ldflags handling.
### Dependencies
- Dependency bumps including `github.com/spf13/cobra` 1.8.1 and `github.com/fatih/color` 1.18.0.

[3.2.0]: https://github.com/slimm609/checksec/compare/3.1.0...3.2.0
[3.1.0]: https://github.com/slimm609/checksec/compare/3.0.2...3.1.0
[3.0.2]: https://github.com/slimm609/checksec/compare/3.0.1...3.0.2
[3.0.1]: https://github.com/slimm609/checksec/compare/3.0.0...3.0.1
[3.0.0]: https://github.com/slimm609/checksec/compare/2.7.1...3.0.0
