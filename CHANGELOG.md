# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
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

[Unreleased]: https://github.com/slimm609/checksec/compare/3.0.2...HEAD
[3.0.2]: https://github.com/slimm609/checksec/compare/3.0.1...3.0.2
[3.0.1]: https://github.com/slimm609/checksec/compare/3.0.0...3.0.1
[3.0.0]: https://github.com/slimm609/checksec/compare/2.7.1...3.0.0
