# Test Coverage Reporting & Increase — Design

**Date:** 2026-04-23
**Scope:** Add terminal-based coverage reporting and increase unit test coverage for `pkg/checksec`

## Goals

- Add a `make coverage` command that prints a per-function coverage summary to the terminal
- Fix `go: no such tool "covdata"` errors so all packages appear in coverage output
- Increase `pkg/checksec` coverage from ~20% by adding unit tests for currently untested files

## Out of Scope

- HTML coverage reports
- CI/CD integration (Codecov, Coveralls)
- Coverage thresholds / enforcement

---

## Coverage Reporting

### Makefile target

Add a `coverage` target to the Makefile:

```makefile
.PHONY: coverage
coverage:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -func=coverage.out
```

`-covermode=atomic` is the most accurate mode and is required when tests run concurrently. The `coverage.out` profile file is a standard Go artifact and should be added to `.gitignore`.

### Fix `covdata` error

The `go: no such tool "covdata"` error appears for `cmd/` and the root package. This needs investigation to determine whether it is a build tag issue, an incompatible Go toolchain version, or a misconfigured test binary. The fix will ensure all packages report coverage rather than erroring out.

---

## Test Coverage Increase

### Current state

| Package | Coverage |
|---|---|
| `pkg/checksec` | 20.1% |
| `pkg/utils` | 54.6% |
| `pkg/output` | 84.0% |

### Target files

The following files in `pkg/checksec` have zero test coverage and are the primary targets:

- `fortify.go`
- `kernel.go`
- `pie.go`
- `relro.go`
- `rpath.go`
- `runpath.go`
- `symbols.go`
- `sysctl.go`

### Test patterns

Existing test files (`canary_test.go`, `cfi_test.go`, `nx_test.go`, `safestack_test.go`) establish patterns to follow:

- Use table-driven tests with named cases
- Use test binary fixtures from `tests/binaries/` where available
- Test both the happy path (binary with feature enabled/disabled) and error cases (missing file, invalid ELF)
- Use `testhelpers_test.go` utilities for shared setup

New test files will be named `<feature>_test.go` alongside the source file.

---

## File Changes

| File | Change |
|---|---|
| `Makefile` | Add `coverage` phony target |
| `.gitignore` | Add `coverage.out` |
| `cmd/` or `main.go` | Fix covdata error (TBD after investigation) |
| `pkg/checksec/fortify_test.go` | New |
| `pkg/checksec/kernel_test.go` | New |
| `pkg/checksec/pie_test.go` | New |
| `pkg/checksec/relro_test.go` | New |
| `pkg/checksec/rpath_test.go` | New |
| `pkg/checksec/runpath_test.go` | New |
| `pkg/checksec/symbols_test.go` | New |
| `pkg/checksec/sysctl_test.go` | New |
