package checksec

import (
	"bytes"
	"debug/elf"
)

// stackClashProbeScan is the heuristic fallback for binaries without annobin
// notes. It scans a bounded prefix of executable sections for the canonical
// stack-probe instruction signatures emitted by -fstack-clash-protection.
//
// This is inherently best-effort:
//   - A binary with the flag set but no function whose frame exceeds the probe
//     interval (4 KiB on x86-64) emits no probes → false negative.
//   - The byte patterns are arch-specific and not unique to stack-clash probes,
//     so the result is "Likely Enabled", never authoritative "Enabled".
//
// Returns nil to defer to the caller's Unknown when no scan applies (unsupported
// arch, no executable section).
const stackClashScanCap = 1 << 20 // 1 MiB per section

func stackClashProbeScan(file *elf.File) *Result {
	pat := stackClashProbePattern(file.Machine)
	if pat == nil {
		return nil
	}
	var sections [][]byte
	for _, sec := range file.Sections {
		if sec.Flags&elf.SHF_EXECINSTR == 0 {
			continue
		}
		if data, err := sec.Data(); err == nil {
			sections = append(sections, data)
		}
	}
	return probeScanResult(sections, pat, stackClashScanCap)
}

// probeScanResult is the testable core of stackClashProbeScan: searches each
// section's first cap bytes for pat.
func probeScanResult(sections [][]byte, pat []byte, cap int) *Result {
	for _, data := range sections {
		if len(data) > cap {
			data = data[:cap]
		}
		if bytes.Contains(data, pat) {
			return &Result{Value: "Likely Enabled", Status: StatusGood}
		}
	}
	return &Result{Value: "No Probes", Status: StatusWarn}
}

// stackClashProbePattern returns the raw machine-code bytes of the per-page
// stack probe the compiler emits under -fstack-clash-protection, or nil for
// unsupported architectures.
func stackClashProbePattern(m elf.Machine) []byte {
	switch m {
	case elf.EM_X86_64:
		// orq $0x0, (%rsp) — REX.W 83 0C 24 00. GCC and Clang both emit this
		// exact 5-byte form as the probe touch in the alloca/prologue loop.
		return []byte{0x48, 0x83, 0x0c, 0x24, 0x00}
	case elf.EM_386:
		// orl $0x0, (%esp) — 83 0C 24 00.
		return []byte{0x83, 0x0c, 0x24, 0x00}
	case elf.EM_AARCH64:
		// str xzr, [sp] — encoding F9 00 03 FF (LE: FF 03 00 F9). GCC's
		// aarch64 stack-clash probe loop touches [sp] with xzr after each
		// page-sized decrement.
		return []byte{0xff, 0x03, 0x00, 0xf9}
	default:
		return nil
	}
}
