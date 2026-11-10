package checksec

import (
	"bytes"
	"debug/elf"
)

// Shadow call stack instrumentation (-fsanitize=shadow-call-stack) emits no
// ELF note or property: it is pure code generation that reserves x18 as the
// shadow stack pointer, with the runtime supplied by the OS or the
// application (see clang/docs/ShadowCallStack.rst). Detection is therefore a
// code-pattern heuristic in the same spirit as the stack-clash probe: scan
// executable sections for the canonical prologue/epilogue pair the AArch64
// backend emits (llvm/lib/Target/AArch64/AArch64FrameLowering.cpp):
//
//	str x30, [x18], #8     — save LR on the shadow stack
//	ldr x30, [x18, #-8]!   — restore LR
//
// The patterns are fixed instruction encodings, verified against
// `clang -target aarch64-linux-gnu` assembler output. Best-effort by nature:
// unrelated x18-based code shaped exactly like these instructions can
// false-positive, and a binary whose only SCS functions are leaf functions
// (which need no save/restore) can false-negative.
const scsScanCap = 1 << 20 // 1 MiB per section

var (
	scsProloguePattern = []byte{0x5e, 0x86, 0x00, 0xf8} // str x30, [x18], #8
	scsEpiloguePattern = []byte{0x5e, 0x8e, 0x5f, 0xf8} // ldr x30, [x18, #-8]!
)

// scsProbeScan reports whether the AArch64 binary's executable sections
// contain the shadow-call-stack prologue/epilogue pair. Always false for
// non-AArch64 binaries.
func scsProbeScan(file *elf.File) bool {
	if file.Machine != elf.EM_AARCH64 {
		return false
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
	return scsPairPresent(sections, scsScanCap)
}

// scsPairPresent is the testable core of scsProbeScan: the save and restore
// patterns must both appear within the first cap bytes of the scanned
// sections. Order-independent — the two typically occur in the same
// function, but section-level matching keeps the probe simple.
func scsPairPresent(sections [][]byte, cap int) bool {
	var sawPrologue, sawEpilogue bool
	for _, data := range sections {
		if len(data) > cap {
			data = data[:cap]
		}
		if !sawPrologue && bytes.Contains(data, scsProloguePattern) {
			sawPrologue = true
		}
		if !sawEpilogue && bytes.Contains(data, scsEpiloguePattern) {
			sawEpilogue = true
		}
		if sawPrologue && sawEpilogue {
			return true
		}
	}
	return false
}
