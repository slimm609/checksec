package checksec

import (
	"debug/elf"
	"encoding/binary"
)

// Stack-clash protection (-fstack-clash-protection) is detected via annobin
// notes in the .gnu.build.attributes ELF section. The annobin GCC plugin emits
// a bool-typed note per translation unit:
//
//	name = "GA+stack_clash\0"  → built WITH    -fstack-clash-protection
//	name = "GA!stack_clash\0"  → built WITHOUT -fstack-clash-protection
//
// (annobin-global.h: '+' = BOOL_TRUE, '!' = BOOL_FALSE.)
//
// When annobin notes are absent, a bounded .text byte-scan looks for the
// canonical stack-probe instruction signatures (heuristic — see
// classifyStackClashProbe).

const annobinStackClashAttr = "stack_clash"

// stackClashState is the tri-state classification before rendering.
type stackClashState int

const (
	scUnknown stackClashState = iota
	scEnabled
	scDisabled
)

func (s stackClashState) result() Result {
	switch s {
	case scEnabled:
		return Result{Value: "Enabled", Status: StatusGood}
	case scDisabled:
		return Result{Value: "Disabled", Status: StatusBad}
	default:
		return Result{Value: "Unknown", Status: StatusWarn}
	}
}

// merge combines two per-section classifications. Any Disabled wins (partial
// protection is effectively no protection); otherwise Enabled wins over Unknown.
func (s stackClashState) merge(other stackClashState) stackClashState {
	if s == scDisabled || other == scDisabled {
		return scDisabled
	}
	if s == scEnabled || other == scEnabled {
		return scEnabled
	}
	return scUnknown
}

// StackClash reports whether the binary was built with
// -fstack-clash-protection, based on annobin .gnu.build.attributes notes when
// present, falling back to a bounded .text probe-pattern scan otherwise.
func StackClash(file *elf.File) *Result {
	data, bo := annobinSections(file)
	state := classifyAnnobinStackClash(data, bo)
	if state == scUnknown {
		// No annobin verdict — try the heuristic disasm scan.
		if r := stackClashProbeScan(file); r != nil {
			return r
		}
	}
	r := state.result()
	return &r
}

// classifyAnnobinStackClash walks a .gnu.build.attributes payload and returns
// the stack-clash classification. It is bounds-safe on truncated/malformed
// input.
func classifyAnnobinStackClash(data []byte, bo binary.ByteOrder) stackClashState {
	state := scUnknown
	walkAnnobinNotes(data, bo, func(kind byte, attr string, _ []byte) {
		if attr != annobinStackClashAttr {
			return
		}
		switch kind {
		case annobinBoolTrue:
			state = state.merge(scEnabled)
		case annobinBoolFalse:
			state = state.merge(scDisabled)
		}
	})
	return state
}
