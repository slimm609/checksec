package checksec

import (
	"debug/elf"
	"encoding/binary"
	"strings"
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
// This check is authoritative when annobin notes are present (RHEL/Fedora and
// derivatives). On binaries without annobin notes the result is Unknown — a
// disassembly-based heuristic is tracked separately (issue #300).

const (
	annobinSectionPrefix    = ".gnu.build.attributes"
	ntGnuBuildAttributeOpen = 0x100
	ntGnuBuildAttributeFunc = 0x101
	annobinBoolTrue         = '+'
	annobinBoolFalse        = '!'
	annobinStackClashAttr   = "stack_clash"
)

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
// -fstack-clash-protection, based on annobin .gnu.build.attributes notes.
func StackClash(file *elf.File) *Result {
	state := scUnknown
	for _, sec := range file.Sections {
		if !strings.HasPrefix(sec.Name, annobinSectionPrefix) {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		state = state.merge(classifyAnnobinStackClash(data, file.ByteOrder))
		if state == scDisabled {
			break // can't get worse
		}
	}

	r := state.result()
	return &r
}

// classifyAnnobinStackClash walks a .gnu.build.attributes payload and returns
// the stack-clash classification. It is bounds-safe on truncated/malformed
// input: out-of-range reads stop the scan rather than panicking.
func classifyAnnobinStackClash(data []byte, bo binary.ByteOrder) stackClashState {
	state := scUnknown
	pad4 := func(n uint32) int { return int((uint64(n) + 3) &^ 3) }

	i := 0
	for i+12 <= len(data) {
		namesz := bo.Uint32(data[i : i+4])
		descsz := bo.Uint32(data[i+4 : i+8])
		ntype := bo.Uint32(data[i+8 : i+12])
		i += 12

		nameLen := pad4(namesz)
		descLen := pad4(descsz)
		if nameLen < 0 || descLen < 0 || i+nameLen+descLen > len(data) || i+nameLen < i {
			break // truncated or hostile sizes
		}
		name := data[i : i+int(namesz)]
		i += nameLen + descLen

		if ntype != ntGnuBuildAttributeOpen && ntype != ntGnuBuildAttributeFunc {
			continue
		}
		state = state.merge(parseAnnobinBoolNote(name))
		if state == scDisabled {
			return state
		}
	}
	return state
}

// parseAnnobinBoolNote interprets a single annobin note name field. Returns
// scEnabled/scDisabled for a stack_clash bool note, scUnknown otherwise.
func parseAnnobinBoolNote(name []byte) stackClashState {
	// Strip trailing NUL.
	for len(name) > 0 && name[len(name)-1] == 0 {
		name = name[:len(name)-1]
	}
	// Expect "GA" + type-char + attr-id.
	if len(name) < 4 || name[0] != 'G' || name[1] != 'A' {
		return scUnknown
	}
	kind := name[2]
	attr := string(name[3:])
	if attr != annobinStackClashAttr {
		return scUnknown
	}
	switch kind {
	case annobinBoolTrue:
		return scEnabled
	case annobinBoolFalse:
		return scDisabled
	default:
		return scUnknown
	}
}
