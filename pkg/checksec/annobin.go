package checksec

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"strings"
)

// Generalised annobin .gnu.build.attributes note parsing. The note name field
// encodes (kind, attribute, value):
//
//	GA + <kind-char> + <attr> [ \0 <value-bytes> ] \0
//
// kind: '+' bool true, '!' bool false, '*' numeric (LE bytes), '$' string.
// For bool kinds the attr is the rest of the name. For '*' and '$' the attr is
// either a single ID byte (<32) or a string up to the first NUL, with value
// bytes following.
//
// Spec: https://fedoraproject.org/wiki/Toolchain/Watermark and annobin source.

const (
	annobinSectionPrefix    = ".gnu.build.attributes"
	ntGnuBuildAttributeOpen = 0x100
	ntGnuBuildAttributeFunc = 0x101
	annobinBoolTrue         = '+'
	annobinBoolFalse        = '!'
	annobinNumeric          = '*'
	annobinString           = '$'
)

// parseAnnobinName splits a raw note name into (kind, attr, value). Returns
// kind=0 for non-annobin / malformed names.
func parseAnnobinName(raw []byte) (kind byte, attr string, val []byte) {
	// Strip exactly one trailing NUL (the namesz terminator). Stripping more
	// would eat a numeric value byte of 0.
	if len(raw) > 0 && raw[len(raw)-1] == 0 {
		raw = raw[:len(raw)-1]
	}
	if len(raw) < 3 || raw[0] != 'G' || raw[1] != 'A' {
		return 0, "", nil
	}
	kind = raw[2]
	rest := raw[3:]
	switch kind {
	case annobinBoolTrue, annobinBoolFalse:
		return kind, string(rest), nil
	case annobinNumeric, annobinString:
		// Single-byte ID (<32) or NUL-terminated string attr.
		if len(rest) == 0 {
			return kind, "", nil
		}
		if rest[0] < 32 {
			return kind, string(rest[:1]), rest[1:]
		}
		if i := bytes.IndexByte(rest, 0); i >= 0 {
			return kind, string(rest[:i]), rest[i+1:]
		}
		return kind, string(rest), nil
	default:
		return 0, "", nil
	}
}

// walkAnnobinNotes walks a .gnu.build.attributes payload, calling fn for each
// OPEN/FUNC note's parsed name. Bounds-safe on truncated/hostile input.
func walkAnnobinNotes(data []byte, bo binary.ByteOrder, fn func(kind byte, attr string, val []byte)) {
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
			break
		}
		name := data[i : i+int(namesz)]
		i += nameLen + descLen

		if ntype != ntGnuBuildAttributeOpen && ntype != ntGnuBuildAttributeFunc {
			continue
		}
		if kind, attr, val := parseAnnobinName(name); kind != 0 {
			fn(kind, attr, val)
		}
	}
}

// annobinSections concatenates the data of every .gnu.build.attributes* section.
func annobinSections(file *elf.File) ([]byte, binary.ByteOrder) {
	var all []byte
	for _, sec := range file.Sections {
		if !strings.HasPrefix(sec.Name, annobinSectionPrefix) {
			continue
		}
		if d, err := sec.Data(); err == nil {
			all = append(all, d...)
		}
	}
	return all, file.ByteOrder
}

// classifyFortifyLevel scans annobin notes for GA*FORTIFY and returns the
// lowest level seen across translation units (lowest = weakest link). annobin
// uses 0xfe as the "level not set / unknown" sentinel.
func classifyFortifyLevel(data []byte, bo binary.ByteOrder) Result {
	lowest := -1
	walkAnnobinNotes(data, bo, func(kind byte, attr string, val []byte) {
		if kind != annobinNumeric || attr != "FORTIFY" || len(val) == 0 {
			return
		}
		level := int(val[0])
		if level == 0xfe || level == 0xff { // annobin "unknown" sentinels
			return
		}
		if lowest < 0 || level < lowest {
			lowest = level
		}
	})
	switch {
	case lowest < 0:
		return Result{Value: "Unknown", Status: StatusWarn}
	case lowest == 0:
		return Result{Value: "Level 0", Status: StatusBad}
	case lowest == 1:
		return Result{Value: "Level 1", Status: StatusWarn}
	default:
		return Result{Value: fmt.Sprintf("Level %d", lowest), Status: StatusGood}
	}
}

// classifyGlibcxxAssertions scans annobin notes for GA{+,!}GLIBCXX_ASSERTIONS.
// Any false → Disabled (weakest link).
func classifyGlibcxxAssertions(data []byte, bo binary.ByteOrder) Result {
	seen, anyFalse := false, false
	walkAnnobinNotes(data, bo, func(kind byte, attr string, _ []byte) {
		if attr != "GLIBCXX_ASSERTIONS" {
			return
		}
		seen = true
		if kind == annobinBoolFalse {
			anyFalse = true
		}
	})
	switch {
	case !seen:
		return Result{Value: "Unknown", Status: StatusWarn}
	case anyFalse:
		return Result{Value: "Disabled", Status: StatusBad}
	default:
		return Result{Value: "Enabled", Status: StatusGood}
	}
}

// FortifyLevel reports the _FORTIFY_SOURCE level (0/1/2/3) recorded by annobin.
func FortifyLevel(file *elf.File) *Result {
	data, bo := annobinSections(file)
	r := classifyFortifyLevel(data, bo)
	return &r
}

// GlibcxxAssertions reports whether _GLIBCXX_ASSERTIONS was defined, per annobin.
func GlibcxxAssertions(file *elf.File) *Result {
	data, bo := annobinSections(file)
	r := classifyGlibcxxAssertions(data, bo)
	return &r
}
