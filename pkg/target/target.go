// pkg/target/target.go
package target

import (
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
)

// Format is the container format of a scan target.
type Format string

const (
	ELF     Format = "elf"
	MachO   Format = "macho"
	PE      Format = "pe" // detected, not opened, in this piece
	Unknown Format = "unknown"
)

// Supported reports whether checksec has a check registry for f.
func Supported(f Format) bool {
	return f == ELF || f == MachO
}

// handle is the descriptor shared by every Target of one path.
type handle struct {
	f    *os.File
	once sync.Once
}

// Target is one analyzable image. Exactly one of ELF / MachO is non-nil for a
// supported, parsable image. Fat Mach-O files produce one Target per slice,
// all sharing Raw.
type Target struct {
	Path   string
	Format Format
	Arch   string // "x86_64", "arm64", "arm64e", "i386", ...; "" for ELF
	Fat    bool   // true when this Target is one slice of a fat Mach-O
	Raw    *os.File
	ELF    *elf.File
	MachO  *macho.File

	h *handle
}

// Close releases the shared descriptor. Safe to call on any Target of a path
// and safe to call more than once.
func (t *Target) Close() {
	if t == nil || t.h == nil {
		return
	}
	t.h.once.Do(func() { _ = t.h.f.Close() })
}

const (
	magicELF    = 0x7f454c46
	magicFat    = 0xcafebabe
	machoMagic  = 0xfeedface
	machoMagic6 = 0xfeedfacf
	maxFatArch  = 16
	fatHdrLen   = 8
	fatArchLen  = 20
)

// Detect reads the leading magic and reports the format without parsing the
// image. A 0xcafebabe header counts as fat Mach-O only when the arch count is
// plausible (1..16), which excludes Java class files.
func Detect(r io.ReaderAt) Format {
	var hdr [8]byte
	n, _ := r.ReadAt(hdr[:], 0)
	if n < 4 {
		return Unknown
	}
	be := binary.BigEndian.Uint32(hdr[:4])
	le := binary.LittleEndian.Uint32(hdr[:4])
	switch {
	case be == magicELF:
		return ELF
	case be == machoMagic || be == machoMagic6 || le == machoMagic || le == machoMagic6:
		return MachO
	case be == magicFat && n >= 8:
		if narch := binary.BigEndian.Uint32(hdr[4:8]); narch >= 1 && narch <= maxFatArch {
			return MachO
		}
		return Unknown
	case hdr[0] == 'M' && hdr[1] == 'Z':
		var lfanew [4]byte
		if _, err := r.ReadAt(lfanew[:], 0x3c); err != nil {
			return Unknown
		}
		off := int64(binary.LittleEndian.Uint32(lfanew[:]))
		var sig [4]byte
		if _, err := r.ReadAt(sig[:], off); err != nil {
			return Unknown
		}
		if string(sig[:]) == "PE\x00\x00" {
			return PE
		}
		return Unknown
	}
	return Unknown
}

// ArchName maps a Mach-O cpu type/subtype pair to the name lipo prints.
func ArchName(cpu macho.Cpu, sub uint32) string {
	switch cpu {
	case macho.CpuAmd64:
		return "x86_64"
	case macho.Cpu386:
		return "i386"
	case macho.CpuArm64:
		if sub&0x00ffffff == 2 {
			return "arm64e"
		}
		return "arm64"
	case macho.CpuArm:
		return "arm"
	case macho.CpuPpc:
		return "ppc"
	case macho.CpuPpc64:
		return "ppc64"
	}
	return fmt.Sprintf("cpu-%d", uint32(cpu))
}

// Open opens path exactly once and returns one Target per image. Unknown and
// PE formats return a single Target with no parsed view and no error, so
// callers can still emit an aligned error row. An error is returned only when
// the file itself cannot be opened.
func Open(path string) ([]*Target, error) {
	raw, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", path, err)
	}
	h := &handle{f: raw}
	base := Target{Path: path, Raw: raw, h: h}

	switch Detect(raw) {
	case ELF:
		t := base
		t.Format = ELF
		if ef, err := elf.NewFile(raw); err == nil {
			t.ELF = ef
		}
		return []*Target{&t}, nil
	case MachO:
		return openMachO(base, raw), nil
	case PE:
		t := base
		t.Format = PE
		return []*Target{&t}, nil
	}
	t := base
	t.Format = Unknown
	return []*Target{&t}, nil
}

func openMachO(base Target, raw *os.File) []*Target {
	var hdr [fatHdrLen]byte
	if _, err := raw.ReadAt(hdr[:], 0); err == nil && binary.BigEndian.Uint32(hdr[:4]) == magicFat {
		return openFat(base, raw, binary.BigEndian.Uint32(hdr[4:8]))
	}
	t := base
	t.Format = MachO
	if mf, err := macho.NewFile(raw); err == nil {
		t.MachO = mf
		t.Arch = ArchName(mf.Cpu, mf.SubCpu)
	}
	return []*Target{&t}
}

// openFat parses the fat header itself (rather than macho.NewFatFile) so one
// unparsable slice does not hide the others.
func openFat(base Target, raw *os.File, narch uint32) []*Target {
	size := int64(-1)
	if fi, err := raw.Stat(); err == nil {
		size = fi.Size()
	}
	out := make([]*Target, 0, narch)
	for i := uint32(0); i < narch; i++ {
		var arch [fatArchLen]byte
		if _, err := raw.ReadAt(arch[:], int64(fatHdrLen+i*fatArchLen)); err != nil {
			break
		}
		cpu := macho.Cpu(binary.BigEndian.Uint32(arch[0:4]))
		sub := binary.BigEndian.Uint32(arch[4:8])
		off := int64(binary.BigEndian.Uint32(arch[8:12]))
		sz := int64(binary.BigEndian.Uint32(arch[12:16]))

		t := base
		t.Format = MachO
		t.Fat = true
		t.Arch = ArchName(cpu, sub)
		if size < 0 || (off >= 0 && sz > 0 && off+sz <= size) {
			if mf, err := macho.NewFile(io.NewSectionReader(raw, off, sz)); err == nil {
				t.MachO = mf
			}
		}
		out = append(out, &t)
	}
	if len(out) == 0 {
		t := base
		t.Format = MachO
		out = append(out, &t)
	}
	return out
}
