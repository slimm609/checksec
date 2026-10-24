package macho

import (
	dm "debug/macho"
	"fmt"
)

// Load command ids debug/macho does not type. All values from <mach-o/loader.h>.
const (
	lcCodeSignature     uint32 = 0x1d
	lcEncryptionInfo    uint32 = 0x21
	lcEncryptionInfo64  uint32 = 0x2c
	lcDyldEnvironment   uint32 = 0x27
	lcVersionMinMacOSX  uint32 = 0x24
	lcVersionMinIPhone  uint32 = 0x25
	lcVersionMinTvOS    uint32 = 0x2f
	lcVersionMinWatchOS uint32 = 0x30
	lcBuildVersion      uint32 = 0x32
	lcDyldChainedFixups uint32 = 0x80000034
)

// rawLoad is one load command as it appears in the file: Cmd plus the whole
// command bytes (header included), so payload fields are at fixed offsets.
type rawLoad struct {
	Cmd  uint32
	Data []byte
}

// rawLoads returns every load command. debug/macho exposes Raw() on all Load
// implementations, so typed loads (segments, symtab) are included too.
func rawLoads(f *dm.File) []rawLoad {
	out := make([]rawLoad, 0, len(f.Loads))
	for _, l := range f.Loads {
		b := l.Raw()
		if len(b) < 8 {
			continue
		}
		out = append(out, rawLoad{Cmd: f.ByteOrder.Uint32(b[0:4]), Data: b})
	}
	return out
}

// findLoad returns the first load command with the given id.
func findLoad(f *dm.File, cmd uint32) (rawLoad, bool) {
	for _, l := range rawLoads(f) {
		if l.Cmd == cmd {
			return l, true
		}
	}
	return rawLoad{}, false
}

// linkeditData reads the payload a linkedit_data_command (dataoff, datasize at
// bytes 8 and 12) points at, through the __LINKEDIT segment's ReaderAt. ok is
// false when the command is absent. err is non-nil when the command is
// truncated, __LINKEDIT is missing, or the range falls outside it.
func linkeditData(f *dm.File, cmd uint32) ([]byte, bool, error) {
	l, ok := findLoad(f, cmd)
	if !ok {
		return nil, false, nil
	}
	if len(l.Data) < 16 {
		return nil, true, fmt.Errorf("load command %#x truncated (%d bytes)", cmd, len(l.Data))
	}
	off := uint64(f.ByteOrder.Uint32(l.Data[8:12]))
	size := uint64(f.ByteOrder.Uint32(l.Data[12:16]))
	seg := f.Segment("__LINKEDIT")
	if seg == nil {
		return nil, true, fmt.Errorf("no __LINKEDIT segment")
	}
	if off < seg.Offset || off+size > seg.Offset+seg.Filesz || size == 0 {
		return nil, true, fmt.Errorf("linkedit range %#x+%#x outside __LINKEDIT", off, size)
	}
	buf := make([]byte, size)
	if _, err := seg.ReadAt(buf, int64(off-seg.Offset)); err != nil {
		return nil, true, err
	}
	return buf, true, nil
}
