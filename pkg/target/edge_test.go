package target

import (
	"bytes"
	"testing"
)

func TestDetect_MZWithoutPESignature(t *testing.T) {
	// "MZ" whose e_lfanew points at bytes that are not "PE\0\0".
	noSig := peHeader()
	copy(noSig[0x40:], "XX\x00\x00")
	if got := Detect(bytes.NewReader(noSig)); got != Unknown {
		t.Errorf("MZ without PE signature: %q, want unknown", got)
	}
	// "MZ" whose e_lfanew points past the end of the file.
	short := peHeader()[:0x40]
	if got := Detect(bytes.NewReader(short)); got != Unknown {
		t.Errorf("MZ with e_lfanew past EOF: %q, want unknown", got)
	}
}

func TestOpen_FatWithTruncatedArchTable(t *testing.T) {
	// The fat header claims one arch but the file ends before the fat_arch entry.
	p := writeTemp(t, []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1})
	targets, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer targets[0].Close()
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1 placeholder", len(targets))
	}
	if targets[0].Format != MachO || targets[0].MachO != nil {
		t.Errorf("placeholder must be MachO with nil parse: %+v", targets[0])
	}
}

func TestClose_NilSafe(t *testing.T) {
	var tg *Target
	tg.Close() // must not panic
	(&Target{}).Close()
}
