// pkg/target/target_test.go
package target

import (
	"bytes"
	"debug/macho"
	"encoding/base64"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const elfFixture = "../../tests/binaries/output/none"

// stdlibMachO decodes a base64 fixture shipped with Go's debug/macho testdata.
func stdlibMachO(t *testing.T, name string) []byte {
	t.Helper()
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Skipf("go env GOROOT: %v", err)
	}
	p := filepath.Join(strings.TrimSpace(string(out)), "src", "debug", "macho", "testdata", name+".base64")
	enc, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("stdlib fixture %q missing: %v", name, err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(enc))
	if err != nil {
		t.Fatalf("decode %q: %v", name, err)
	}
	return raw
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// peHeader builds the smallest byte string Detect should call PE: "MZ",
// e_lfanew at offset 0x3c pointing to "PE\0\0".
func peHeader() []byte {
	b := make([]byte, 0x44)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x40)
	copy(b[0x40:], "PE\x00\x00")
	return b
}

func TestDetect(t *testing.T) {
	elfData, err := os.ReadFile(elfFixture)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	cases := []struct {
		name string
		data []byte
		want Format
	}{
		{"elf", elfData, ELF},
		{"thin macho", stdlibMachO(t, "gcc-amd64-darwin-exec"), MachO},
		{"fat macho", stdlibMachO(t, "fat-gcc-386-amd64-darwin-exec"), MachO},
		{"pe", peHeader(), PE},
		{"java class", []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x41, 0, 0, 0, 0}, Unknown},
		{"text", []byte("hello world, not a binary\n"), Unknown},
		{"empty", nil, Unknown},
		{"three bytes", []byte{0x7f, 'E', 'L'}, Unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Detect(bytes.NewReader(tc.data)); got != tc.want {
				t.Errorf("Detect = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOpen_ThinELF(t *testing.T) {
	if _, err := os.Stat(elfFixture); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	targets, err := Open(elfFixture)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer targets[0].Close()
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
	tg := targets[0]
	if tg.Format != ELF || tg.ELF == nil || tg.MachO != nil || tg.Fat {
		t.Errorf("unexpected target: %+v", tg)
	}
	if tg.Raw == nil {
		t.Error("Raw descriptor must be set")
	}
}

func TestOpen_ThinMachO(t *testing.T) {
	p := writeTemp(t, stdlibMachO(t, "clang-amd64-darwin-exec-with-rpath"))
	targets, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer targets[0].Close()
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
	tg := targets[0]
	if tg.Format != MachO || tg.MachO == nil || tg.ELF != nil || tg.Fat {
		t.Errorf("unexpected target: %+v", tg)
	}
	if tg.Arch != "x86_64" {
		t.Errorf("Arch = %q, want x86_64", tg.Arch)
	}
}

func TestOpen_FatMachO(t *testing.T) {
	p := writeTemp(t, stdlibMachO(t, "fat-gcc-386-amd64-darwin-exec"))
	targets, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer targets[0].Close()
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
	want := []string{"i386", "x86_64"}
	for i, tg := range targets {
		if tg.Format != MachO || tg.MachO == nil || !tg.Fat {
			t.Errorf("slice %d: unexpected target %+v", i, tg)
		}
		if tg.Arch != want[i] {
			t.Errorf("slice %d Arch = %q, want %q", i, tg.Arch, want[i])
		}
		if tg.Raw != targets[0].Raw {
			t.Errorf("slice %d must share the descriptor", i)
		}
	}
	// Close is idempotent and safe from any slice.
	targets[1].Close()
	targets[0].Close()
}

// Review Focus 1: a fat header whose slice offsets run past EOF yields a
// Target per slice with MachO nil, no panic, no error.
func TestOpen_FatWithBadSliceOffsets(t *testing.T) {
	b := make([]byte, 8+2*20)
	binary.BigEndian.PutUint32(b[0:], 0xcafebabe)
	binary.BigEndian.PutUint32(b[4:], 2)
	// arch 0: arm64 at an offset far past EOF
	binary.BigEndian.PutUint32(b[8:], uint32(macho.CpuArm64))
	binary.BigEndian.PutUint32(b[12:], 0)
	binary.BigEndian.PutUint32(b[16:], 0x10000000)
	binary.BigEndian.PutUint32(b[20:], 0x1000)
	// arch 1: x86_64 with size past EOF
	binary.BigEndian.PutUint32(b[28:], uint32(macho.CpuAmd64))
	binary.BigEndian.PutUint32(b[32:], 3)
	binary.BigEndian.PutUint32(b[36:], 48)
	binary.BigEndian.PutUint32(b[40:], 0xffffffff)
	p := writeTemp(t, b)

	targets, err := Open(p)
	if err != nil {
		t.Fatalf("Open must not error on bad slices: %v", err)
	}
	defer targets[0].Close()
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
	if targets[0].Arch != "arm64" || targets[1].Arch != "x86_64" {
		t.Errorf("arch from fat header: %q %q", targets[0].Arch, targets[1].Arch)
	}
	for i, tg := range targets {
		if tg.Format != MachO || tg.MachO != nil || !tg.Fat {
			t.Errorf("slice %d: want MachO/nil/Fat, got %+v", i, tg)
		}
	}
}

func TestOpen_Unknown(t *testing.T) {
	p := writeTemp(t, []byte("plain text"))
	targets, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer targets[0].Close()
	if len(targets) != 1 || targets[0].Format != Unknown {
		t.Fatalf("want one Unknown target, got %+v", targets)
	}
}

func TestOpen_PEIsDetectedButNotParsed(t *testing.T) {
	p := writeTemp(t, peHeader())
	targets, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer targets[0].Close()
	if len(targets) != 1 || targets[0].Format != PE || targets[0].ELF != nil || targets[0].MachO != nil {
		t.Fatalf("want one PE target with no parsed view, got %+v", targets)
	}
}

func TestOpen_MissingFile(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSupported(t *testing.T) {
	if !Supported(ELF) || !Supported(MachO) {
		t.Error("ELF and MachO must be supported")
	}
	if Supported(PE) || Supported(Unknown) {
		t.Error("PE and Unknown must not be supported in this piece")
	}
}

func TestArchName(t *testing.T) {
	cases := []struct {
		cpu  macho.Cpu
		sub  uint32
		want string
	}{
		{macho.CpuAmd64, 3, "x86_64"},
		{macho.Cpu386, 3, "i386"},
		{macho.CpuArm64, 0, "arm64"},
		{macho.CpuArm64, 2, "arm64e"},
		{macho.CpuArm64, 0x80000002, "arm64e"},
		{macho.CpuArm, 9, "arm"},
		{macho.CpuPpc, 0, "ppc"},
		{macho.CpuPpc64, 0, "ppc64"},
		{macho.Cpu(99), 0, "cpu-99"},
	}
	for _, tc := range cases {
		if got := ArchName(tc.cpu, tc.sub); got != tc.want {
			t.Errorf("ArchName(%v,%#x) = %q, want %q", tc.cpu, tc.sub, got, tc.want)
		}
	}
}
