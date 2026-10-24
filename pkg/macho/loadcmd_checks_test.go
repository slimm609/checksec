package macho

import (
	dm "debug/macho"
	"encoding/binary"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func u32s(vals ...uint32) []byte {
	b := make([]byte, 4*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[4*i:], v)
	}
	return b
}

func TestEncrypted(t *testing.T) {
	if r := Encrypted(loadFixture(t, "exec_arm64")); r.Value != "Not encrypted" || r.Status != checksec.StatusInfo {
		t.Errorf("default: %+v", r)
	}
	// encryption_info_command_64: cryptoff, cryptsize, cryptid, pad
	enc := syntheticMachO(t, uint32(dm.TypeExec), 0, lc(lcEncryptionInfo64, u32s(0x4000, 0x8000, 1, 0)))
	if r := Encrypted(enc); r.Value != "Encrypted" || r.Status != checksec.StatusInfo {
		t.Errorf("cryptid=1: %+v", r)
	}
	clear := syntheticMachO(t, uint32(dm.TypeExec), 0, lc(lcEncryptionInfo64, u32s(0x4000, 0x8000, 0, 0)))
	if r := Encrypted(clear); r.Value != "Not encrypted" {
		t.Errorf("cryptid=0: %+v", r)
	}
	short := syntheticMachO(t, uint32(dm.TypeExec), 0, lc(lcEncryptionInfo, u32s(0x4000)))
	if r := Encrypted(short); r.Value != "Not encrypted" {
		t.Errorf("truncated command must not be read as encrypted: %+v", r)
	}
}

func TestFixups(t *testing.T) {
	if r := Fixups(loadFixture(t, "exec_arm64")); r.Value != "Chained fixups" || r.Status != checksec.StatusGood {
		t.Errorf("default: %+v", r)
	}
	if r := Fixups(loadFixture(t, "lazy_arm64")); r.Value != "Lazy binding" || r.Status != checksec.StatusWarn {
		t.Errorf("lazy: %+v", r)
	}
	if r := Fixups(loadFixture(t, "obj.o")); r.Value != "N/A" || r.Status != checksec.StatusNA {
		t.Errorf("object: %+v", r)
	}
	// No chained fixups, no lazy pointers, MH_BINDATLOAD set.
	f := syntheticMachO(t, uint32(dm.TypeExec), dm.FlagBindAtLoad)
	if r := Fixups(f); r.Value != "Bind at load" || r.Status != checksec.StatusGood {
		t.Errorf("bind at load: %+v", r)
	}
	// Nothing at all: no imports to bind lazily.
	if r := Fixups(syntheticMachO(t, uint32(dm.TypeExec), 0)); r.Value != "Bind at load" {
		t.Errorf("no lazy pointers: %+v", r)
	}
}

func TestDyldEnv(t *testing.T) {
	if r := DyldEnv(loadFixture(t, "exec_arm64")); r.Value != "None" || r.Status != checksec.StatusGood {
		t.Errorf("default: %+v", r)
	}
	r := DyldEnv(loadFixture(t, "dyldenv_arm64"))
	if r.Value != "DYLD_INSERT_LIBRARIES=/tmp/x.dylib" || r.Status != checksec.StatusBad {
		t.Errorf("dyldenv: %+v", r)
	}
	// Two commands join with "; ". dylinker_command: name offset 12 then string.
	mk := func(s string) []byte { return lc(lcDyldEnvironment, append(u32s(12), append([]byte(s), 0)...)) }
	f := syntheticMachO(t, uint32(dm.TypeExec), 0, mk("A=1"), mk("B=2"))
	if r := DyldEnv(f); r.Value != "A=1; B=2" {
		t.Errorf("two commands: %+v", r)
	}
	// Name offset past the command: reported, not crashed.
	bad := syntheticMachO(t, uint32(dm.TypeExec), 0, lc(lcDyldEnvironment, u32s(0x400)))
	if r := DyldEnv(bad); r.Status != checksec.StatusBad || r.Value != "(malformed)" {
		t.Errorf("bad offset: %+v", r)
	}
}

func TestRestrict(t *testing.T) {
	if r := Restrict(loadFixture(t, "restrict_arm64")); r.Value != "Enabled" || r.Status != checksec.StatusGood {
		t.Errorf("restrict: %+v", r)
	}
	if r := Restrict(loadFixture(t, "exec_arm64")); r.Value != "No Restrict" || r.Status != checksec.StatusInfo {
		t.Errorf("default: %+v", r)
	}
}

func TestARC(t *testing.T) {
	if r := ARC(loadFixture(t, "arc_arm64")); r.Value != "ARC" || r.Status != checksec.StatusGood {
		t.Errorf("arc: %+v", r)
	}
	if r := ARC(loadFixture(t, "noarc_arm64")); r.Value != "No ARC" || r.Status != checksec.StatusWarn {
		t.Errorf("noarc: %+v", r)
	}
	if r := ARC(loadFixture(t, "exec_arm64")); r.Value != "N/A" || r.Status != checksec.StatusNA {
		t.Errorf("plain C: %+v", r)
	}
}

func TestMinOS(t *testing.T) {
	if r := MinOS(loadFixture(t, "minos13_arm64")); r.Value != "macOS 13.0" || r.Status != checksec.StatusInfo {
		t.Errorf("build version: %+v", r)
	}
	// LC_VERSION_MIN_IPHONEOS: version 0x000f0200 = 15.2, sdk.
	f := syntheticMachO(t, uint32(dm.TypeExec), 0, lc(lcVersionMinIPhone, u32s(0x000f0200, 0x00100000)))
	if r := MinOS(f); r.Value != "iOS 15.2" {
		t.Errorf("version_min: %+v", r)
	}
	// Review Focus 4: a build_version command shorter than its fields.
	short := syntheticMachO(t, uint32(dm.TypeExec), 0, lc(lcBuildVersion, u32s(1)))
	if r := MinOS(short); r.Value != "Unknown" || r.Status != checksec.StatusWarn {
		t.Errorf("truncated: %+v", r)
	}
	if r := MinOS(syntheticMachO(t, uint32(dm.TypeExec), 0)); r.Value != "Unknown" {
		t.Errorf("absent: %+v", r)
	}
}

func TestFormatVersionAndPlatform(t *testing.T) {
	cases := map[uint32]string{0x000d0000: "13.0", 0x000f0201: "15.2.1", 0x00100000: "16.0"}
	for in, want := range cases {
		if got := formatVersion(in); got != want {
			t.Errorf("formatVersion(%#x) = %q, want %q", in, got, want)
		}
	}
	plats := map[uint32]string{1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "macCatalyst", 11: "visionOS", 99: "platform 99"}
	for in, want := range plats {
		if got := platformName(in); got != want {
			t.Errorf("platformName(%d) = %q, want %q", in, got, want)
		}
	}
}
