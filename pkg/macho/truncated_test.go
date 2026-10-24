package macho

import (
	dm "debug/macho"
	"encoding/binary"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// Load commands shorter than their fixed fields are reported, never indexed.
func TestTruncatedLoadCommands(t *testing.T) {
	env := syntheticMachO(t, uint32(dm.TypeExec), 0, lc(lcDyldEnvironment, nil))
	if r := DyldEnv(env); r.Value != "(malformed)" || r.Status != checksec.StatusBad {
		t.Errorf("8-byte LC_DYLD_ENVIRONMENT: %+v", r)
	}
	legacy := syntheticMachO(t, uint32(dm.TypeExec), 0, lc(lcVersionMinMacOSX, nil))
	if r := MinOS(legacy); r.Value != "Unknown" || r.Status != checksec.StatusWarn {
		t.Errorf("8-byte LC_VERSION_MIN_MACOSX: %+v", r)
	}
	sig := syntheticMachO(t, uint32(dm.TypeExec), 0, lc(lcCodeSignature, nil))
	if r := Signature(sig); r.Value != "Malformed" || r.Status != checksec.StatusWarn {
		t.Errorf("8-byte LC_CODE_SIGNATURE: %+v", r)
	}
	if r := HardenedRuntime(sig); r.Value != "N/A" {
		t.Errorf("hardened on truncated signature command: %+v", r)
	}
}

// Every CodeDirectory bound is checked: header length, team-offset room, and
// both string offsets.
func TestParseSuperBlob_CodeDirectoryBounds(t *testing.T) {
	wrap := func(cd []byte) []byte {
		return superBlob(map[uint32][]byte{csSlotCodeDirectory: cd})
	}

	short := blob(csMagicCodeDirectory, make([]byte, 12))
	if _, err := parseSuperBlob(wrap(short)); err == nil {
		t.Error("20-byte CodeDirectory must error")
	}

	// Version 0x20200 promises a teamOffset field the blob does not contain.
	noRoom := codeDirectory(0, "id", "")
	binary.BigEndian.PutUint32(noRoom[8:], 0x20200)
	if _, err := parseSuperBlob(wrap(noRoom)); err == nil {
		t.Error("v0x20200 CodeDirectory without teamOffset room must error")
	}

	badTeam := codeDirectory(0, "id", "TEAM")
	binary.BigEndian.PutUint32(badTeam[48:], 0xffff)
	if _, err := parseSuperBlob(wrap(badTeam)); err == nil {
		t.Error("teamOffset outside the blob must error")
	}

	badIdent := codeDirectory(0, "id", "")
	binary.BigEndian.PutUint32(badIdent[20:], 0xffff)
	if _, err := parseSuperBlob(wrap(badIdent)); err == nil {
		t.Error("identOffset outside the blob must error")
	}

	// Drop the terminating NUL so the identifier runs off the end of the blob.
	unterminated := codeDirectory(0, "id", "")
	unterminated = unterminated[:len(unterminated)-1]
	binary.BigEndian.PutUint32(unterminated[4:], uint32(len(unterminated)))
	if _, err := parseSuperBlob(wrap(unterminated)); err == nil {
		t.Error("unterminated identifier must error")
	}

	// Sanity: the untouched builder output still parses.
	info, err := parseSuperBlob(wrap(codeDirectory(0, "id", "TEAM")))
	if err != nil || info.Ident != "id" || info.TeamID != "TEAM" {
		t.Errorf("baseline CodeDirectory: %+v, %v", info, err)
	}
}
