// pkg/macho/signature.go
package macho

import (
	"bytes"
	dm "debug/macho"
	"encoding/binary"
	"fmt"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// Code-signing constants from Security framework <cs_blobs.h>. All blob
// fields are big-endian regardless of the image's byte order.
const (
	csMagicEmbeddedSignature uint32 = 0xfade0cc0
	csMagicCodeDirectory     uint32 = 0xfade0c02
	csMagicEntitlements      uint32 = 0xfade7171
	csMagicEntitlementsDER   uint32 = 0xfade7172
	csMagicBlobWrapper       uint32 = 0xfade0b01

	csSlotCodeDirectory   uint32 = 0
	csSlotEntitlements    uint32 = 5
	csSlotEntitlementsDER uint32 = 7
	csSlotSignature       uint32 = 0x10000

	csFlagAdhoc        uint32 = 0x2
	csFlagRuntime      uint32 = 0x10000
	csFlagLinkerSigned uint32 = 0x20000

	maxSuperBlobSlots = 64
)

// CodeSignatureInfo is what checksec extracts from LC_CODE_SIGNATURE. It
// describes structure only; no signature, certificate, or hash is verified.
type CodeSignatureInfo struct {
	Present         bool
	Malformed       bool
	Flags           uint32
	Ident           string
	TeamID          string
	HasCMS          bool
	CMSEmpty        bool
	EntitlementsXML []byte
	EntitlementsDER []byte
}

// CodeSignature locates and parses the embedded signature. Absence is not an
// error; a present but unparsable blob sets Malformed.
func CodeSignature(f *dm.File) CodeSignatureInfo {
	data, ok, err := linkeditData(f, lcCodeSignature)
	if !ok {
		return CodeSignatureInfo{}
	}
	if err != nil {
		return CodeSignatureInfo{Present: true, Malformed: true}
	}
	info, err := parseSuperBlob(data)
	if err != nil {
		return CodeSignatureInfo{Present: true, Malformed: true}
	}
	info.Present = true
	return info
}

// cString returns the NUL-terminated string starting at off, or an error when
// off is outside b or no terminator exists.
func cString(b []byte, off uint32) (string, error) {
	if uint64(off) >= uint64(len(b)) {
		return "", fmt.Errorf("string offset %#x outside blob of %d bytes", off, len(b))
	}
	rest := b[off:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return "", fmt.Errorf("unterminated string at %#x", off)
	}
	return string(rest[:i]), nil
}

// slice returns b[off:off+n] with every bound checked.
func slice(b []byte, off, n uint32) ([]byte, error) {
	end := uint64(off) + uint64(n)
	if uint64(off) > uint64(len(b)) || end > uint64(len(b)) {
		return nil, fmt.Errorf("range %#x+%#x outside blob of %d bytes", off, n, len(b))
	}
	return b[off:end], nil
}

// parseSuperBlob walks a CSMAGIC_EMBEDDED_SIGNATURE SuperBlob and its
// CodeDirectory. Every offset and length is validated against the input.
func parseSuperBlob(b []byte) (CodeSignatureInfo, error) {
	var info CodeSignatureInfo
	be := binary.BigEndian
	if len(b) < 12 {
		return info, fmt.Errorf("superblob too short: %d bytes", len(b))
	}
	if be.Uint32(b[0:4]) != csMagicEmbeddedSignature {
		return info, fmt.Errorf("bad superblob magic %#x", be.Uint32(b[0:4]))
	}
	total := be.Uint32(b[4:8])
	if uint64(total) > uint64(len(b)) || total < 12 {
		return info, fmt.Errorf("superblob length %d outside %d-byte input", total, len(b))
	}
	b = b[:total]
	count := be.Uint32(b[8:12])
	if count > maxSuperBlobSlots || uint64(12+8*count) > uint64(len(b)) {
		return info, fmt.Errorf("superblob index count %d does not fit", count)
	}
	sawCD := false
	for i := uint32(0); i < count; i++ {
		typ := be.Uint32(b[12+8*i:])
		off := be.Uint32(b[16+8*i:])
		hdr, err := slice(b, off, 8)
		if err != nil {
			return info, err
		}
		magic := be.Uint32(hdr[0:4])
		length := be.Uint32(hdr[4:8])
		if length < 8 {
			return info, fmt.Errorf("blob %d length %d too small", i, length)
		}
		body, err := slice(b, off, length)
		if err != nil {
			return info, err
		}
		switch typ {
		case csSlotCodeDirectory:
			if magic != csMagicCodeDirectory {
				return info, fmt.Errorf("code directory slot has magic %#x", magic)
			}
			if err := parseCodeDirectory(body, &info); err != nil {
				return info, err
			}
			sawCD = true
		case csSlotEntitlements:
			if magic == csMagicEntitlements {
				info.EntitlementsXML = body[8:]
			}
		case csSlotEntitlementsDER:
			if magic == csMagicEntitlementsDER {
				info.EntitlementsDER = body[8:]
			}
		case csSlotSignature:
			info.HasCMS = true
			info.CMSEmpty = length == 8
		}
	}
	if !sawCD {
		return info, fmt.Errorf("superblob has no CodeDirectory")
	}
	return info, nil
}

// parseCodeDirectory reads version, flags, identifier and (v>=0x20200) team id.
func parseCodeDirectory(cd []byte, info *CodeSignatureInfo) error {
	be := binary.BigEndian
	if len(cd) < 44 {
		return fmt.Errorf("code directory too short: %d bytes", len(cd))
	}
	version := be.Uint32(cd[8:12])
	info.Flags = be.Uint32(cd[12:16])
	ident, err := cString(cd, be.Uint32(cd[20:24]))
	if err != nil {
		return err
	}
	info.Ident = ident
	if version >= 0x20200 {
		if len(cd) < 52 {
			return fmt.Errorf("code directory v%#x too short for team offset", version)
		}
		if teamOff := be.Uint32(cd[48:52]); teamOff != 0 {
			team, err := cString(cd, teamOff)
			if err != nil {
				return err
			}
			info.TeamID = team
		}
	}
	return nil
}

func classifySignature(info CodeSignatureInfo) (string, checksec.Status) {
	switch {
	case !info.Present:
		return "Unsigned", checksec.StatusBad
	case info.Malformed:
		return "Malformed", checksec.StatusWarn
	case info.Flags&csFlagLinkerSigned != 0:
		return "Linker-signed", checksec.StatusWarn
	case info.Flags&csFlagAdhoc != 0, !info.HasCMS, info.CMSEmpty:
		return "Ad-hoc", checksec.StatusWarn
	case info.TeamID != "":
		return fmt.Sprintf("Signed [%s]", info.TeamID), checksec.StatusGood
	}
	return "Signed", checksec.StatusGood
}

// Signature reports the kind of embedded code signature (structure, not trust).
func Signature(f *dm.File) *checksec.Result {
	v, s := classifySignature(CodeSignature(f))
	return &checksec.Result{Value: v, Status: s}
}

// HardenedRuntime reports CS_RUNTIME in the CodeDirectory flags.
func HardenedRuntime(f *dm.File) *checksec.Result {
	info := CodeSignature(f)
	if !info.Present || info.Malformed {
		return &checksec.Result{Value: "N/A", Status: checksec.StatusNA}
	}
	if info.Flags&csFlagRuntime != 0 {
		return &checksec.Result{Value: "Enabled", Status: checksec.StatusGood}
	}
	return &checksec.Result{Value: "Disabled", Status: checksec.StatusBad}
}
