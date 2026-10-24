// pkg/macho/entitlements_test.go
package macho

import (
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

const plistHdr = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">`

func TestParseEntitlementsXML_TopLevelBooleans(t *testing.T) {
	x := plistHdr + `<dict>
  <key>com.apple.security.get-task-allow</key><true/>
  <key>com.apple.security.cs.allow-jit</key><false/>
  <key>com.apple.application-identifier</key><string>TEAM.com.example</string>
</dict></plist>`
	m := parseEntitlementsXML([]byte(x))
	if !m["com.apple.security.get-task-allow"] {
		t.Error("get-task-allow must be true")
	}
	if v, ok := m["com.apple.security.cs.allow-jit"]; !ok || v {
		t.Errorf("allow-jit must be present and false, got %v/%v", v, ok)
	}
	if _, ok := m["com.apple.application-identifier"]; ok {
		t.Error("string-valued key must not be reported as a boolean")
	}
}

// Review Focus 3: booleans nested inside a dict or array value must not be
// attributed to the enclosing key or to a sibling.
func TestParseEntitlementsXML_IgnoresNested(t *testing.T) {
	x := plistHdr + `<dict>
  <key>com.apple.security.cs.disable-library-validation</key>
  <dict><key>com.apple.security.get-task-allow</key><true/></dict>
  <key>keychain-access-groups</key>
  <array><string>x</string><true/></array>
</dict></plist>`
	m := parseEntitlementsXML([]byte(x))
	if m["com.apple.security.get-task-allow"] {
		t.Error("nested get-task-allow leaked to top level")
	}
	if m["com.apple.security.cs.disable-library-validation"] {
		t.Error("dict-valued key reported true")
	}
	if m["keychain-access-groups"] {
		t.Error("array-valued key reported true")
	}
}

func TestParseEntitlementsXML_Garbage(t *testing.T) {
	for _, in := range []string{"", "<", "<plist><dict><key>a</key>", "\xff\xfe\x00"} {
		_ = parseEntitlementsXML([]byte(in)) // must not panic
	}
}

// DER: SEQUENCE { UTF8String "k", BOOLEAN true } nested in APPLICATION 16.
func TestParseEntitlementsDER(t *testing.T) {
	kv := func(key string, val byte) []byte {
		k := append([]byte{0x0c, byte(len(key))}, key...)
		v := []byte{0x01, 0x01, val}
		inner := append(k, v...)
		return append([]byte{0x30, byte(len(inner))}, inner...)
	}
	set := append(kv("com.apple.security.get-task-allow", 0xff), kv("com.apple.security.cs.allow-jit", 0x00)...)
	set = append([]byte{0x31, byte(len(set))}, set...)
	seq := append([]byte{0x02, 0x01, 0x01}, set...)
	seq = append([]byte{0x30, byte(len(seq))}, seq...)
	der := append([]byte{0x70, byte(len(seq))}, seq...)

	m := parseEntitlementsDER(der)
	if !m["com.apple.security.get-task-allow"] {
		t.Errorf("get-task-allow missing: %v", m)
	}
	if v, ok := m["com.apple.security.cs.allow-jit"]; !ok || v {
		t.Errorf("allow-jit must be present and false: %v", m)
	}
	for _, in := range [][]byte{nil, {0x30}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, {0x0c, 0x05, 'a'}} {
		_ = parseEntitlementsDER(in) // must not panic
	}
}

func TestClassifyEntitlements(t *testing.T) {
	cases := []struct {
		m      map[string]bool
		want   string
		status checksec.Status
	}{
		{map[string]bool{}, "None", checksec.StatusGood},
		{map[string]bool{"com.apple.security.cs.allow-jit": true}, "allow-jit", checksec.StatusInfo},
		{map[string]bool{"com.apple.security.cs.allow-unsigned-executable-memory": true}, "allow-unsigned-executable-memory", checksec.StatusWarn},
		{map[string]bool{"com.apple.security.get-task-allow": true, "com.apple.security.cs.allow-jit": true}, "get-task-allow, allow-jit", checksec.StatusBad},
		{map[string]bool{"com.apple.security.cs.debugger": true}, "debugger", checksec.StatusBad},
		{map[string]bool{"com.apple.security.get-task-allow": false, "other.key": true}, "None", checksec.StatusGood},
	}
	for _, tc := range cases {
		if v, s := classifyEntitlements(tc.m); v != tc.want || s != tc.status {
			t.Errorf("classifyEntitlements(%v) = %q/%q, want %q/%q", tc.m, v, s, tc.want, tc.status)
		}
	}
}

func TestEntitlements_Fixtures(t *testing.T) {
	r := Entitlements(loadFixture(t, "debuggable_arm64"))
	if r.Status != checksec.StatusBad || !strings.Contains(r.Value, "get-task-allow") || !strings.Contains(r.Value, "disable-library-validation") {
		t.Errorf("debuggable: %+v", r)
	}
	if strings.Contains(r.Value, "allow-jit") {
		t.Errorf("allow-jit is <false/> in the fixture plist and must not appear: %+v", r)
	}
	if r := Entitlements(loadFixture(t, "hardened_arm64")); r.Value != "None" || r.Status != checksec.StatusGood {
		t.Errorf("hardened (no entitlements): %+v", r)
	}
	if r := Entitlements(loadFixture(t, "unsigned_arm64")); r.Value != "N/A" || r.Status != checksec.StatusNA {
		t.Errorf("unsigned: %+v", r)
	}
}
