// pkg/macho/entitlements.go
package macho

import (
	"bytes"
	dm "debug/macho"
	"encoding/xml"
	"io"
	"strings"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// riskyEntitlement maps an entitlement that weakens the hardened runtime to
// its display name and the status it earns when set.
type riskyEntitlement struct {
	key    string
	label  string
	status checksec.Status
}

// Order is display order.
var riskyEntitlements = []riskyEntitlement{
	{"com.apple.security.get-task-allow", "get-task-allow", checksec.StatusBad},
	{"com.apple.security.cs.disable-library-validation", "disable-library-validation", checksec.StatusBad},
	{"com.apple.security.cs.allow-dyld-environment-variables", "allow-dyld-environment-variables", checksec.StatusBad},
	{"com.apple.security.cs.debugger", "debugger", checksec.StatusBad},
	{"com.apple.security.cs.allow-unsigned-executable-memory", "allow-unsigned-executable-memory", checksec.StatusWarn},
	{"com.apple.security.cs.allow-jit", "allow-jit", checksec.StatusInfo},
}

// severity orders statuses so the worst present entitlement wins.
func severity(s checksec.Status) int {
	switch s {
	case checksec.StatusBad:
		return 3
	case checksec.StatusWarn:
		return 2
	case checksec.StatusInfo:
		return 1
	}
	return 0
}

func classifyEntitlements(m map[string]bool) (string, checksec.Status) {
	var labels []string
	worst := checksec.StatusGood
	for _, e := range riskyEntitlements {
		if !m[e.key] {
			continue
		}
		labels = append(labels, e.label)
		if severity(e.status) > severity(worst) {
			worst = e.status
		}
	}
	if len(labels) == 0 {
		return "None", checksec.StatusGood
	}
	return strings.Join(labels, ", "), worst
}

// parseEntitlementsXML returns the top-level boolean keys of a plist. It walks
// tokens with a depth counter: a <key> at dict depth 1 followed directly by
// <true/> or <false/> at the same depth is recorded; anything nested is not.
func parseEntitlementsXML(b []byte) map[string]bool {
	out := map[string]bool{}
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = false
	depth := 0 // dict nesting depth; 1 == the top-level dict
	pendingKey := ""
	inKey := false
	for {
		tok, err := dec.Token()
		if err == io.EOF || err != nil {
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "dict":
				depth++
				pendingKey = ""
			case "array":
				depth += 100 // anything inside an array is never top level
				pendingKey = ""
			case "key":
				inKey = depth == 1
				if inKey {
					pendingKey = ""
				}
			case "true", "false":
				if depth == 1 && pendingKey != "" {
					out[pendingKey] = t.Name.Local == "true"
				}
				pendingKey = ""
			default:
				pendingKey = "" // string/integer/data/date value: not a boolean
			}
		case xml.CharData:
			if inKey {
				pendingKey += string(t) // key text may arrive as several tokens (e.g. CDATA)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "dict":
				depth--
			case "array":
				depth -= 100
			case "key":
				if inKey {
					pendingKey = strings.TrimSpace(pendingKey)
				}
				inKey = false
			}
		}
	}
}

// parseEntitlementsDER walks the DER entitlements blob as generic TLVs and
// records every SEQUENCE { UTF8String key, BOOLEAN value } pair it meets at
// any depth. The outer structure (APPLICATION 16, version INTEGER, SET) is
// traversed but not interpreted, which keeps the parser tolerant.
func parseEntitlementsDER(b []byte) map[string]bool {
	out := map[string]bool{}
	walkDER(b, out, 0)
	return out
}

const (
	derTagBoolean    = 0x01
	derTagUTF8String = 0x0c
	derTagSequence   = 0x10
	derConstructed   = 0x20
	derMaxDepth      = 16
)

// readTLV decodes one tag-length-value; ok is false on any malformation.
func readTLV(b []byte) (tag byte, val []byte, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	l := int(b[1])
	i := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return 0, nil, nil, false
		}
		l = 0
		for j := 0; j < n; j++ {
			l = l<<8 | int(b[2+j])
		}
		i += n
	}
	if l < 0 || len(b)-i < l {
		return 0, nil, nil, false
	}
	return tag, b[i : i+l], b[i+l:], true
}

func walkDER(b []byte, out map[string]bool, depth int) {
	if depth > derMaxDepth {
		return
	}
	for len(b) > 0 {
		tag, val, rest, ok := readTLV(b)
		if !ok {
			return
		}
		if tag&derConstructed != 0 {
			if tag&0x1f == derTagSequence {
				if k, v, isPair := keyBoolPair(val); isPair {
					out[k] = v
					b = rest
					continue
				}
			}
			walkDER(val, out, depth+1)
		}
		b = rest
	}
}

// keyBoolPair recognises SEQUENCE contents of exactly UTF8String + BOOLEAN.
func keyBoolPair(seq []byte) (string, bool, bool) {
	t1, k, rest, ok := readTLV(seq)
	if !ok || t1 != derTagUTF8String {
		return "", false, false
	}
	t2, v, rest, ok := readTLV(rest)
	if !ok || t2 != derTagBoolean || len(v) != 1 || len(rest) != 0 {
		return "", false, false
	}
	return string(k), v[0] != 0, true
}

// Entitlements reports the risky boolean entitlements present in the
// signature. XML is authoritative when present; DER is the fallback.
func Entitlements(f *dm.File) *checksec.Result {
	info := CodeSignature(f)
	if !info.Present || info.Malformed {
		return &checksec.Result{Value: "N/A", Status: checksec.StatusNA}
	}
	var m map[string]bool
	switch {
	case len(info.EntitlementsXML) > 0:
		m = parseEntitlementsXML(info.EntitlementsXML)
	case len(info.EntitlementsDER) > 0:
		m = parseEntitlementsDER(info.EntitlementsDER)
	default:
		m = map[string]bool{}
	}
	v, s := classifyEntitlements(m)
	return &checksec.Result{Value: v, Status: s}
}
