package utils

import (
	"debug/elf"
	"encoding/json"
	"strings"
	"testing"
)

type stubRes struct{ Output, Color string }
type stubFortify struct{ Output, Color, Fortified, Fortifiable string }

func TestRunFileChecks_UsesHooksAndAggregates(t *testing.T) {
	origGetBinary := getBinaryFn
	origRelro, origCanary, origCfi, origNx, origPie := relroFn, canaryFn, cfiFn, nxFn, pieFn
	origRpath, origRunpath, origSymbols, origFortify := rpathFn, runpathFn, symbolsFn, fortifyFn
	defer func() {
		getBinaryFn = origGetBinary
		relroFn, canaryFn, cfiFn, nxFn, pieFn = origRelro, origCanary, origCfi, origNx, origPie
		rpathFn, runpathFn, symbolsFn, fortifyFn = origRpath, origRunpath, origSymbols, origFortify
	}()

	getBinaryFn = func(string) *elf.File { return nil }
	relroFn = func(string) interface{} { return &stubRes{Output: "Full RELRO", Color: "green"} }
	canaryFn = func(string) interface{} { return &stubRes{Output: "Canary Found", Color: "green"} }
	cfiFn = func(string) interface{} { return &stubRes{Output: "SHSTK & IBT", Color: "green"} }
	nxFn = func(string, interface{}) interface{} { return &stubRes{Output: "NX enabled", Color: "green"} }
	pieFn = func(string, interface{}) interface{} { return &stubRes{Output: "PIE Enabled", Color: "green"} }
	rpathFn = func(string) interface{} { return &stubRes{Output: "No RPATH", Color: "green"} }
	runpathFn = func(string) interface{} { return &stubRes{Output: "No RUNPATH", Color: "green"} }
	symbolsFn = func(string) interface{} { return &stubRes{Output: "0 symbols", Color: "green"} }
	fortifyFn = func(string, interface{}, string) interface{} {
		return &stubFortify{Output: "Yes", Color: "green", Fortified: "2", Fortifiable: "3"}
	}

	data, colors := RunFileChecks("/tmp/bin", "")

	b, _ := json.Marshal(data)
	s := string(b)
	mustContain := []string{"Full RELRO", "Canary Found", "SHSTK", "NX enabled", "PIE Enabled", "No RPATH", "No RUNPATH", "0 symbols", "\"fortified\":\"2\"", "\"fortifyable\":\"3\""}
	for _, m := range mustContain {
		if !strings.Contains(s, m) {
			t.Fatalf("data missing %q in %s", m, s)
		}
	}

	cb, _ := json.Marshal(colors)
	cs := string(cb)
	for _, m := range []string{"canaryColor", "cfiColor", "pieColor", "nxColor", "relroColor", "rpathColor", "runpathColor", "symbolsColor", "fortify_sourceColor"} {
		if !strings.Contains(cs, m) {
			t.Fatalf("colors missing %q in %s", m, cs)
		}
	}
}

func TestParseKernel_CombinesResults(t *testing.T) {
	origKernel, origSysctl := kernelConfigFn, sysctlCheckFn
	defer func() { kernelConfigFn, sysctlCheckFn = origKernel, origSysctl }()

	kernelConfigFn = func(string) ([]interface{}, []interface{}) {
		return []interface{}{map[string]any{"name": "K", "desc": "KD", "value": "Enabled", "type": "Kernel Config"}},
			[]interface{}{map[string]any{"name": "K", "desc": "KD", "value": "Enabled", "type": "Kernel Config", "color": "green"}}
	}
	sysctlCheckFn = func() ([]interface{}, []interface{}) {
		return []interface{}{map[string]any{"name": "S", "desc": "SD", "value": "Enabled", "type": "Sysctl"}},
			[]interface{}{map[string]any{"name": "S", "desc": "SD", "value": "Enabled", "type": "Sysctl", "color": "green"}}
	}

	data, colors := ParseKernel("/tmp/config")
	b, _ := json.Marshal(data)
	s := string(b)
	if !strings.Contains(s, "\"K\"") || !strings.Contains(s, "\"S\"") {
		t.Fatalf("expected kernel+sysctl combined, got %s", s)
	}
	cb, _ := json.Marshal(colors)
	cs := string(cb)
	if !strings.Contains(cs, "\"color\"") {
		t.Fatalf("expected color results, got %s", cs)
	}
}
