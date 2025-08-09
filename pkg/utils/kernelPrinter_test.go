package utils

import (
	"encoding/json"
	"testing"
)

func TestKernelPrinter_AllFormats(t *testing.T) {
	k := []interface{}{
		map[string]any{"name": "CONF", "desc": "d", "value": "Enabled", "type": "Kernel Config"},
	}
	kc := []interface{}{
		map[string]any{"name": "CONF", "desc": "d", "value": "Enabled", "type": "Kernel Config", "color": "green"},
	}

	out := captureOutput(t, func() { KernelPrinter("json", k, kc, true, true) })
	if !json.Valid([]byte(out)) {
		t.Fatalf("expected JSON output")
	}

	out = captureOutput(t, func() { KernelPrinter("yaml", k, kc, true, true) })
	if len(out) == 0 {
		t.Fatalf("expected YAML output")
	}

	out = captureOutput(t, func() { KernelPrinter("xml", k, kc, true, true) })
	if len(out) == 0 || out[0] != '<' {
		t.Fatalf("expected XML output")
	}

	out = captureOutput(t, func() { KernelPrinter("table", k, kc, true, false) })
	if len(out) == 0 {
		t.Fatalf("expected table output")
	}
}
