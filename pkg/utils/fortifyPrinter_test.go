package utils

import (
	"encoding/json"
	"testing"
)

func TestFortifyPrinter_AllFormats(t *testing.T) {
	data := []interface{}{
		map[string]any{
			"name": "bin",
			"checks": map[string]any{
				"fortified":      "1",
				"fortifyable":    "2",
				"fortify_source": "Yes",
				"noFortify":      "1",
				"libcSupport":    "Yes",
				"numLibcFunc":    "1",
				"numFileFunc":    "3",
			},
		},
	}
	colors := []interface{}{
		map[string]any{
			"name": "bin",
			"checks": map[string]any{
				"Fortified":     "1",
				"FortifyAble":   "2",
				"FortifySource": "Yes", "FortifySourceColor": "green",
				"NoFortify":   "1",
				"LibcSupport": "Yes", "LibcSupportColor": "green",
				"NumLibcFunc": "1",
				"NumFileFunc": "3",
			},
		},
	}

	out := captureOutput(t, func() { FortifyPrinter("json", data, colors, true, true) })
	if !json.Valid([]byte(out)) {
		t.Fatalf("expected JSON, got %q", out)
	}

	out = captureOutput(t, func() { FortifyPrinter("yaml", data, colors, true, true) })
	if len(out) == 0 {
		t.Fatalf("expected YAML output")
	}

	out = captureOutput(t, func() { FortifyPrinter("xml", data, colors, true, true) })
	if len(out) == 0 || out[0] != '<' {
		t.Fatalf("expected XML output")
	}

	out = captureOutput(t, func() { FortifyPrinter("table", data, colors, true, false) })
	if len(out) == 0 {
		t.Fatalf("expected table output")
	}
}
