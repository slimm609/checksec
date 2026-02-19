package utils

import (
	"encoding/json"
	"testing"
)

func TestFilePrinter_JSON_YAML_XML_AndTable(t *testing.T) {
	// prepare minimal data matching expected schema
	data := []interface{}{
		map[string]any{
			"name": "bin",
			"checks": map[string]any{
				"relro":          "Full RELRO",
				"canary":         "Canary Found",
				"nx":             "NX enabled",
				"pie":            "PIE Enabled",
				"rpath":          "No RPATH",
				"runpath":        "No RUNPATH",
				"symbols":        "0 symbols",
				"safestack":      "No SafeStack Found",
				"fortify_source": "Yes",
				"fortified":      "2",
				"fortifyable":    "3",
			},
		},
	}
	colors := []interface{}{
		map[string]any{
			"name": "bin",
			"checks": map[string]any{
				"relro": "Full RELRO", "relroColor": "green",
				"canary": "Canary Found", "canaryColor": "green",
				"nx": "NX enabled", "nxColor": "green",
				"pie": "PIE Enabled", "pieColor": "green",
				"rpath": "No RPATH", "rpathColor": "green",
				"runpath": "No RUNPATH", "runpathColor": "green",
				"symbols": "0 symbols", "symbolsColor": "green",
				"safestack": "No SafeStack Found", "safestackColor": "red",
				"fortify_source": "Yes", "fortify_sourceColor": "green",
				"fortified":   "2",
				"fortifyable": "3",
			},
		},
	}

	// JSON
	out := captureOutput(t, func() { FilePrinter("json", data, colors, true, true) })
	if !json.Valid([]byte(out)) {
		t.Fatalf("expected valid JSON output, got: %q", out)
	}

	// YAML
	out = captureOutput(t, func() { FilePrinter("yaml", data, colors, true, true) })
	if len(out) == 0 {
		t.Fatalf("expected YAML output")
	}

	// XML
	out = captureOutput(t, func() { FilePrinter("xml", data, colors, true, true) })
	if len(out) == 0 || out[0] != '<' {
		t.Fatalf("expected XML output, got %q", out)
	}

	// Table
	out = captureOutput(t, func() { FilePrinter("table", data, colors, true, false) })
	if len(out) == 0 {
		t.Fatalf("expected table output")
	}
}
