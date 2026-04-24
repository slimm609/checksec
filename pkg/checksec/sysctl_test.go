package checksec

import (
	"testing"
)

func TestSysctlCheck_ReturnsWellFormedOutput(t *testing.T) {
	results, colors := SysctlCheck()

	if len(results) == 0 {
		t.Fatal("SysctlCheck() returned no results")
	}
	if len(results) != len(colors) {
		t.Fatalf("results length %d != colors length %d", len(results), len(colors))
	}

	validColors := map[string]bool{
		"green":  true,
		"yellow": true,
		"red":    true,
		"italic": true,
	}

	for i, colorEntry := range colors {
		colorMap, ok := colorEntry.(map[string]interface{})
		if !ok {
			t.Errorf("colors[%d] is %T, want map[string]interface{}", i, colorEntry)
			continue
		}
		if color, ok := colorMap["color"].(string); ok {
			if !validColors[color] {
				t.Errorf("colors[%d] has unexpected color %q", i, color)
			}
		}
	}
}

func TestSysctlCheck_EachResultHasRequiredFields(t *testing.T) {
	results, _ := SysctlCheck()

	for i, resultEntry := range results {
		m, ok := resultEntry.(map[string]interface{})
		if !ok {
			t.Errorf("results[%d] is %T, want map[string]interface{}", i, resultEntry)
			continue
		}
		for _, field := range []string{"name", "value", "desc", "type"} {
			if _, ok := m[field]; !ok {
				t.Errorf("results[%d] missing field %q", i, field)
			}
		}
	}
}
