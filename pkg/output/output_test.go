package output

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/fatih/color"
)

// captureOutput captures stdout during fn execution and returns it as string
func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	oldColor := color.Output
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	os.Stdout = w
	color.Output = w
	defer func() { os.Stdout = old; color.Output = oldColor }()

	fn()

	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("copy error: %v", err)
	}
	_ = r.Close()
	return buf.String()
}

func TestPrintLogo(t *testing.T) {
	// noBanner=false prints ASCII logo
	out := captureOutput(t, func() { PrintLogo(false) })
	if !strings.Contains(out, "_____") {
		t.Fatalf("expected logo output, got: %q", out)
	}

	// noBanner=true should print nothing
	out = captureOutput(t, func() { PrintLogo(true) })
	if out != "" {
		t.Fatalf("expected no output when noBanner=true, got: %q", out)
	}
}

func TestColorPrinter(t *testing.T) {
	cases := []struct {
		color string
		text  string
	}{
		{"green", "ok"},
		{"red", "fail"},
		{"yellow", "warn"},
		{"blue", "info"},
		{"italic", "emph"},
		{"unset", "plain"},
	}
	for _, tc := range cases {
		got := ColorPrinter(tc.text, tc.color)
		if !strings.Contains(got, tc.text) {
			t.Fatalf("expected colored output to contain text %q for color %q, got %q", tc.text, tc.color, got)
		}
	}
}
