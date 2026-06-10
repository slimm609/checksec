package output

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/fatih/color"
)

// TestFatalf_Exits covers the os.Exit(1) path of Fatalf via a subprocess.
func TestFatalf_Exits(t *testing.T) {
	if os.Getenv("BE_FATALF") == "1" {
		Fatalf("fatal %s", "boom")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFatalf_Exits$")
	cmd.Env = append(os.Environ(), "BE_FATALF=1")
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok && !exitErr.Success() {
		return // expected non-zero exit
	}
	t.Fatalf("expected Fatalf to exit non-zero, got err=%v", err)
}

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

func TestWarnf(t *testing.T) {
	// Redirect the package's stderr sink to a pipe so we can inspect output.
	oldErr, oldNoWarn := stdError, NoWarnings
	defer func() { stdError, NoWarnings = oldErr, oldNoWarn }()

	capture := func(fn func()) string {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		stdError = w
		fn()
		_ = w.Close()
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, r); err != nil {
			t.Fatalf("copy: %v", err)
		}
		_ = r.Close()
		return buf.String()
	}

	NoWarnings = false
	got := capture(func() { Warnf("danger %s %d", "zone", 7) })
	if !strings.Contains(got, "danger zone 7") {
		t.Errorf("Warnf output = %q, want it to contain %q", got, "danger zone 7")
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("Warnf output = %q, want trailing newline", got)
	}

	NoWarnings = true
	if got := capture(func() { Warnf("suppressed") }); got != "" {
		t.Errorf("Warnf with NoWarnings=true wrote %q, want empty", got)
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
