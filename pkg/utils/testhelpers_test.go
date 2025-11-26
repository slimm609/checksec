package utils

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/fatih/color"
)

// captureOutput redirects stdout (and color output) during fn execution and returns the captured bytes as a string.
func captureOutput(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	oldColor := color.Output

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}

	os.Stdout = w
	color.Output = w
	defer func() {
		os.Stdout = oldStdout
		color.Output = oldColor
	}()

	fn()

	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("copy error: %v", err)
	}
	_ = r.Close()

	return buf.String()
}
