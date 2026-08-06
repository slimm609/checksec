package utils

import (
	"bytes"
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func TestWriteLLMKernel(t *testing.T) {
	checks := []checksec.KernelCheck{
		{Name: "KASLR", Desc: "Kernel address space randomization", Type: "Config",
			Result: checksec.Result{Value: "Enabled", Status: checksec.StatusGood}},
		{Name: "SELinux", Desc: "Mandatory access control", Type: "Config",
			Result: checksec.Result{Value: "Disabled", Status: checksec.StatusBad}},
	}
	var buf bytes.Buffer
	writeLLMKernel(&buf, checks, PrintOptions{})
	out := buf.String()
	if !strings.Contains(out, "AUTHORITATIVE") {
		t.Errorf("kernel llm output needs the preamble:\n%s", out)
	}
	if !strings.Contains(out, "- [ok] KASLR = Enabled") {
		t.Errorf("missing good kernel row:\n%s", out)
	}
	if !strings.Contains(out, "- [!] SELinux = Disabled") {
		t.Errorf("missing bad kernel row:\n%s", out)
	}
}
