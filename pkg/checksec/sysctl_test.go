package checksec

import (
	"io/fs"
	"testing"
)

func TestSysctlCheck_ReturnsWellFormedOutput(t *testing.T) {
	results := SysctlCheck()
	if len(results) == 0 {
		t.Fatal("SysctlCheck() returned no results")
	}
	if len(results) != len(sysctlChecks) {
		t.Fatalf("results length %d != registry length %d", len(results), len(sysctlChecks))
	}

	valid := map[Status]bool{StatusGood: true, StatusWarn: true, StatusBad: true, StatusNA: true}
	for i, r := range results {
		if !valid[r.Result.Status] {
			t.Errorf("results[%d] has unexpected status %q", i, r.Result.Status)
		}
	}
}

func TestSysctlCheck_EachResultHasRequiredFields(t *testing.T) {
	for i, r := range SysctlCheck() {
		if r.Name == "" {
			t.Errorf("results[%d] missing Name", i)
		}
		if r.Desc == "" {
			t.Errorf("results[%d] missing Desc", i)
		}
		if r.Type != "Sysctl" {
			t.Errorf("results[%d] Type = %q, want Sysctl", i, r.Type)
		}
		if r.Result.Value == "" {
			t.Errorf("results[%d] missing Result.Value", i)
		}
	}
}

func TestBpfDisabledValueMapping(t *testing.T) {
	tests := []struct {
		value  string
		want   string
		status Status
	}{
		{"0", "Disabled", StatusBad},
		{"1", "Enabled", StatusGood},
		{"2", "Enabled (Locked)", StatusGood},
	}

	for _, tt := range tests {
		result, ok := bpfDisabled[tt.value]
		if !ok {
			t.Errorf("bpfDisabled[%q] not found", tt.value)
			continue
		}
		if result.Value != tt.want {
			t.Errorf("bpfDisabled[%q].Value = %q, want %q", tt.value, result.Value, tt.want)
		}
		if result.Status != tt.status {
			t.Errorf("bpfDisabled[%q].Status = %v, want %v", tt.value, result.Status, tt.status)
		}
	}
}

func TestResolveSysctlResult(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		err        error
		wantValue  string
		wantStatus Status
	}{
		{
			name:       "knob absent from kernel reports N/A",
			err:        &fs.PathError{Op: "open", Path: "/proc/sys/kernel/exec-shield", Err: fs.ErrNotExist},
			wantValue:  "N/A",
			wantStatus: StatusNA,
		},
		{
			name:       "unreadable knob reports Unknown",
			err:        &fs.PathError{Op: "open", Path: "/proc/sys/kernel/yama/ptrace_scope", Err: fs.ErrPermission},
			wantValue:  "Unknown",
			wantStatus: StatusNA,
		},
		{
			name:       "empty value reports Unknown",
			raw:        "",
			wantValue:  "Unknown",
			wantStatus: StatusNA,
		},
		{
			name:       "unmapped value reports Unknown",
			raw:        "42",
			wantValue:  "Unknown",
			wantStatus: StatusNA,
		},
		{
			name:       "mapped value reports its mapping",
			raw:        "1",
			wantValue:  "Enabled",
			wantStatus: StatusGood,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveSysctlResult(tt.raw, tt.err, onOff)
			if got.Value != tt.wantValue {
				t.Errorf("Value = %q, want %q", got.Value, tt.wantValue)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("Status = %v, want %v", got.Status, tt.wantStatus)
			}
		})
	}
}
