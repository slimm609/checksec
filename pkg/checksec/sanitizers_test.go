package checksec

import (
	"testing"
)

// TestClassifySanitizers drives the pure symbol-set classifier. Each sanitizer
// is identified by its runtime initialiser / handler symbols (compiler-rt).
func TestClassifySanitizers(t *testing.T) {
	tests := []struct {
		name    string
		symbols []string
		want    string
	}{
		{"none", []string{"main", "printf"}, "None"},
		{"asan only", []string{"__asan_init", "main"}, "ASAN"},
		{"asan via report", []string{"__asan_report_load8"}, "ASAN"},
		{"ubsan only", []string{"__ubsan_handle_add_overflow"}, "UBSAN"},
		{"msan only", []string{"__msan_init"}, "MSAN"},
		{"tsan only", []string{"__tsan_init"}, "TSAN"},
		{"lsan only", []string{"__lsan_init"}, "LSAN"},
		{"asan+ubsan", []string{"__asan_init", "__ubsan_handle_type_mismatch_v1"}, "ASAN+UBSAN"},
		{"all four primary", []string{"__asan_init", "__ubsan_handle_add_overflow", "__msan_init", "__tsan_init"}, "ASAN+UBSAN+MSAN+TSAN"},
		{"dedupe: many asan symbols → one ASAN", []string{"__asan_init", "__asan_report_load1", "__asan_register_globals"}, "ASAN"},
		{"stable order regardless of input order", []string{"__tsan_init", "__asan_init"}, "ASAN+TSAN"},
		{"unrelated double-underscore", []string{"__libc_start_main", "__cxa_finalize"}, "None"},
		{"empty", nil, "None"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifySanitizers(tt.symbols); got != tt.want {
				t.Errorf("classifySanitizers(%v) = %q, want %q", tt.symbols, got, tt.want)
			}
		})
	}
}

func TestSanitizers_Result(t *testing.T) {
	tests := []struct {
		value      string
		wantStatus Status
	}{
		{"None", StatusInfo},
		{"ASAN", StatusGood},
		{"ASAN+UBSAN", StatusGood},
	}
	for _, tt := range tests {
		r := sanitizerResult(tt.value)
		if r.Value != tt.value || r.Status != tt.wantStatus {
			t.Errorf("sanitizerResult(%q) = %+v, want status %q", tt.value, r, tt.wantStatus)
		}
	}
}

func TestSanitizers_ELFWithoutSanitizers(t *testing.T) {
	ef, _ := openELF(t, buildLinuxELF(t))
	res := Sanitizers(ef)
	if res.Value != "None" || res.Status != StatusInfo {
		t.Errorf("Sanitizers() = %+v, want {None, StatusInfo}", res)
	}
}
