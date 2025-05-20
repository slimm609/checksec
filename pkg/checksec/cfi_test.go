package checksec

import "testing"

func TestX86CFI(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected x86CET
	}{
		{"no shstk & no ibt", 0, x86CET{shstk: false, ibt: false}},
		{"no shstk & ibt", 1, x86CET{shstk: false, ibt: true}},
		{"shstk & no ibt", 2, x86CET{shstk: true, ibt: false}},
		{"shstk & ibt", 3, x86CET{shstk: true, ibt: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := parseBitmaskForx86CET(tt.input)
			if res != tt.expected {
				t.Errorf("got %v, want %v", res, tt.expected)
			}
		})
	}
}

func TestArmPACBTI(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected armPACBTI
	}{
		{"no pac & no bti", 0, armPACBTI{pac: false, bti: false}},
		{"no pac & bti", 1, armPACBTI{pac: false, bti: true}},
		{"pac & no bti", 2, armPACBTI{pac: true, bti: false}},
		{"pac & bti", 3, armPACBTI{pac: true, bti: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := parseBitmaskForArmPACBTI(tt.input)
			if res != tt.expected {
				t.Errorf("got %v, want %v", res, tt.expected)
			}
		})
	}
}
