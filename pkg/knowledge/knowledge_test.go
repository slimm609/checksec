package knowledge

import "testing"

func TestLookupKnownCheck(t *testing.T) {
	c, ok := Lookup("relro")
	if !ok {
		t.Fatal("relro must be in the registry")
	}
	if c.Remediation == "" {
		t.Error("relro must carry a remediation")
	}
}

func TestPresentPreservesOrderAndFallsBack(t *testing.T) {
	got := Present([]string{"pie", "definitely-not-a-check"})
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	if got[0].ID != "pie" {
		t.Errorf("order not preserved: %+v", got)
	}
	if got[1].Meaning != "(no description available)" {
		t.Errorf("unknown id must fall back, got %q", got[1].Meaning)
	}
}
