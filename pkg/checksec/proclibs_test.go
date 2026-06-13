package checksec

import (
	"reflect"
	"strings"
	"testing"
)

// TestParseProcMaps verifies extraction of unique mapped-file paths from a
// /proc/<pid>/maps stream. Anonymous mappings, [vdso]/[heap]/etc., and
// duplicate paths are excluded.
func TestParseProcMaps(t *testing.T) {
	const sample = `55a1c0000000-55a1c0001000 r--p 00000000 08:01 123 /usr/bin/cat
55a1c0001000-55a1c0002000 r-xp 00001000 08:01 123 /usr/bin/cat
7f0000000000-7f0000001000 r--p 00000000 08:01 456 /usr/lib/libc.so.6
7f0000001000-7f0000100000 r-xp 00001000 08:01 456 /usr/lib/libc.so.6
7f0000200000-7f0000201000 r--p 00000000 08:01 789 /usr/lib/ld-linux-x86-64.so.2
7f0000300000-7f0000301000 rw-p 00000000 00:00 0
7f0000400000-7f0000401000 r-xp 00000000 00:00 0                          [vdso]
7f0000500000-7f0000501000 r--p 00000000 08:01 999 /usr/lib/with spaces/lib.so
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
7f0000600000-7f0000601000 r--p 00000000 08:01 111 /memfd:foo (deleted)
`
	got := ParseProcMaps(strings.NewReader(sample))
	want := []string{
		"/usr/bin/cat",
		"/usr/lib/libc.so.6",
		"/usr/lib/ld-linux-x86-64.so.2",
		"/usr/lib/with spaces/lib.so",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseProcMaps() = %v\nwant %v", got, want)
	}
}

func TestParseProcMaps_Empty(t *testing.T) {
	if got := ParseProcMaps(strings.NewReader("")); got != nil {
		t.Errorf("ParseProcMaps(empty) = %v, want nil", got)
	}
}

func TestProcLibs_ErrorPath(t *testing.T) {
	// PID -1 has no /proc entry on any platform.
	if _, err := ProcLibs(-1); err == nil {
		t.Error("ProcLibs(-1) returned nil error")
	}
}

func TestParseProcMaps_PreservesFirstSeenOrder(t *testing.T) {
	const sample = `0-1 r--p 0 0:0 1 /b
1-2 r--p 0 0:0 2 /a
2-3 r--p 0 0:0 1 /b
`
	got := ParseProcMaps(strings.NewReader(sample))
	want := []string{"/b", "/a"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (first-seen order)", got, want)
	}
}
