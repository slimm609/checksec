package checksec

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// ParseProcMaps reads a /proc/<pid>/maps stream and returns the unique
// backing-file paths in first-seen order. Anonymous mappings, pseudo-paths
// ([vdso], [heap], …), memfd, and deleted-on-disk mappings are excluded.
//
// maps format (proc(5)):
//
//	address           perms offset  dev   inode   pathname
//	7f0000000000-…    r-xp  0000…   08:01 456     /usr/lib/libc.so.6
func ParseProcMaps(r io.Reader) []string {
	var paths []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		// The pathname column starts after the 5 fixed whitespace-separated
		// fields; it may itself contain spaces, so split on the first 5 only.
		parts := strings.SplitN(line, " ", 6)
		if len(parts) < 6 {
			continue
		}
		path := strings.TrimSpace(parts[5])
		if path == "" || !strings.HasPrefix(path, "/") {
			continue // anonymous, [vdso], [heap], etc.
		}
		if strings.HasSuffix(path, " (deleted)") || strings.HasPrefix(path, "/memfd:") {
			continue
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		paths = append(paths, path)
	}
	return paths
}

// ProcLibs returns the unique mapped-file paths for pid, or an error if
// /proc/<pid>/maps is unreadable (no procfs, no such PID, permission denied).
func ProcLibs(pid int) ([]string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseProcMaps(f), nil
}
