package checksec

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// parseSeccompStatus reads a /proc/<pid>/status stream and returns the seccomp
// mode. Per proc(5): Seccomp: 0=disabled, 1=strict, 2=filter (BPF).
func parseSeccompStatus(r io.Reader) Result {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "Seccomp:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(line, "Seccomp:"))
		switch val {
		case "0":
			return Result{Value: "Disabled", Status: StatusBad}
		case "1":
			return Result{Value: "Strict", Status: StatusGood}
		case "2":
			return Result{Value: "Filter", Status: StatusGood}
		default:
			return Result{Value: "Unknown", Status: StatusWarn}
		}
	}
	return Result{Value: "Unknown", Status: StatusWarn}
}

// Seccomp reports the seccomp mode of the running process pid by reading
// /proc/<pid>/status. Returns Unknown on platforms without /proc or for
// inaccessible PIDs.
func Seccomp(pid int) Result {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return Result{Value: "Unknown", Status: StatusWarn}
	}
	defer f.Close()
	return parseSeccompStatus(f)
}
