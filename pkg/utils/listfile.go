package utils

import (
	"bufio"
	"io"
	"strings"
)

// ReadPathList reads newline-separated file paths from r. Blank lines and
// lines whose first non-whitespace character is '#' are skipped; surrounding
// whitespace is trimmed.
func ReadPathList(r io.Reader) ([]string, error) {
	var paths []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		paths = append(paths, line)
	}
	return paths, sc.Err()
}

// RunListChecks runs RunFileChecks over every path and returns the reports in
// input order. Unreadable / non-ELF paths still yield a fully-populated
// FileReport (every field = Err), so output stays aligned.
func RunListChecks(paths []string, libc string) []FileReport {
	reports := make([]FileReport, 0, len(paths))
	for _, p := range paths {
		reports = append(reports, RunFileChecks(p, libc))
	}
	return reports
}
