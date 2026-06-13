package utils

import (
	"bufio"
	"io"
	"runtime"
	"strings"
	"sync"
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

// RunListChecksParallel runs RunFileChecks over every path using a bounded
// worker pool and returns the reports in input order. RunFileChecks is pure
// (opens its own scanContext, no shared state), so this is data-race-free.
// workers <= 0 defaults to GOMAXPROCS.
func RunListChecksParallel(paths []string, libc string, workers int) []FileReport {
	if len(paths) == 0 {
		return nil
	}
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers > len(paths) {
		workers = len(paths)
	}

	reports := make([]FileReport, len(paths))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				reports[i] = RunFileChecks(paths[i], libc)
			}
		}()
	}
	for i := range paths {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return reports
}
