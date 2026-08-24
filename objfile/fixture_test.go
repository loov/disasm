package objfile

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// buildFixture compiles testdata/src for a target and returns the
// binary's path; each configuration is built once per test process.
// It skips the test when there is no go tool.
func buildFixture(t *testing.T, goos, goarch, ldflags string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go tool not available: %v", err)
	}
	key := goos + "/" + goarch + " " + ldflags
	fixtures.mu.Lock()
	once, ok := fixtures.builds[key]
	if !ok {
		once = sync.OnceValues(func() (string, error) {
			out := filepath.Join(fixtures.dir, filepath.Base(goos+"_"+goarch+ldflags))
			if goos == "windows" {
				out += ".exe"
			}
			cmd := exec.Command("go", "build", "-o", out, "-ldflags="+ldflags, "./testdata/src")
			cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
			if output, err := cmd.CombinedOutput(); err != nil {
				return "", &buildError{err, string(output)}
			}
			return out, nil
		})
		fixtures.builds[key] = once
	}
	fixtures.mu.Unlock()
	path, err := once()
	if err != nil {
		t.Fatalf("building fixture %s: %v", key, err)
	}
	return path
}

type buildError struct {
	err    error
	output string
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + e.output }

var fixtures struct {
	mu     sync.Mutex
	dir    string
	builds map[string]func() (string, error)
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "objfile-fixtures-*")
	if err != nil {
		panic(err)
	}
	fixtures.dir = dir
	fixtures.builds = map[string]func() (string, error){}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
