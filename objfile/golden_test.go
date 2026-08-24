package objfile

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// dump renders every function of the binary: header, then one line per
// instruction with its source position. It is the complete observable
// behaviour of the package for one file.
func dump(t *testing.T, bin *Binary, keep func(name string) bool) (full, kept []byte) {
	var all, some bytes.Buffer
	for i := range bin.Funcs {
		fn := &bin.Funcs[i]
		var b bytes.Buffer
		fmt.Fprintf(&b, "== %s %#x %d %s\n", fn.Name, fn.Addr, fn.Size, bin.FuncFile(fn.Addr))
		insts, err := bin.Disassemble(fn)
		if err != nil {
			fmt.Fprintf(&b, "error: %v\n", err)
		}
		for _, ix := range insts {
			file, line := bin.PCToLine(ix.Addr)
			fmt.Fprintf(&b, "%#x %d %q %q %q", ix.Addr, ix.Len, ix.Op, ix.Text, ix.GNU)
			if ix.RefKnown {
				fmt.Fprintf(&b, " ref=%#x call=%v", ix.Ref, ix.Call)
			}
			fmt.Fprintf(&b, " %s:%d\n", filepath.Base(file), line)
		}
		all.Write(b.Bytes())
		if keep(fn.Name) {
			some.Write(b.Bytes())
		}
	}
	return all.Bytes(), some.Bytes()
}

// TestGolden checks every testdata binary against golden/<name>.txt:
// a summary line with the hash of the full dump, followed by the full
// text of the functions matching keepFunc, for readable diffs.
func TestGolden(t *testing.T) {
	paths, _ := filepath.Glob("testdata/*")
	for _, path := range paths {
		if fi, err := os.Stat(path); err != nil || fi.IsDir() {
			continue
		}
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			bin, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer bin.Close()
			full, kept := dump(t, bin, keepFunc)
			var out bytes.Buffer
			fmt.Fprintf(&out, "arch=%s funcs=%d sha256=%x\n", bin.Arch, len(bin.Funcs), sha256.Sum256(full))
			out.Write(kept)

			golden := filepath.Join("testdata", "golden", name+".txt")
			if dir := os.Getenv("OBJFILE_DUMP"); dir != "" {
				_ = os.WriteFile(filepath.Join(dir, name+".txt"), full, 0o644)
			}
			if *update {
				_ = os.MkdirAll(filepath.Dir(golden), 0o755)
				if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update)", err)
			}
			if !bytes.Equal(want, out.Bytes()) {
				t.Errorf("golden mismatch; diff %s against -update output, or set OBJFILE_DUMP to compare full dumps", golden)
				t.Log(firstDiff(want, out.Bytes()))
			}
		})
	}
}

func keepFunc(name string) bool {
	return strings.HasPrefix(name, "main.") || strings.HasPrefix(name, "main/") || name == "main" || strings.HasPrefix(name, "_start") ||
		strings.HasPrefix(name, "Reset_Handler") || strings.HasPrefix(name, "runtime.memmove") ||
		strings.HasPrefix(name, "runtime.run")
}

func firstDiff(a, b []byte) string {
	al, bl := strings.Split(string(a), "\n"), strings.Split(string(b), "\n")
	for i := range min(len(al), len(bl)) {
		if al[i] != bl[i] {
			return fmt.Sprintf("line %d:\n-%s\n+%s", i+1, al[i], bl[i])
		}
	}
	return fmt.Sprintf("lengths differ: %d vs %d lines", len(al), len(bl))
}
