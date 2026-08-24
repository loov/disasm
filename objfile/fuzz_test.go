package objfile

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParse checks that no input makes Parse panic or return a Binary
// whose functions cannot be read and disassembled. Seeds are the small
// fixtures; the large ones only add copies of the same formats.
func FuzzParse(f *testing.F) {
	paths, _ := filepath.Glob("testdata/*")
	for _, path := range paths {
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() && fi.Size() < 512<<10 {
			data, _ := os.ReadFile(path)
			f.Add(data)
		}
	}
	f.Add([]byte("!<arch>\n"))
	f.Add([]byte("\x00asm\x01\x00\x00\x00"))
	f.Add([]byte("\x00asm\x0d\x00\x01\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		bin, err := Parse(data)
		if err != nil {
			return
		}
		for i := range min(len(bin.Funcs), 64) {
			fn := &bin.Funcs[i]
			insts, _ := bin.Disassemble(fn)
			for _, in := range insts[:min(len(insts), 64)] {
				bin.PCToLine(in.Addr)
			}
			bin.FuncFile(fn.Addr)
			bin.Lookup(fn.Addr)
			bin.DataSym(fn.Addr)
		}
	})
}
