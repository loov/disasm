package objfile

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

func open(t *testing.T, path string) *Binary {
	t.Helper()
	bin, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bin.Close() })
	return bin
}

func TestFunc_ByName(t *testing.T) {
	bin := open(t, "testdata/testprog_linux_amd64")
	fn := bin.Func("main.main")
	if fn == nil {
		t.Fatal("main.main not found")
	}
	if fn.Size == 0 || fn.Size > 1<<20 {
		t.Errorf("main.main size = %d, out of sane range", fn.Size)
	}
	if got := uint64(len(fn.Code())); got != fn.Size {
		t.Errorf("len(Code()) = %d, want Size = %d", got, fn.Size)
	}
	if bin.Func("no.such") != nil {
		t.Error("Func found a function that does not exist")
	}
	if !slices.IsSortedFunc(bin.Funcs, func(x, y Func) int { return int(x.Addr - y.Addr) }) {
		t.Error("Funcs not sorted by address")
	}
}

// TestFunc_Code_MatchesFileContents checks Code() against bytes read
// directly from the file via section offsets.
func TestFunc_Code_MatchesFileContents(t *testing.T) {
	path := "testdata/testprog_linux_amd64"
	bin := open(t, path)
	fn := bin.Func("main.main")
	ef, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := ef.Section(".text")
	off := text.Offset + fn.Addr - text.Addr
	if !bytes.Equal(fn.Code(), raw[off:off+fn.Size]) {
		t.Error("Code() differs from bytes at the function's file offset")
	}
}

func TestLookup(t *testing.T) {
	bin := open(t, "testdata/testprog_linux_amd64")
	fn := bin.Func("main.main")
	if name, base := bin.Lookup(fn.Addr + 4); name != "main.main" || base != fn.Addr {
		t.Errorf("Lookup inside main.main = %q, %#x", name, base)
	}
	// f and f.abi0 share an address: the alias sorted last wins, in
	// every binary alike.
	wrapper := bin.Func("runtime.morestack_noctxt.abi0")
	if wrapper == nil {
		t.Skip("no runtime.morestack_noctxt.abi0 in fixture")
	}
	if name, _ := bin.Lookup(wrapper.Addr); name != "runtime.morestack_noctxt.abi0" {
		t.Errorf("Lookup(aliased) = %q, want the .abi0 alias", name)
	}
	// Data symbols resolve through Lookup too, and the Go section
	// boundary marker at the same address does not shadow them.
	name, base, size := bin.DataSym(bssVar(t, bin))
	if name != "internal/cpu.doDerived" || size == 0 {
		t.Errorf("DataSym = %q, %#x, %d", name, base, size)
	}
	if got, _ := bin.Lookup(base); got != name {
		t.Errorf("Lookup(data) = %q, want %q", got, name)
	}
	if !bin.Contains(base) || bin.Contains(1<<62) {
		t.Error("Contains disagrees with the section ranges")
	}
}

// bssVar returns the address of internal/cpu.doDerived, the first
// variable in .bss, which shares its address with runtime.bss.
func bssVar(t *testing.T, bin *Binary) uint64 {
	for _, s := range bin.syms {
		if s.name == "internal/cpu.doDerived" {
			return s.addr
		}
	}
	t.Skip("no internal/cpu.doDerived in fixture")
	return 0
}

func TestPCToLine_Concurrent(t *testing.T) {
	// DWARF units are indexed lazily; lookups from many goroutines must
	// not race on the cache.
	bin := open(t, "testdata/pico.elf")
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range bin.Funcs {
				bin.PCToLine(bin.Funcs[i].Addr)
				bin.FuncFile(bin.Funcs[i].Addr)
			}
		}()
	}
	wg.Wait()
}

// TestOpen_HostileInputs feeds Open corrupt and unsupported files: each
// must produce an error, never a panic or a half-parsed Binary.
func TestOpen_HostileInputs(t *testing.T) {
	elfData, err := os.ReadFile("testdata/testprog_linux_amd64")
	if err != nil {
		t.Fatal(err)
	}
	// e_machine is the little-endian uint16 at offset 18 of the ELF
	// header; 0xffff is not a machine any parser supports.
	badMachine := slices.Clone(elfData)
	binary.LittleEndian.PutUint16(badMachine[18:], 0xffff)
	// A code section declaring ~2^63 functions must error out promptly
	// instead of spinning on the bogus count or allocating for it.
	hugeCount := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}
	hugeWasm := append([]byte("\x00asm\x01\x00\x00\x00\x0a"), byte(len(hugeCount)))
	hugeWasm = append(hugeWasm, hugeCount...)
	// An archive entry whose declared size runs past the end of the file.
	lyingSize := fmt.Sprintf("!<arch>\n%-16s%-12d%-6d%-6d%-8o%-10d`\nshort", "_go_.o", 0, 0, 0, 0o644, 4096)

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"too short", []byte{0x7f, 'E'}, "too short"},
		{"not a binary", []byte("plain text, not an executable\n"), "unsupported binary format"},
		{"unsupported ELF machine", badMachine, "unsupported ELF machine"},
		{"truncated ELF", elfData[:len(elfData)*2/5], ""},
		{"wasm truncated section header", []byte("\x00asm\x01\x00\x00\x00\x0a\x20"), "truncated wasm section"},
		{"wasm huge code count", hugeWasm, "malformed wasm code section"},
		{"empty component", []byte("\x00asm\x0d\x00\x01\x00"), "no core module"},
		{"archive truncated header", []byte("!<arch>\ngarbage"), "truncated archive entry header"},
		{"archive truncated entry", []byte(lyingSize), "truncated archive entry"},
		{"archive truncated object header", archive("_go_.o", "go object linux amd64 go1.26"), "truncated object header"},
		{"archive unsupported version", archive("_go_.o", "go object linux amd64 go1.19\n!\n\x00go119ld"), "unsupported Go object version"},
		{"archive truncated object", archive("_go_.o", "go object linux amd64 go1.26\n!\n\x00go120ld"), "truncated object file"},
		{"archive unsupported arch", archive("_go_.o", "go object plan9 mips go1.26\n!\n\x00go120ld"), "unsupported architecture"},
		{"archive no objects", archive("__.PKGDEF", "go object linux amd64 go1.26\n!\n"), "no Go object files"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hostile.bin")
			if err := os.WriteFile(path, tt.data, 0o600); err != nil {
				t.Fatal(err)
			}
			bin, err := Open(path)
			if err == nil {
				bin.Close()
				t.Fatal("Open succeeded on hostile input")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Open = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestParse_TruncatedWasmPclntab(t *testing.T) {
	tab := make([]byte, 44)
	copy(tab, []byte{0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 4})
	binary.LittleEndian.PutUint32(tab[8:], 1)
	binary.LittleEndian.PutUint32(tab[36:], 40)

	payload := []byte{1, 0, 0x41, 0, 0x0b}
	payload = appendUleb(payload, uint64(len(tab)))
	payload = append(payload, tab...)
	wasm := []byte("\x00asm\x01\x00\x00\x00")
	wasm = append(wasm, wasmSecData)
	wasm = appendUleb(wasm, uint64(len(payload)))
	wasm = append(wasm, payload...)

	if _, err := Parse(wasm); err != nil {
		t.Fatal(err)
	}
}

// archive wraps content as the single entry of an ar archive.
func archive(name, content string) []byte {
	hdr := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name, 0, 0, 0, 0o644, len(content))
	data := "!<arch>\n" + hdr + content
	if len(content)%2 == 1 {
		data += "\n"
	}
	return []byte(data)
}

// TestOpen_Stripped checks that function ranges come from the pclntab
// when the symbol table is stripped, in every executable format.
func TestOpen_Stripped(t *testing.T) {
	for _, tt := range []struct{ goos, goarch string }{
		{"linux", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"},
	} {
		t.Run(tt.goos, func(t *testing.T) {
			bin := open(t, buildFixture(t, tt.goos, tt.goarch, "-s -w"))
			fn := bin.Func("main.main")
			if fn == nil {
				t.Fatal("main.main not found in stripped binary")
			}
			if fn.Size == 0 || fn.Size > 1<<20 {
				t.Errorf("main.main size = %d, out of sane range", fn.Size)
			}
			if file, line := bin.PCToLine(fn.Addr); !strings.HasSuffix(file, "main.go") || line == 0 {
				t.Errorf("PCToLine(main.main) = %q:%d", file, line)
			}
			if file := bin.FuncFile(fn.Addr); !strings.HasSuffix(file, "main.go") {
				t.Errorf("FuncFile(main.main) = %q", file)
			}
		})
	}
}

// TestOpen_ELFWithoutPclntabSection checks that function ranges are
// still recovered when the ELF has no .gopclntab section, as with
// externally linked (cgo) binaries where the system linker merges the
// pclntab into another data section. The fixture simulates that layout
// by renaming the section in a stripped binary, leaving the pclntab
// bytes findable only by scanning.
func TestOpen_ELFWithoutPclntabSection(t *testing.T) {
	data, err := os.ReadFile(buildFixture(t, "linux", "amd64", "-s -w"))
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(data, []byte(".gopclntab\x00"))
	if i < 0 {
		t.Fatal("fixture has no .gopclntab section name to rename")
	}
	data[i] = 'X'
	path := filepath.Join(t.TempDir(), "renamed")
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := open(t, path)
	if bin.Func("main.main") == nil {
		t.Fatal("main.main not found without a .gopclntab section")
	}
}

func TestOpen_GoArchive(t *testing.T) {
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod": "module p\n\ngo 1.26\n",
		"p.go":   "package p\n\nfunc Add(a, b int) int { return a + b }\n\nfunc Greet(name string) string { return \"hello \" + name }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := buildIn(t, dir, "p.a")
	bin := open(t, path)
	if bin.Arch != runtime.GOARCH || !bin.NoLayout {
		t.Errorf("Arch = %q NoLayout = %v", bin.Arch, bin.NoLayout)
	}
	for _, name := range []string{"p.Add", "p.Greet"} {
		fn := bin.Func(name)
		if fn == nil {
			t.Fatalf("%s not found; have %d funcs", name, len(bin.Funcs))
		}
		if len(fn.Code()) == 0 || uint64(len(fn.Code())) != fn.Size {
			t.Errorf("%s: %d code bytes, size %d", name, len(fn.Code()), fn.Size)
		}
		if insts, err := bin.Disassemble(fn); err != nil || len(insts) == 0 {
			t.Errorf("%s: Disassemble = %d insts, %v", name, len(insts), err)
		}
	}
}

func buildIn(t *testing.T, dir, out string) string {
	t.Helper()
	path := filepath.Join(dir, out)
	cmd := exec.Command("go", "build", "-o", path, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}
	return path
}

func TestOpen_Wasm_GoNames(t *testing.T) {
	for _, goos := range []string{"wasip1", "js"} {
		t.Run(goos, func(t *testing.T) {
			bin := open(t, buildFixture(t, goos, "wasm", ""))
			// The exact name proves pclntab recovery worked: the wasm
			// name section alone only has sanitized names.
			fn := bin.Func("main.main")
			if fn == nil {
				t.Fatal("main.main not found")
			}
			if name, _ := bin.Lookup(fn.Addr); name != "main.main" {
				t.Errorf("Lookup(%d) = %q, want main.main", fn.Addr, name)
			}
			insts, err := bin.Disassemble(fn)
			if err != nil || len(insts) == 0 {
				t.Fatalf("Disassemble: %d insts, %v", len(insts), err)
			}
			if file, line := bin.PCToLine(insts[0].Addr); !strings.HasSuffix(file, "main.go") || line == 0 {
				t.Errorf("PCToLine(first inst) = %q:%d", file, line)
			}
		})
	}
}

// White-box checks for the overflow hardening: crafting hostile
// binaries per format is disproportionate, so the guarded code is
// exercised directly.
func TestHardening(t *testing.T) {
	b := &Binary{}
	b.addText(^uint64(0)-32, make([]byte, 64))
	f := &Func{Name: "evil", Addr: ^uint64(0) - 8, Size: 1 << 20, bin: b}
	if got := f.Code(); got != nil {
		t.Errorf("Code() = %d bytes for a symbol whose addr+size wraps, want nil", len(got))
	}

	b = &Binary{}
	b.addRange(^uint64(0)-16, 1<<20)
	if !b.Contains(^uint64(0) - 1) {
		t.Error("Contains lost an in-range address to end wraparound")
	}
	if b.Contains(^uint64(0) - 17) {
		t.Error("Contains reports an address below the range start")
	}

	// The last sizeless data symbol is bounded by its section, not
	// infinity; sizeless aliases share the extent to the next address.
	b = &Binary{}
	b.addText(0x1000, make([]byte, 0x100))
	b.addRange(0x1000, 0x100)
	b.addRange(0x2000, 0x100)
	b.addSym("a", 0x1000, 0, symText)
	b.addSym("alias", 0x1000, 0, symText)
	b.addSym("b", 0x1080, 0, symText)
	b.addSym("last", 0x2080, 0, symData)
	b.finish()
	for _, name := range []string{"a", "alias"} {
		if fn := b.Func(name); fn == nil || fn.Size != 0x80 {
			t.Errorf("%s = %+v, want size 0x80", name, fn)
		}
	}
	if name, _, _ := b.DataSym(0x2090); name != "last" {
		t.Errorf("DataSym inside the section = %q, want last", name)
	}
	if name, _, _ := b.DataSym(1 << 40); name != "" {
		t.Errorf("DataSym far above every section = %q, want no match", name)
	}
	if name, _ := b.Lookup(0x1090); name != "b" {
		t.Errorf("Lookup(0x1090) = %q, want b", name)
	}
}

func TestFinish_SizelessSymbolsStopAtSectionEnd(t *testing.T) {
	b := &Binary{}
	b.addText(0x1000, make([]byte, 0x100))
	b.addText(0x3000, make([]byte, 0x100))
	b.addRange(0x2000, 0x100)
	b.addRange(0x4000, 0x100)
	b.addSym("first-text", 0x1080, 0, symText)
	b.addSym("later-text", 0x3000, 0, symText)
	b.addSym("data", 0x2080, 0, symData)
	b.addSym("later-data", 0x4000, 0, symData)
	b.finish()

	fn := b.Func("first-text")
	if fn == nil {
		t.Fatal("first-text not found")
	}
	if fn.Size != 0x80 || len(fn.Code()) != 0x80 {
		t.Errorf("first-text = %+v, %d code bytes; want size 128", fn, len(fn.Code()))
	}
	if name, _, _ := b.DataSym(0x2200); name != "" {
		t.Errorf("DataSym in section gap = %q, want no match", name)
	}
}
