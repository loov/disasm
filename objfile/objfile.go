// Package objfile loads executables into a format-independent
// representation: the architecture, the functions with their machine
// code, symbol lookups, source positions from the Go pclntab or DWARF,
// and a disassembler for the code.
//
// A binary is memory-mapped, and Open reads only its headers and symbol
// tables; line tables are parsed per compilation unit on first use.
// All methods are safe for concurrent use after Open.
package objfile

import (
	"bytes"
	"cmp"
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"unsafe"

	"github.com/ianlancetaylor/demangle"
)

// Binary is a loaded executable, backed by a read-only memory mapping
// of the file. Close releases the mapping; Func.Code slices become
// invalid afterwards.
type Binary struct {
	Arch string // GOARCH name, e.g. "amd64"
	// Funcs are the functions inside the text section, sorted by
	// address, then name. Names are not unique: a Go ABI wrapper shares
	// the name of the function it wraps.
	Funcs []Func
	// NoLayout reports that function addresses are deterministic
	// pseudo-addresses (file offsets in a Go compile archive) rather
	// than a memory layout: gaps between functions are not padding.
	NoLayout bool

	text     []byte
	textAddr uint64
	// byteOrder of instruction words; only ppc64 has a big-endian variant.
	byteOrder binary.ByteOrder
	// syms are all symbols sorted by address, used to resolve addresses to names.
	syms []sym
	// ranges are the [start, end) virtual address ranges of the
	// binary's loadable sections, used to recognize address-valued
	// immediates.
	ranges [][2]uint64
	pcln   *pclntab
	// dwarf opens the debug info, and lines is the line table indexed
	// from it on first use. It is only consulted when there is no
	// pclntab — binaries from clang, gcc and anything else that isn't
	// Go — so a Go binary never pays for the DWARF it also carries.
	dwarf     func() (*dwarf.Data, error)
	lines     *Lines
	linesOnce sync.Once
	// arm32 is the ARM mapping-symbol map: where ARM, Thumb and data
	// regions begin within the text of a 32-bit ARM ELF. Empty for
	// everything else, and for binaries that carry no mapping symbols.
	arm32 *armRegions
	// xtensaLiterals are the addresses L32R instructions load from: the
	// literal pools that share .text with the code, found by a pass over
	// every function. Computed on first use.
	xtensaLiterals     map[uint64]bool
	xtensaLiteralsOnce sync.Once

	byName     map[string]int
	byNameOnce sync.Once

	closeMapping func() error
}

// Func is a single function inside a binary.
type Func struct {
	Name string
	Addr uint64
	Size uint64

	bin *Binary
}

// Code returns the machine code of the function, or nil when it lies
// outside the text section. The slice aliases the file mapping and must
// not be modified.
func (f *Func) Code() []byte {
	if f.Addr < f.bin.textAddr {
		return nil
	}
	return sectionSlice(f.bin.text, f.Addr-f.bin.textAddr, f.Size)
}

// Close releases the file mapping.
func (b *Binary) Close() error {
	if b.closeMapping == nil {
		return nil
	}
	err := b.closeMapping()
	b.closeMapping = nil
	return err
}

// Func returns the function called name — the lowest-addressed one
// when several share it — or nil.
func (b *Binary) Func(name string) *Func {
	b.byNameOnce.Do(func() {
		b.byName = make(map[string]int, len(b.Funcs))
		for i, fn := range b.Funcs {
			if _, ok := b.byName[fn.Name]; !ok {
				b.byName[fn.Name] = i
			}
		}
	})
	if i, ok := b.byName[name]; ok {
		return &b.Funcs[i]
	}
	return nil
}

// PCToLine maps a pc to its source location using the Go pclntab, or
// DWARF when there is none; zero values when unknown.
func (b *Binary) PCToLine(pc uint64) (file string, line int) {
	if b.pcln == nil {
		return b.lineTable().At(pc)
	}
	return b.pcln.pcToLine(pc)
}

// FuncFile returns the file a function starting at addr was written in,
// from the debug info; empty when it isn't recorded.
func (b *Binary) FuncFile(addr uint64) string {
	if b.pcln != nil {
		// A Go function's entry instruction is on its declaration
		// line; inlined bodies never own the entry.
		file, _ := b.pcln.pcToLine(addr)
		return file
	}
	return b.lineTable().DeclFile(addr)
}

// lineTable indexes the DWARF on first use; nil when there is none.
func (b *Binary) lineTable() *Lines {
	b.linesOnce.Do(func() {
		if b.dwarf == nil {
			return
		}
		data, err := b.dwarf()
		if err != nil {
			return
		}
		b.lines = LinesFromDWARF(data, 0)
	})
	return b.lines
}

// Contains reports whether addr falls inside any loadable section of
// the binary.
func (b *Binary) Contains(addr uint64) bool {
	for _, r := range b.ranges {
		if r[0] <= addr && addr < r[1] {
			return true
		}
	}
	return false
}

// Lookup resolves addr to the name and base of the symbol containing
// it, text or data, matching the contract of the x/arch GoSyntax symname
// functions.
func (b *Binary) Lookup(addr uint64) (name string, base uint64) {
	if s, ok := b.symAt(addr, symAny); ok {
		return s.name, s.addr
	}
	return "", 0
}

// DataSym resolves addr to the name, base address, and size of the data
// symbol containing it, or zero values when unknown.
func (b *Binary) DataSym(addr uint64) (name string, base, size uint64) {
	if s, ok := b.symAt(addr, symData); ok {
		return s.name, s.addr, s.size
	}
	return "", 0, 0
}

// symAt finds the symbol of the given kind containing addr: the last
// symbol at or before addr, skipping over other kinds so a data symbol
// between two functions does not hide the function before it.
func (b *Binary) symAt(addr uint64, kind symKind) (sym, bool) {
	i, _ := slices.BinarySearchFunc(b.syms, addr, func(s sym, a uint64) int {
		if s.addr > a {
			return 1
		}
		return -1
	})
	for i--; i >= 0; i-- {
		s := b.syms[i]
		if kind != symAny && s.kind != kind {
			continue
		}
		if addr < s.addr+s.size {
			return s, true
		}
		return sym{}, false
	}
	return sym{}, false
}

type symKind uint8

const (
	symText symKind = iota
	symData
	symAny
)

type sym struct {
	name string
	addr uint64
	size uint64 // zero when the format does not record sizes (Mach-O, PE)
	kind symKind
}

// Open maps the binary at path and parses it, detecting ELF, Mach-O,
// PE, wasm and Go compile archives from the magic bytes.
func Open(path string) (*Binary, error) {
	data, closeMapping, err := mmapFile(path)
	if err != nil {
		return nil, err
	}
	bin, err := parse(data)
	if err != nil {
		_ = closeMapping()
		return nil, fmt.Errorf("%q: %w", path, err)
	}
	bin.closeMapping = closeMapping
	if bin.pcln == nil && bin.dwarf == nil {
		bin.loadCompanionDWARF(path)
	}
	return bin, nil
}

// parse dispatches on the magic bytes of a mapped binary.
func parse(data []byte) (*Binary, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("too short to be a binary")
	}
	r := bytes.NewReader(data)
	var bin *Binary
	var err error
	switch magic := string(data[:4]); {
	case magic == elf.ELFMAG:
		bin, err = openELF(r, data)
	case magic == "\xcf\xfa\xed\xfe" || magic == "\xfe\xed\xfa\xcf":
		bin, err = openMachO(r, data)
	case magic[0] == 'M' && magic[1] == 'Z':
		bin, err = openPE(r, data)
	default:
		err = fmt.Errorf("unsupported binary format")
	}
	if err != nil {
		return nil, err
	}
	bin.finish()
	return bin, nil
}

// loadCompanionDWARF reads the line table from a dSYM bundle beside the
// binary. On macOS the linker leaves debug info in the object files and
// dsymutil collects it there, so an executable built with -g carries no
// DWARF of its own.
func (b *Binary) loadCompanionDWARF(path string) {
	dsym := path + ".dSYM/Contents/Resources/DWARF/" + filepath.Base(path)
	if _, err := os.Stat(dsym); err != nil {
		return
	}
	b.dwarf = func() (*dwarf.Data, error) {
		file, err := macho.Open(dsym)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return file.DWARF()
	}
}

// sectionSlice returns data[off:off+size], or nil when the range is
// invalid; overflow-safe for corrupt headers near 2^64.
func sectionSlice(data []byte, off, size uint64) []byte {
	if off > uint64(len(data)) || size > uint64(len(data))-off {
		return nil
	}
	return data[off : off+size]
}

// sectionMarkers are linker boundary symbols; they are not functions or
// variables and would shadow the real symbol at the same address.
var sectionMarkers = map[string]bool{
	"runtime.text": true, "text": true, "_text": true,
	"runtime.etext": true, "etext": true, "_etext": true,
	"runtime.rodata": true, "runtime.erodata": true,
	"runtime.types": true, "runtime.etypes": true,
	"runtime.data": true, "runtime.edata": true, "_data": true, "_edata": true,
	"runtime.bss": true, "runtime.ebss": true, "_bss": true, "_ebss": true,
	"runtime.noptrdata": true, "runtime.enoptrdata": true,
	"runtime.noptrbss": true, "runtime.enoptrbss": true,
	"runtime.end": true, "_end": true, "end": true,
}

func (b *Binary) addSym(name string, addr, size uint64, kind symKind) {
	if sectionMarkers[name] || addr == 0 {
		return
	}
	b.syms = append(b.syms, sym{name: Demangle(name), addr: addr, size: size, kind: kind})
}

// addRange records a loadable section's virtual address range. An end
// that would wrap past 2^64 is clamped to the top of the address space
// so Contains stays correct for corrupt section headers.
func (b *Binary) addRange(addr, size uint64) {
	if size == 0 {
		return
	}
	end := addr + size
	if end < addr {
		end = ^uint64(0)
	}
	b.ranges = append(b.ranges, [2]uint64{addr, end})
}

// Demangle turns a C++ or Rust symbol into the name it had in the
// source, signature and all, so that overloads stay apart. Anything that
// isn't a mangled name — every Go and C symbol — is returned unchanged.
// Rust has two schemes: the older one looks like C++ ("_ZN4prog8sum_ints
// 17h<hash>E"), the current one has its own prefix.
func Demangle(name string) string {
	if !strings.HasPrefix(name, "_Z") && !strings.HasPrefix(name, "_R") {
		return name
	}
	return demangle.Filter(name)
}

// loadPclntab parses a Go runtime pclntab; it gives exact function
// ranges even for stripped binaries. Best-effort: on failure the
// symbol-table functions remain.
func (b *Binary) loadPclntab(pclntab []byte) {
	if len(pclntab) == 0 {
		return
	}
	b.pcln, _ = parsePclntab(pclntab, b.textAddr)
}

// findWasmLineTable scans a reconstructed linear-memory image for a Go
// pclntab and returns a table addressed by wasm PCs: function index plus
// funcValueOffset, shifted left 16, with the resume-point block in the
// low bits. That is the PC the compiler's line deltas are relative to,
// but the table stores function entries unshifted, so the table would
// place every block after the first inside the following function.
// Scaling the stored entries — and only those — puts them back in PC
// space, leaving the deltas to count blocks. nil when there is no
// usable table.
func findWasmLineTable(image []byte) *pclntab {
	tab := findPclntab(image)
	if tab == nil {
		return nil
	}
	tab = bytes.Clone(tab)
	if !scaleWasmEntries(tab) {
		return nil
	}
	t, _ := parsePclntab(tab, 0)
	return t
}

// scaleWasmEntries shifts every function entry in a pclntab left by 16,
// in the function table and in each _func. It reports whether the layout
// was understood and every entry fitted.
func scaleWasmEntries(tab []byte) bool {
	if len(tab) < 8 {
		return false
	}
	ptrSize := int(tab[7])
	if ptrSize != 4 && ptrSize != 8 {
		return false
	}
	// Header: magic, pad, quantum, ptrSize, then ptr-sized nfunc, nfiles,
	// textStart and the offsets of the name, cu, file, pc and func tables.
	field := func(i int) (uint64, bool) {
		off := 8 + i*ptrSize
		if off+ptrSize > len(tab) {
			return 0, false
		}
		if ptrSize == 8 {
			return binary.LittleEndian.Uint64(tab[off:]), true
		}
		return uint64(binary.LittleEndian.Uint32(tab[off:])), true
	}
	nfunc, ok1 := field(0)
	funcTab, ok2 := field(7)
	if !ok1 || !ok2 || nfunc > uint64(len(tab)) {
		return false
	}
	// The function table is nfunc (entryOff, funcOff) uint32 pairs plus a
	// final entryOff marking the end of the text.
	shift := func(off uint64) bool {
		if off+4 > uint64(len(tab)) {
			return false
		}
		v := binary.LittleEndian.Uint32(tab[off:])
		if v >= 1<<16 { // already in PC space, or too many functions
			return false
		}
		binary.LittleEndian.PutUint32(tab[off:], v<<16)
		return true
	}
	for i := uint64(0); i <= nfunc; i++ {
		if !shift(funcTab + i*8) {
			return false
		}
		if i == nfunc {
			break
		}
		funcOff := uint64(binary.LittleEndian.Uint32(tab[funcTab+i*8+4:]))
		// _func starts with its own entryOff.
		if !shift(funcTab + funcOff) {
			return false
		}
	}
	return true
}

// finish sorts symbols, drops duplicates, infers missing sizes as the
// distance to the next symbol, and collects the functions: pclntab
// entries give exact ranges even when the binary is stripped, the
// symbol table supplies the rest.
func (b *Binary) finish() {
	if b.pcln != nil {
		b.syms = slices.Grow(b.syms, b.pcln.nfunc)
		b.pcln.funcs(func(name string, entry, end uint64) bool {
			b.addSym(name, entry, end-entry, symText)
			return true
		})
	}
	// The last symbol at or before an address wins a lookup; ties are
	// broken by name so aliases (f and f.abi0) resolve the same way in
	// every binary. A function known to both the symbol table and the
	// pclntab keeps the larger extent, the pclntab's: it runs to the
	// next function, covering the alignment padding.
	slices.SortFunc(b.syms, func(x, y sym) int {
		return cmp.Or(cmp.Compare(x.addr, y.addr), cmp.Compare(x.name, y.name), cmp.Compare(y.size, x.size))
	})
	b.syms = slices.CompactFunc(b.syms, func(x, y sym) bool {
		return x.addr == y.addr && x.name == y.name && x.kind == y.kind
	})
	textEnd := b.textAddr + uint64(len(b.text))
	for i := range b.syms {
		s := &b.syms[i]
		if s.size != 0 {
			continue
		}
		for _, next := range b.syms[i+1:] {
			if next.addr != s.addr && next.kind == s.kind {
				s.size = next.addr - s.addr
				break
			}
		}
		if s.size == 0 {
			// Last of its kind: bound it by its section instead of
			// infinity, so unrelated high addresses don't resolve to it.
			end := textEnd
			if s.kind == symData {
				end = 0
				for _, r := range b.ranges {
					if r[0] <= s.addr && s.addr < r[1] {
						end = r[1]
						break
					}
				}
			}
			if s.addr < end {
				s.size = end - s.addr
			}
		}
	}

	b.Funcs = make([]Func, 0, len(b.syms))
	for _, s := range b.syms {
		if s.kind == symText && s.addr >= b.textAddr && s.addr < textEnd {
			b.Funcs = append(b.Funcs, Func{Name: s.name, Addr: s.addr, Size: s.size, bin: b})
		}
	}
	b.Funcs = slices.Clip(b.Funcs)
}

// pclntabMagics are the little-endian header magics of pclntab versions.
var pclntabMagics = [][]byte{
	{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00}, // Go 1.20+
	{0xf0, 0xff, 0xff, 0xff, 0x00, 0x00}, // Go 1.18–1.19
	{0xfa, 0xff, 0xff, 0xff, 0x00, 0x00}, // Go 1.16–1.17
}

// findPclntab locates a pclntab inside data by its header: a version
// magic followed by a plausible pc quantum and pointer size. It is the
// fallback for binaries without a dedicated section: PE always, and ELF
// when the system linker merged it into another data section.
func findPclntab(data []byte) []byte {
	for _, magic := range pclntabMagics {
		for off := 0; ; off += len(magic) {
			i := bytes.Index(data[off:], magic)
			if i < 0 {
				break
			}
			off += i
			if off+8 <= len(data) {
				quantum, ptrsize := data[off+6], data[off+7]
				if (quantum == 1 || quantum == 4) && (ptrsize == 4 || ptrsize == 8) {
					return data[off:]
				}
			}
		}
	}
	return nil
}

// elfSym is one symbol table entry, read in place.
type elfSym struct {
	name  string // aliases the string table
	value uint64
	size  uint64
	info  uint8
	shndx elf.SectionIndex
}

// elfSymbols walks the symbol table without copying it: entries are
// decoded from the mapping and names are views into .strtab. f returns
// false to stop.
func elfSymbols(ef *elf.File, data []byte, f func(elfSym) bool) error {
	symtab := ef.SectionByType(elf.SHT_SYMTAB)
	if symtab == nil {
		return nil
	}
	if int(symtab.Link) >= len(ef.Sections) {
		return fmt.Errorf("bad symtab link")
	}
	strtab := ef.Sections[symtab.Link]
	if symtab.Flags&elf.SHF_COMPRESSED != 0 || strtab.Flags&elf.SHF_COMPRESSED != 0 {
		return fmt.Errorf("compressed symbol table")
	}
	entries := sectionSlice(data, symtab.Offset, symtab.FileSize)
	strs := sectionSlice(data, strtab.Offset, strtab.FileSize)
	if entries == nil || strs == nil {
		return fmt.Errorf("unreadable symbol table")
	}
	name := func(off uint32) string {
		if off >= uint32(len(strs)) {
			return ""
		}
		end := bytes.IndexByte(strs[off:], 0)
		if end < 0 {
			end = len(strs) - int(off)
		}
		return unsafe.String(&strs[off], end)
	}
	ord := ef.ByteOrder
	entrySize := 16
	if ef.Class == elf.ELFCLASS64 {
		entrySize = 24
	}
	// The first entry is the reserved null symbol.
	for off := entrySize; off+entrySize <= len(entries); off += entrySize {
		e := entries[off:]
		var s elfSym
		if ef.Class == elf.ELFCLASS64 {
			s = elfSym{
				name:  name(ord.Uint32(e)),
				info:  e[4],
				shndx: elf.SectionIndex(ord.Uint16(e[6:])),
				value: ord.Uint64(e[8:]),
				size:  ord.Uint64(e[16:]),
			}
		} else {
			s = elfSym{
				name:  name(ord.Uint32(e)),
				value: uint64(ord.Uint32(e[4:])),
				size:  uint64(ord.Uint32(e[8:])),
				info:  e[12],
				shndx: elf.SectionIndex(ord.Uint16(e[14:])),
			}
		}
		if !f(s) {
			return nil
		}
	}
	return nil
}

// elfSection returns a section's file-backed contents as a slice into
// the mapping, or nil when it is absent, compressed, or out of range.
func elfSection(ef *elf.File, data []byte, name string) []byte {
	sec := ef.Section(name)
	if sec == nil || sec.Type == elf.SHT_NOBITS || sec.Flags&elf.SHF_COMPRESSED != 0 {
		return nil
	}
	return sectionSlice(data, sec.Offset, sec.FileSize)
}

// elfDWARF builds the DWARF reader over the mapping without copying the
// debug sections. Compressed sections (SHF_COMPRESSED or .zdebug_*) fall
// back to debug/elf, which decompresses into memory.
func elfDWARF(ef *elf.File, data []byte) (*dwarf.Data, error) {
	for _, sec := range ef.Sections {
		if strings.HasPrefix(sec.Name, ".zdebug_") || (strings.HasPrefix(sec.Name, ".debug_") && sec.Flags&elf.SHF_COMPRESSED != 0) {
			return ef.DWARF()
		}
	}
	get := func(name string) []byte { return elfSection(ef, data, ".debug_"+name) }
	if get("info") == nil {
		return nil, fmt.Errorf("no DWARF")
	}
	d, err := dwarf.New(get("abbrev"), get("aranges"), get("frame"), get("info"), get("line"), get("pubnames"), get("ranges"), get("str"))
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"addr", "line_str", "str_offsets", "rnglists", "loclists"} {
		if s := get(name); s != nil {
			if err := d.AddSection(".debug_"+name, s); err != nil {
				return nil, err
			}
		}
	}
	return d, nil
}

func openELF(r *bytes.Reader, data []byte) (*Binary, error) {
	ef, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	bin := &Binary{byteOrder: binary.LittleEndian}
	switch ef.Machine {
	case elf.EM_X86_64:
		bin.Arch = "amd64"
	case elf.EM_AARCH64:
		bin.Arch = "arm64"
	case elf.EM_386:
		bin.Arch = "386"
	case elf.EM_ARM:
		bin.Arch = "arm"
	case elf.EM_S390:
		bin.Arch = "s390x"
	case elf.EM_PPC64:
		bin.Arch = "ppc64le"
		if ef.ByteOrder == binary.BigEndian {
			bin.Arch, bin.byteOrder = "ppc64", binary.BigEndian
		}
	case elf.EM_RISCV:
		// RV32 (e.g. TinyGo for ESP32-C3) shares RV64's encoding; the
		// riscv64 decoder handles it, only the label differs.
		bin.Arch = "riscv64"
		if ef.Class == elf.ELFCLASS32 {
			bin.Arch = "riscv32"
		}
	case elf.EM_LOONGARCH:
		bin.Arch = "loong64"
	case elf.EM_AVR:
		bin.Arch = "avr"
	case elf.EM_XTENSA:
		bin.Arch = "xtensa"
	default:
		return nil, fmt.Errorf("unsupported ELF machine %v", ef.Machine)
	}
	if ef.Class != elf.ELFCLASS64 && bin.Arch != "386" && bin.Arch != "arm" && bin.Arch != "riscv32" && bin.Arch != "avr" && bin.Arch != "xtensa" {
		return nil, fmt.Errorf("unsupported 32-bit ELF for %s", bin.Arch)
	}

	text := ef.Section(".text")
	if text == nil {
		return nil, fmt.Errorf("no .text section")
	}
	bin.text = elfSection(ef, data, ".text")
	if bin.text == nil {
		return nil, fmt.Errorf("unreadable .text section")
	}
	bin.textAddr = text.Addr
	for _, sec := range ef.Sections {
		if sec.Flags&elf.SHF_ALLOC != 0 {
			bin.addRange(sec.Addr, sec.Size)
		}
	}

	var arm32 armRegionsBuilder
	err = elfSymbols(ef, data, func(s elfSym) bool {
		switch elf.ST_TYPE(s.info) {
		case elf.STT_FUNC:
			addr := s.value
			if bin.Arch == "arm" {
				// A Thumb function's symbol value has bit 0 set to mark
				// the instruction set; the code itself is at the even
				// address.
				addr &^= 1
				arm32.addFunc(s.value)
			}
			bin.addSym(s.name, addr, s.size, symText)
		case elf.STT_OBJECT:
			bin.addSym(s.name, s.value, s.size, symData)
		case elf.STT_NOTYPE:
			if bin.Arch == "arm" {
				arm32.addMapping(s.name, s.value, bin.textAddr, bin.textAddr+uint64(len(bin.text)))
			}
		}
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("reading symbols: %w", err)
	}
	if bin.Arch == "arm" {
		bin.arm32 = arm32.regions()
	}

	bin.dwarf = func() (*dwarf.Data, error) { return elfDWARF(ef, data) }
	if tab := elfSection(ef, data, ".gopclntab"); tab != nil {
		bin.loadPclntab(tab)
	} else if ef.Section(".gopclntab") == nil {
		// The system linker (cgo, external linking) emits no dedicated
		// section; the pclntab lands inside another data section,
		// commonly .data.rel.ro. Scan them all.
		for _, sec := range ef.Sections {
			if sec.Type == elf.SHT_PROGBITS && sec.Flags&elf.SHF_ALLOC != 0 && sec.Flags&elf.SHF_EXECINSTR == 0 {
				if tab := findPclntab(elfSection(ef, data, sec.Name)); tab != nil {
					bin.loadPclntab(tab)
					break
				}
			}
		}
	}
	return bin, nil
}

func openMachO(r *bytes.Reader, data []byte) (*Binary, error) {
	mf, err := macho.NewFile(r)
	if err != nil {
		return nil, err
	}
	bin := &Binary{byteOrder: binary.LittleEndian}
	switch mf.Cpu {
	case macho.CpuAmd64:
		bin.Arch = "amd64"
	case macho.CpuArm64:
		bin.Arch = "arm64"
	default:
		return nil, fmt.Errorf("unsupported Mach-O cpu %v", mf.Cpu)
	}

	text := mf.Section("__text")
	if text == nil {
		return nil, fmt.Errorf("no __text section")
	}
	bin.text = sectionSlice(data, uint64(text.Offset), text.Size)
	if bin.text == nil {
		return nil, fmt.Errorf("unreadable __text section")
	}
	bin.textAddr = text.Addr
	for _, seg := range mf.Loads {
		if seg, ok := seg.(*macho.Segment); ok && seg.Name != "__PAGEZERO" {
			bin.addRange(seg.Addr, seg.Memsz)
		}
	}

	if mf.Symtab != nil {
		for _, s := range mf.Symtab.Syms {
			// 0xe0 masks the N_STAB debugging bits; such entries
			// describe source info, not symbols.
			if s.Type&0xe0 != 0 {
				continue
			}
			kind := symData
			if s.Value >= bin.textAddr && s.Value < bin.textAddr+uint64(len(bin.text)) {
				kind = symText
			}
			bin.addSym(strings.TrimPrefix(s.Name, "_"), s.Value, 0, kind)
		}
	}
	if sec := mf.Section("__gopclntab"); sec != nil {
		if tab := sectionSlice(data, uint64(sec.Offset), sec.Size); tab != nil {
			bin.loadPclntab(tab)
		}
	}
	bin.dwarf = mf.DWARF
	return bin, nil
}

func openPE(r *bytes.Reader, data []byte) (*Binary, error) {
	pf, err := pe.NewFile(r)
	if err != nil {
		return nil, err
	}
	bin := &Binary{byteOrder: binary.LittleEndian}
	switch pf.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		bin.Arch = "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		bin.Arch = "arm64"
	case pe.IMAGE_FILE_MACHINE_I386:
		bin.Arch = "386"
	default:
		return nil, fmt.Errorf("unsupported PE machine %#x", pf.Machine)
	}

	var imageBase uint64
	switch hdr := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		imageBase = hdr.ImageBase
	case *pe.OptionalHeader32:
		imageBase = uint64(hdr.ImageBase)
	default:
		return nil, fmt.Errorf("missing PE optional header")
	}

	text := pf.Section(".text")
	if text == nil {
		return nil, fmt.Errorf("no .text section")
	}
	// The on-disk section can be padded past its virtual size.
	bin.text = sectionSlice(data, uint64(text.Offset), min(uint64(text.Size), uint64(text.VirtualSize)))
	if bin.text == nil {
		return nil, fmt.Errorf("unreadable .text section")
	}
	bin.textAddr = imageBase + uint64(text.VirtualAddress)
	for _, sec := range pf.Sections {
		bin.addRange(imageBase+uint64(sec.VirtualAddress), uint64(sec.VirtualSize))
	}

	// COFF symbol values are offsets within their 1-based section.
	for _, s := range pf.Symbols {
		if s.SectionNumber <= 0 || int(s.SectionNumber) > len(pf.Sections) {
			continue
		}
		sec := pf.Sections[s.SectionNumber-1]
		kind := symData
		if sec == text {
			kind = symText
		}
		bin.addSym(s.Name, imageBase+uint64(sec.VirtualAddress)+uint64(s.Value), 0, kind)
	}

	bin.dwarf = pf.DWARF
	// PE has no pclntab section; scan the data sections for its header.
	for _, name := range []string{".rdata", ".data"} {
		if sec := pf.Section(name); sec != nil {
			raw := sectionSlice(data, uint64(sec.Offset), min(uint64(sec.Size), uint64(sec.VirtualSize)))
			if tab := findPclntab(raw); tab != nil {
				bin.loadPclntab(tab)
				break
			}
		}
	}
	return bin, nil
}
