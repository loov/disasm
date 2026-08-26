package objfile

import (
	"debug/dwarf"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/eliben/watgo"
	"github.com/eliben/watgo/wasmir"
)

// WebAssembly has no virtual addresses. Func.Addr is the function's
// index in its module's function index space (imports first, then
// defined functions), which is what call instructions name, and
// Func.Size is the body size in bytes. Inst.Addr is whatever the
// module's own line table is keyed by: for a Go module the runtime's
// PC (function index plus wasmPCBase, shifted left 16, with the resume
// block below), for a module with DWARF the instruction's byte offset
// in the file, and otherwise the instruction's 1-based ordinal.
//
// A component (the component model's container, as TinyGo's wasip2
// target emits) shares the magic of a core module and carries its core
// modules nested inside; every one is loaded, and their functions are
// qualified by the module's name when there is more than one.

// wasm section ids used by the loader.
const (
	wasmSecCustom = 0
	wasmSecImport = 2
	wasmSecMemory = 5
	wasmSecCode   = 10
	wasmSecData   = 11

	componentCoreModuleID = 1
	componentNestedID     = 4
)

// wasmPCBase is the first function "address" the Go linker assigns on
// wasm (funcValueOffset in cmd/link).
const wasmPCBase = 0x1000

// wasmModule is one core module and what it takes to read code out of
// it.
type wasmModule struct {
	data []byte // the module's bytes, a slice of the file
	base uint64 // offset of data in the file, so instruction offsets are file offsets
	// names maps the function index space to names, for resolving call
	// targets; imports first.
	names   []string
	imports int
	// pcln is the Go line table recovered from the data segments,
	// keyed by wasm PC; nil for non-Go modules.
	pcln *pclntab
	// debug holds the DWARF custom sections, which TinyGo and clang
	// emit instead of a pclntab, indexed on first use.
	debug     map[string][]byte
	codeStart uint64 // offset of the code section payload in data
	bodies    []codeRange
	lines     *lines
	linesOnce sync.Once
}

// codeRange is the position of one function body in the module: its
// bytes after the entry's size prefix, starting with the locals vector.
type codeRange struct{ start, size uint64 }

// wasmSeg is one active data segment: init is copied to linear-memory
// offset off at instantiation.
type wasmSeg struct {
	off  int64
	init []byte
}

func openWasm(data []byte) (*Binary, error) {
	modules := [][]byte{data}
	if isComponent(data) {
		if modules = coreModules(data); len(modules) == 0 {
			return nil, fmt.Errorf("component holds no core module")
		}
	}
	bin := &Binary{Arch: "wasm"}
	var firstErr error
	for i, mod := range modules {
		m, err := bin.loadWasmModule(mod, uint64(sliceOffset(data, mod)), i, len(modules) > 1)
		if err != nil {
			if len(modules) == 1 {
				return nil, err
			}
			// One unreadable adapter should not hide the program.
			if firstErr == nil {
				firstErr = fmt.Errorf("core module %d: %w", i, err)
			}
			continue
		}
		bin.wasm = append(bin.wasm, m)
	}
	if len(bin.wasm) == 0 {
		return nil, firstErr
	}
	bin.finish()
	return bin, nil
}

// sliceOffset returns where sub starts within data; sub must alias it.
func sliceOffset(data, sub []byte) int {
	if len(sub) == 0 {
		return 0
	}
	return int(uintptr(unsafe.Pointer(unsafe.SliceData(sub))) - uintptr(unsafe.Pointer(unsafe.SliceData(data))))
}

// loadWasmModule reads a module's sections: function bodies from the
// code section; names from the embedded Go pclntab when present (exact
// symbol names) and otherwise from the name section, whose names the
// Go linker sanitizes ("internal/abi.(*Type)" becomes
// "internal_abi.__Type_"). When qualify is set the names are prefixed
// by the module's own name, for components.
func (b *Binary) loadWasmModule(data []byte, base uint64, index int, qualify bool) (*wasmModule, error) {
	if len(data) < 8 || string(data[:4]) != "\x00asm" {
		return nil, fmt.Errorf("not a wasm module")
	}
	m := &wasmModule{data: data, base: base}
	var (
		importNames []string
		nameSec     = map[uint64]string{}
		moduleName  string
		segs        []wasmSeg
		memPages    uint64
	)
	c := &wasmCursor{data: data, pos: 8}
	for c.pos < len(data) && !c.fail {
		id := c.byte()
		size := c.uint()
		start := c.pos
		payload := c.bytes(size)
		if c.fail {
			return nil, fmt.Errorf("truncated wasm section %d", id)
		}
		sec := &wasmCursor{data: payload}
		switch id {
		case wasmSecCustom:
			switch name := sec.name(); {
			case name == "name":
				moduleName = parseWasmNames(sec, nameSec)
			case strings.HasPrefix(name, ".debug_"):
				if m.debug == nil {
					m.debug = map[string][]byte{}
				}
				m.debug[name] = payload[sec.pos:]
			}
		case wasmSecImport:
			importNames = parseWasmImports(sec)
		case wasmSecMemory:
			if sec.uint() > 0 {
				flags := sec.byte()
				if pages := sec.uint(); !sec.fail && flags&4 == 0 {
					memPages = pages
				}
			}
		case wasmSecCode:
			m.codeStart = uint64(start)
			for range sec.uint() {
				n := sec.uint()
				bodyStart := start + sec.pos
				sec.bytes(n)
				if sec.fail {
					// Checked inside the loop: the declared count is
					// attacker-controlled and reads past the end are
					// no-ops, so an unchecked loop would spin on a
					// huge count in a tiny section.
					return nil, fmt.Errorf("malformed wasm code section")
				}
				m.bodies = append(m.bodies, codeRange{uint64(bodyStart), n})
			}
		case wasmSecData:
			segs = parseWasmData(sec)
		}
	}
	if c.fail {
		return nil, fmt.Errorf("malformed wasm module")
	}

	prefix := ""
	if qualify {
		prefix = moduleName + "/"
		if moduleName == "" {
			prefix = fmt.Sprintf("module%d/", index)
		}
	}
	m.imports = len(importNames)
	m.names = make([]string, m.imports+len(m.bodies))
	for i, name := range importNames {
		m.names[i] = prefix + name
	}
	for i := range m.bodies {
		m.names[m.imports+i] = Demangle(nameSec[uint64(m.imports+i)])
	}
	if image := wasmImage(segs); image != nil {
		if t := findWasmLineTable(image); t != nil && t.nfunc == len(m.bodies) {
			// On wasm a function's pclntab entry is its position in
			// code-section order, so the i-th entry names the i-th
			// defined function; a count mismatch means the layout
			// assumption does not hold and the name section stands.
			m.pcln = t
			i := 0
			t.funcs(func(name string, _, _ uint64) bool {
				m.names[m.imports+i] = name
				i++
				return true
			})
		}
	}
	for i, body := range m.bodies {
		idx := m.imports + i
		if m.names[idx] == "" {
			m.names[idx] = fmt.Sprintf("func%d", idx)
		}
		m.names[idx] = prefix + m.names[idx]
		b.Funcs = append(b.Funcs, Func{
			Name: m.names[idx],
			Addr: uint64(idx),
			Size: body.size,
			bin:  b,
			code: data[body.start : body.start+body.size],
			wasm: m,
		})
	}

	// One range from the start of initialized data to the end of the
	// initial memory, for recognizing address-valued constants: global
	// data, including bss past the initialized segments, lives there.
	// An ordinary large constant inside the range is masked too, an
	// inherent ambiguity of wasm's flat low address space.
	var lo, hi int64
	for _, s := range segs {
		if lo == 0 || s.off < lo {
			lo = s.off
		}
		if end := s.off + int64(len(s.init)); end > hi {
			hi = end
		}
	}
	if memPages > 65536 {
		memPages = 65536 // wasm spec maximum; also keeps the multiply below in range
	}
	if memEnd := int64(memPages) * 64 * 1024; memEnd > hi {
		hi = memEnd
	}
	if lo < hi {
		b.addRange(uint64(lo), uint64(hi-lo))
	}
	// Go wasm PCs encode a function as wasmPCBase plus its position in
	// the code section, shifted left by 16, with a block index in the
	// low bits. Function bodies materialize such PCs as i64.const
	// immediates (resumption points, function values); covering the PC
	// space lets callers treat them as addresses.
	b.addRange(wasmPCBase<<16, uint64(len(m.bodies))<<16)
	return m, nil
}

// lookup resolves a function index to its name.
func (m *wasmModule) lookup(index uint64) (string, uint64) {
	if index < uint64(len(m.names)) {
		return m.names[index], index
	}
	return "", 0
}

// lineTable reads the DWARF line table from the module's custom
// sections on first use. Its addresses are offsets within the code
// section, shifted here to file offsets. nil when there is no DWARF,
// or when the addresses do not line up with the functions: wasm-opt
// and friends rewrite code without updating DWARF, and lines from a
// stale table would be confidently wrong.
func (m *wasmModule) lineTable() *lines {
	m.linesOnce.Do(func() {
		if m.debug[".debug_line"] == nil || m.debug[".debug_info"] == nil {
			return
		}
		data, err := dwarf.New(m.debug[".debug_abbrev"], m.debug[".debug_aranges"], nil,
			m.debug[".debug_info"], m.debug[".debug_line"], nil,
			m.debug[".debug_ranges"], m.debug[".debug_str"])
		if err != nil {
			return
		}
		for _, name := range []string{".debug_addr", ".debug_line_str", ".debug_str_offsets", ".debug_rnglists"} {
			if s := m.debug[name]; s != nil {
				_ = data.AddSection(name, s)
			}
		}
		shift := int64(m.base + m.codeStart)
		if !m.describesBodies(data) {
			return
		}
		m.lines = linesFromDWARF(data, shift)
	})
	return m.lines
}

// describesBodies reports whether the DWARF still matches the module:
// every subprogram entry names the start of a real function body. One
// that does not means the code moved after the debug info was written.
func (m *wasmModule) describesBodies(data *dwarf.Data) bool {
	starts := make(map[uint64]bool, len(m.bodies))
	for _, body := range m.bodies {
		starts[body.start] = true
	}
	found := 0
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}
		if entry.Tag != dwarf.TagSubprogram {
			continue
		}
		low, ok := entry.Val(dwarf.AttrLowpc).(uint64)
		if !ok || low == 0 {
			continue
		}
		if !starts[low+m.codeStart] {
			return false
		}
		found++
	}
	return found > 0
}

// pcToLine maps an instruction address of this module to a position.
func (m *wasmModule) pcToLine(addr uint64) (string, int) {
	if m.pcln != nil {
		file, line := m.pcln.pcToLine(addr)
		if line < 0 {
			return "", 0
		}
		return file, line
	}
	return m.lineTable().At(addr)
}

// disassembleWasm renders one function body. watgo decodes whole
// modules only, so the body is wrapped into a synthetic single-function
// module and decoded; the body's own instructions give call targets,
// resume blocks and encoded sizes. For the text, the body is printed
// as a sequence of functions, each ending at an instruction that opens
// a block: watgo indents by block depth, and Go compiles a large
// switch into a br_table over blocks nested thousands deep, so
// printing the body as-is costs instructions×depth bytes of
// whitespace (gigabytes for one function). Cut this way no function
// nests, and the printer does not require a closing end, so the
// functions alias the decoded body without copying.
func (b *Binary) disassembleWasm(fn *Func) ([]Inst, error) {
	m := fn.wasm
	module, err := watgo.DecodeWASM(wrapWasmBody(fn.code))
	if err != nil {
		return nil, fmt.Errorf("decoding wasm body: %w", err)
	}
	f := module.Funcs[0]

	// The body's final end closes the function: the printer drops a
	// trailing end, so it is not an instruction of the listing.
	body := f.Body
	flat := &wasmir.Module{Types: module.Types}
	start := 0
	for i, in := range body {
		switch in.Kind {
		case wasmir.InstrBlock, wasmir.InstrLoop, wasmir.InstrIf, wasmir.InstrTryTable, wasmir.InstrElse:
			flat.Funcs = append(flat.Funcs, wasmir.Function{Body: body[start : i+1]})
			start = i + 1
		}
	}
	if start < len(body) {
		flat.Funcs = append(flat.Funcs, wasmir.Function{Body: body[start:]})
	}
	wat, err := watgo.PrintWAT(flat)
	if err != nil {
		return nil, fmt.Errorf("rendering wasm body: %w", err)
	}

	// Addresses, by what the module's line table is keyed on.
	var offsets []uint64
	var blocks []int
	switch {
	case m.pcln != nil:
		blocks = resumeBlocks(f.Body)
	case m.lineTable() != nil:
		offsets = instructionOffsets(m, fn, f)
	}
	index := int(fn.Addr) - m.imports

	var insts []Inst
	// Each function prints one instruction per line between "(func" and
	// its closing ")", in body order.
	for line := range strings.Lines(string(wat)) {
		text := strings.TrimSpace(line)
		if text == "" || strings.HasPrefix(text, "(") || strings.HasPrefix(text, ")") {
			continue
		}
		i := len(insts)
		if i >= len(f.Body) {
			break
		}
		op, rest, _ := strings.Cut(text, " ")
		inst := Inst{Op: op, Text: text}
		switch {
		case offsets != nil:
			inst.Addr = offsets[i]
			if i+1 < len(offsets) {
				inst.Len = int(offsets[i+1] - offsets[i])
			} else {
				inst.Len = int(m.base + fn.wasmBody().start + fn.Size - offsets[i])
			}
		case blocks != nil:
			inst.Addr = uint64(wasmPCBase+index)<<16 | uint64(blocks[i])
		default:
			inst.Addr = uint64(i + 1)
		}
		if f.Body[i].Kind == wasmir.InstrCall {
			// ponytail: only plain call is symbolized; Go does not
			// emit return_call or ref.func in function bodies.
			inst.RefKnown, inst.Call, inst.Ref = true, true, uint64(f.Body[i].FuncIndex)
			if idx, err := strconv.ParseUint(rest, 10, 64); err == nil {
				if name, _ := m.lookup(idx); name != "" {
					inst.Text = "call " + name
				}
			}
		}
		insts = append(insts, inst)
	}
	return insts, nil
}

// wasmBody is the position of the function's body in its module.
func (fn *Func) wasmBody() codeRange {
	return fn.wasm.bodies[int(fn.Addr)-fn.wasm.imports]
}

// resumeBlocks returns, for each instruction of body, the index of the
// resume point it belongs to, the PC_B half of its Go PC. The compiler
// wraps a function's body in one block per resume point and dispatches
// on PC_B through a br_table, so after that dispatch each block that
// ends moves execution into the next resume point.
func resumeBlocks(body []wasmir.Instruction) []int {
	blocks := make([]int, len(body))
	depth, block := 0, 0
	// dispatched turns on at the end that closes the br_table's block;
	// resumeDepth is then the depth of the innermost resume block.
	dispatched, sawTable, resumeDepth := false, false, 0
	for i, in := range body {
		if in.Kind == wasmir.InstrEnd {
			depth--
			switch {
			case !dispatched && sawTable:
				dispatched, resumeDepth = true, depth
			case dispatched && depth == resumeDepth-1:
				block++
				resumeDepth--
			}
		}
		blocks[i] = block
		switch in.Kind {
		case wasmir.InstrBlock, wasmir.InstrLoop, wasmir.InstrIf:
			depth++
		case wasmir.InstrBrTable:
			sawTable = true
		}
	}
	return blocks
}

// instructionOffsets returns the file offset of every instruction in
// the body, for looking up DWARF rows. Lengths come from re-encoding
// each instruction, and the total is checked against the bytes the
// function actually occupies: a module whose encoding differs from
// watgo's (a non-canonical integer, an instruction it round-trips
// differently) would otherwise shift every later offset silently. nil
// when the body is unreadable or the check fails.
func instructionOffsets(m *wasmModule, fn *Func, f wasmir.Function) []uint64 {
	locals := localsSize(fn.code)
	if locals < 0 {
		return nil
	}
	// Encoding a body of just "end" gives the fixed cost of the wrapper
	// module, so each instruction's length is what it adds to that.
	empty, ok := encodedSize(f.Locals, []wasmir.Instruction{{Kind: wasmir.InstrEnd}})
	if !ok {
		return nil
	}
	body := fn.wasmBody()
	offsets := make([]uint64, len(f.Body))
	next := m.base + body.start + uint64(locals)
	for i, instruction := range f.Body {
		size, ok := encodedSize(f.Locals, []wasmir.Instruction{instruction, {Kind: wasmir.InstrEnd}})
		if !ok {
			return nil
		}
		offsets[i] = next
		next += uint64(size - empty)
	}
	if next != m.base+body.start+body.size {
		return nil
	}
	return offsets
}

// encodedSize is the size of a module holding one function with this
// body; only differences between calls are meaningful.
func encodedSize(locals []wasmir.ValueType, body []wasmir.Instruction) (int, bool) {
	encoded, err := watgo.EncodeWASM(&wasmir.Module{
		Types: []wasmir.TypeDef{{Kind: wasmir.TypeDefKindFunc}},
		Funcs: []wasmir.Function{{Locals: locals, Body: body}},
	})
	if err != nil {
		return 0, false
	}
	return len(encoded), true
}

// localsSize returns the byte length of the locals vector a function
// body starts with, or -1 when it is malformed.
func localsSize(body []byte) int {
	c := &wasmCursor{data: body}
	for range c.uint() {
		c.uint() // count
		c.byte() // value type
	}
	if c.fail {
		return -1
	}
	return c.pos
}

// wrapWasmBody builds a minimal module holding body as its only
// function, under a synthetic void signature: the real signature lives
// in the original module's type section and is not needed to render
// the body.
func wrapWasmBody(body []byte) []byte {
	mod := []byte("\x00asm\x01\x00\x00\x00")
	mod = append(mod, 1, 4, 1, 0x60, 0, 0) // type section: () -> ()
	mod = append(mod, 3, 2, 1, 0)          // function section: [type 0]
	entry := appendUleb([]byte{1}, uint64(len(body)))
	entry = append(entry, body...)
	mod = append(mod, 10)
	mod = appendUleb(mod, uint64(len(entry)))
	return append(mod, entry...)
}

// appendUleb appends v as an unsigned LEB128.
func appendUleb(dst []byte, v uint64) []byte {
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			c |= 0x80
		}
		dst = append(dst, c)
		if v == 0 {
			return dst
		}
	}
}

// parseWasmImports returns the names of imported functions as
// "module.field", in function index order. Non-function imports are
// skipped over.
func parseWasmImports(sec *wasmCursor) []string {
	var names []string
	for range sec.uint() {
		module := sec.name()
		field := sec.name()
		switch sec.byte() {
		case 0x00: // function
			sec.uint()
			names = append(names, module+"."+field)
		case 0x01: // table
			sec.byte()
			sec.skipLimits()
		case 0x02: // memory
			sec.skipLimits()
		case 0x03: // global
			sec.byte()
			sec.byte()
		case 0x04: // tag
			sec.byte()
			sec.uint()
		default:
			sec.fail = true
		}
		if sec.fail {
			return nil
		}
	}
	return names
}

// parseWasmNames reads the standard "name" custom section: the module
// name, which it returns, and the function names, filled into out by
// function index.
func parseWasmNames(sec *wasmCursor, out map[uint64]string) (module string) {
	for sec.pos < len(sec.data) && !sec.fail {
		id := sec.byte()
		sub := &wasmCursor{data: sec.bytes(sec.uint())}
		switch id {
		case 0: // module name
			module = sub.name()
		case 1: // function names
			for range sub.uint() {
				idx := sub.uint()
				name := sub.name()
				if sub.fail {
					break // huge declared count in a tiny subsection
				}
				out[idx] = name
			}
		}
	}
	return module
}

// parseWasmData returns the active data segments with constant
// offsets. Parsing stops at the first unsupported form; the segments
// only feed pclntab recovery and address recognition, both of which
// degrade gracefully.
func parseWasmData(sec *wasmCursor) []wasmSeg {
	var segs []wasmSeg
	for range sec.uint() {
		flags := sec.uint()
		switch flags {
		case 1: // passive
			sec.bytes(sec.uint())
			continue
		case 0, 2: // active
			if flags == 2 {
				sec.uint() // memory index
			}
		default:
			return segs
		}
		var off int64
		switch sec.byte() {
		case 0x41: // i32.const
			off = sec.sint()
		case 0x42: // i64.const
			off = sec.sint()
		default:
			return segs
		}
		if sec.byte() != 0x0b { // end
			return segs
		}
		init := sec.bytes(sec.uint())
		if sec.fail || off < 0 {
			return segs
		}
		segs = append(segs, wasmSeg{off: off, init: init})
	}
	return segs
}

// wasmMaxImage caps the reconstructed linear-memory image used for
// pclntab recovery.
const wasmMaxImage int64 = 512 << 20

// wasmImage reconstructs the module's initialized memory from its
// active data segments, where a Go module's pclntab lives. It gives up
// on a segment placed implausibly far past the data actually present:
// a hostile module can name a huge offset with a few bytes of payload,
// and allocating for it is an OOM vector. The Go linker skips zero
// runs, emitting tens of thousands of small segments, so the image is
// larger than the initialized bytes by the zeroed data in between: a
// 50 MB module has 2 MB of gaps over 22 MB of segments. Several times
// the initialized size is still far from hostile.
func wasmImage(segs []wasmSeg) []byte {
	var end, total int64
	var hasPclntab bool
	for _, s := range segs {
		n := int64(len(s.init))
		if s.off < 0 || n > wasmMaxImage || s.off > wasmMaxImage-n || total > wasmMaxImage-n {
			return nil
		}
		if e := s.off + n; e > end {
			end = e
		}
		total += n
		hasPclntab = hasPclntab || findPclntab(s.init) != nil
	}
	if !hasPclntab || end <= 0 || end > 4*total+1<<20 {
		return nil
	}
	mem := make([]byte, end)
	for _, s := range segs {
		copy(mem[s.off:], s.init)
	}
	return mem
}

// isComponent reports whether data starts with a component header: the
// magic of a core module, with the component-model layer and version.
func isComponent(data []byte) bool {
	return len(data) >= 8 && string(data[:4]) == "\x00asm" &&
		data[4] == 0x0d && data[5] == 0x00 && data[6] == 0x01 && data[7] == 0x00
}

// coreModules returns every core module a component embeds, outermost
// first, descending into nested components. Modules are stored whole,
// so each one is returned as its own module binary, aliasing data.
func coreModules(data []byte) [][]byte {
	// A component nests components nests components; the limit is only
	// there so a malformed file cannot recurse without end.
	const maxDepth = 8
	var collect func(data []byte, depth int) [][]byte
	collect = func(data []byte, depth int) [][]byte {
		var out [][]byte
		if depth > maxDepth {
			return out
		}
		c := &wasmCursor{data: data, pos: 8}
		for c.pos < len(data) && !c.fail {
			id := c.byte()
			size := c.uint()
			payload := c.bytes(size)
			if c.fail {
				return out
			}
			switch id {
			case componentCoreModuleID:
				out = append(out, payload)
			case componentNestedID:
				out = append(out, collect(payload, depth+1)...)
			}
		}
		return out
	}
	return collect(data, 0)
}

// wasmCursor reads LEB128-encoded wasm structures. Reads past the end
// or over-long encodings set fail and return zeros, so callers check
// fail once instead of handling an error per read.
type wasmCursor struct {
	data []byte
	pos  int
	fail bool
}

func (c *wasmCursor) byte() byte {
	if c.pos >= len(c.data) {
		c.fail = true
		return 0
	}
	b := c.data[c.pos]
	c.pos++
	return b
}

// uint reads an unsigned LEB128.
func (c *wasmCursor) uint() uint64 {
	var v uint64
	for shift := 0; shift < 64; shift += 7 {
		b := c.byte()
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return v
		}
	}
	c.fail = true
	return 0
}

// sint reads a signed LEB128.
func (c *wasmCursor) sint() int64 {
	var v int64
	for shift := 0; shift < 64; shift += 7 {
		b := c.byte()
		v |= int64(b&0x7f) << shift
		if b&0x80 == 0 {
			if b&0x40 != 0 && shift+7 < 64 {
				v |= -1 << (shift + 7) // sign-extend
			}
			return v
		}
	}
	c.fail = true
	return 0
}

// bytes reads n bytes as a slice into the underlying data.
func (c *wasmCursor) bytes(n uint64) []byte {
	if n > uint64(len(c.data)-c.pos) {
		c.fail = true
		return nil
	}
	b := c.data[c.pos : c.pos+int(n)]
	c.pos += int(n)
	return b
}

// name reads a length-prefixed UTF-8 name.
func (c *wasmCursor) name() string {
	return string(c.bytes(c.uint()))
}

// skipLimits skips a limits structure: flags, min, optional max.
func (c *wasmCursor) skipLimits() {
	flags := c.byte()
	c.uint()
	if flags&1 != 0 {
		c.uint()
	}
}
