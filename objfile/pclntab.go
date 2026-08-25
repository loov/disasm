package objfile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

// pclntab reads the Go runtime's function table in place: the functab
// gives every function's entry and name, and per-function pc-value
// tables give the file and line at a pc. Nothing is materialized per
// function, so a binary with a million functions costs the same to
// open as one with ten. Go 1.16 and later layouts are understood
// (magics 0xfffffffa, 0xfffffff0, 0xfffffff1); debug/gosym documents
// them, and this follows its decoding.
type pclntab struct {
	order     binary.ByteOrder
	ver       int // 116, 118 or 120
	quantum   uint64
	ptrsize   int
	nfunc     int
	textStart uint64

	funcnametab, cutab, filetab, pctab, funcdata, functab []byte
}

// parsePclntab reads the header; textAddr is where the text section
// is loaded, which the table's own value may not reflect before
// relocation. nil when data is not a table this understands.
func parsePclntab(data []byte, textAddr uint64) (t *pclntab, err error) {
	defer func() {
		// A corrupt table indexes out of range somewhere below.
		if r := recover(); r != nil {
			t, err = nil, fmt.Errorf("corrupt pclntab: %v", r)
		}
	}()
	if len(data) < 16 || data[4] != 0 || data[5] != 0 {
		return nil, fmt.Errorf("not a pclntab")
	}
	t = &pclntab{quantum: uint64(data[6]), ptrsize: int(data[7]), textStart: textAddr}
	if (t.quantum != 1 && t.quantum != 2 && t.quantum != 4) || (t.ptrsize != 4 && t.ptrsize != 8) {
		return nil, fmt.Errorf("not a pclntab")
	}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		switch order.Uint32(data) {
		case 0xfffffffa:
			t.order, t.ver = order, 116
		case 0xfffffff0:
			t.order, t.ver = order, 118
		case 0xfffffff1:
			t.order, t.ver = order, 120
		}
	}
	if t.order == nil {
		return nil, fmt.Errorf("unsupported pclntab version %#x", binary.LittleEndian.Uint32(data))
	}
	word := func(i int) uint64 {
		b := data[8+i*t.ptrsize:]
		if t.ptrsize == 8 {
			return t.order.Uint64(b)
		}
		return uint64(t.order.Uint32(b))
	}
	at := func(i int) []byte { return data[word(i):] }
	t.nfunc = int(word(0))
	if t.ver >= 118 {
		// word(2) is textStart, which may be unrelocated.
		t.funcnametab, t.cutab, t.filetab, t.pctab, t.funcdata = at(3), at(4), at(5), at(6), at(7)
	} else {
		t.funcnametab, t.cutab, t.filetab, t.pctab, t.funcdata = at(2), at(3), at(4), at(5), at(6)
	}
	// The functab is nfunc (entry, funcoff) pairs plus a final entry
	// marking the end of the text.
	t.functab = t.funcdata[:(2*t.nfunc+1)*t.fieldSize()]
	return t, nil
}

// fieldSize is the size of a functab field and of a _func's entry.
func (t *pclntab) fieldSize() int {
	if t.ver >= 118 {
		return 4
	}
	return t.ptrsize
}

func (t *pclntab) field(b []byte) uint64 {
	if t.fieldSize() == 4 {
		return uint64(t.order.Uint32(b))
	}
	return t.order.Uint64(b)
}

// entry returns the entry pc of function i; i == nfunc is the end of
// the text.
func (t *pclntab) entry(i int) uint64 {
	pc := t.field(t.functab[2*i*t.fieldSize():])
	if t.ver >= 118 {
		pc += t.textStart
	}
	return pc
}

// fn returns the _func of function i.
func (t *pclntab) fn(i int) []byte {
	return t.funcdata[t.field(t.functab[(2*i+1)*t.fieldSize():]):]
}

// funcField returns the nth uint32 field of a _func after its entry:
// 1 nameOff, 5 pcfile, 6 pcln, 8 cuOffset.
func (t *pclntab) funcField(fn []byte, n int) uint32 {
	return t.order.Uint32(fn[t.fieldSize()+(n-1)*4:])
}

// cstring returns an owned copy of the NUL-terminated string at off.
func cstring(tab []byte, off uint32) string {
	if uint64(off) >= uint64(len(tab)) {
		return ""
	}
	start := int(off)
	end := bytes.IndexByte(tab[start:], 0)
	if end < 0 {
		return ""
	}
	return string(tab[start : start+end])
}

// funcs calls yield for every function with its name and pc range;
// yield returns false to stop. A corrupt table ends the walk early.
func (t *pclntab) funcs(yield func(name string, entry, end uint64) bool) {
	defer func() { _ = recover() }()
	for i := range t.nfunc {
		name := cstring(t.funcnametab, t.funcField(t.fn(i), 1))
		if !yield(name, t.entry(i), t.entry(i+1)) {
			return
		}
	}
}

// find returns the index of the function containing pc, or -1.
func (t *pclntab) find(pc uint64) int {
	if t.nfunc == 0 || pc < t.entry(0) || pc >= t.entry(t.nfunc) {
		return -1
	}
	return sort.Search(t.nfunc, func(i int) bool { return t.entry(i) > pc }) - 1
}

// pcToLine returns the file and line at pc; empty and zero outside any
// function, and a line of -1 inside a function past its tables (the
// alignment padding after the last instruction).
func (t *pclntab) pcToLine(pc uint64) (file string, line int) {
	defer func() {
		if recover() != nil {
			file, line = "", 0
		}
	}()
	i := t.find(pc)
	if i < 0 {
		return "", 0
	}
	fn, entry := t.fn(i), t.entry(i)
	line = int(t.pcvalue(t.funcField(fn, 6), entry, pc))
	if fno := t.pcvalue(t.funcField(fn, 5), entry, pc); fno >= 0 {
		cu := t.funcField(fn, 8)
		if off := t.order.Uint32(t.cutab[(cu+uint32(fno))*4:]); off != ^uint32(0) {
			file = cstring(t.filetab, off)
		}
	}
	return file, line
}

// pcvalue walks the pc-value table at off, pairs of zigzag value
// deltas and pc deltas in quantum units, and returns the value in
// effect at targetpc, or -1 past the table's end.
func (t *pclntab) pcvalue(off uint32, entry, targetpc uint64) int32 {
	p := t.pctab[off:]
	val, pc := int32(-1), entry
	for first := true; len(p) > 0; first = false {
		uvdelta := readvarint(&p)
		if uvdelta == 0 && !first {
			break
		}
		if uvdelta&1 != 0 {
			uvdelta = ^(uvdelta >> 1)
		} else {
			uvdelta >>= 1
		}
		pc += uint64(readvarint(&p)) * t.quantum
		val += int32(uvdelta)
		if targetpc < pc {
			return val
		}
	}
	return -1
}

func readvarint(pp *[]byte) uint32 {
	var v, shift uint32
	p := *pp
	for {
		b := p[0]
		p = p[1:]
		v |= (uint32(b) & 0x7f) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	*pp = p
	return v
}
