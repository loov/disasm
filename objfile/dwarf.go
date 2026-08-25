package objfile

import (
	"cmp"
	"debug/dwarf"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// lines maps addresses to source positions, as DWARF records them for
// code the Go compiler didn't produce. Opening indexes only the address
// ranges of each compilation unit; a unit's line program and subprogram
// list are parsed the first time an address inside it is looked up, so
// a large binary costs what its queries touch, not its debug info.
type lines struct {
	data  *dwarf.Data
	shift int64
	// units is sorted by lo; a unit with several ranges appears once
	// per range. Units with no address range go in unbounded and are
	// searched when nothing else covers an address.
	units     []unitRange
	unbounded []dwarf.Offset

	mu    sync.Mutex
	cache map[dwarf.Offset]*unitLines
}

type unitRange struct {
	lo, hi uint64
	off    dwarf.Offset
}

// unitLines is one compilation unit's parsed line program.
type unitLines struct {
	rows []lineRow
	// declared maps a function's entry address to the file it was
	// written in, which is not always the file its first instruction
	// belongs to: an inlined call can own the entry.
	declared map[uint64]string
}

type lineRow struct {
	addr uint64
	file string
	line int
}

// LinesFromDWARF indexes the compilation units. shift is added to each
// address, for formats whose DWARF addresses are relative to something
// other than the addresses used elsewhere; wasm counts from the start
// of the code section. nil when there are no units.
func LinesFromDWARF(data *dwarf.Data, shift int64) *lines {
	lines := &lines{data: data, shift: shift, cache: map[dwarf.Offset]*unitLines{}}
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}
		if entry.Tag != dwarf.TagCompileUnit {
			reader.SkipChildren()
			continue
		}
		ranges, _ := data.Ranges(entry)
		if len(ranges) == 0 {
			lines.unbounded = append(lines.unbounded, entry.Offset)
		}
		for _, r := range ranges {
			lines.units = append(lines.units, unitRange{
				lo: uint64(int64(r[0]) + shift), hi: uint64(int64(r[1]) + shift), off: entry.Offset,
			})
		}
		reader.SkipChildren()
	}
	if len(lines.units) == 0 && len(lines.unbounded) == 0 {
		return nil
	}
	slices.SortFunc(lines.units, func(a, b unitRange) int { return cmp.Compare(a.lo, b.lo) })
	return lines
}

// unit parses the compilation unit at off, once.
func (lines *lines) unit(off dwarf.Offset) *unitLines {
	lines.mu.Lock()
	defer lines.mu.Unlock()
	if u, ok := lines.cache[off]; ok {
		return u
	}
	u := lines.parseUnit(off)
	lines.cache[off] = u
	return u
}

func (lines *lines) parseUnit(off dwarf.Offset) *unitLines {
	u := &unitLines{declared: map[uint64]string{}}
	reader := lines.data.Reader()
	reader.Seek(off)
	cu, err := reader.Next()
	if err != nil || cu == nil || cu.Tag != dwarf.TagCompileUnit {
		return u
	}
	compDir, _ := cu.Val(dwarf.AttrCompDir).(string)
	fixed := map[string]string{}
	fixName := func(name string) string {
		if out, ok := fixed[name]; ok {
			return out
		}
		out := unjoinCompDir(compDir, name)
		fixed[name] = out
		return out
	}

	var files []*dwarf.LineFile
	if lr, err := lines.data.LineReader(cu); err == nil && lr != nil {
		files = lr.Files()
		var row dwarf.LineEntry
		for lr.Next(&row) == nil {
			out := lineRow{addr: uint64(int64(row.Address) + lines.shift)}
			// An end-sequence row marks where the code of a sequence
			// stops. Keeping it with no position is what stops the
			// last statement of one function from covering whatever
			// follows.
			if !row.EndSequence && row.File != nil {
				out.file, out.line = fixName(row.File.Name), row.Line
			}
			u.rows = append(u.rows, out)
		}
	}
	slices.SortFunc(u.rows, func(a, b lineRow) int {
		return cmp.Or(cmp.Compare(a.addr, b.addr), cmp.Compare(a.line, b.line))
	})

	// The unit's children follow it in order; the next unit's entry
	// ends them.
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil || entry.Tag == dwarf.TagCompileUnit {
			break
		}
		if entry.Tag != dwarf.TagSubprogram {
			continue
		}
		low, ok := entry.Val(dwarf.AttrLowpc).(uint64)
		index, ok2 := entry.Val(dwarf.AttrDeclFile).(int64)
		if !ok || !ok2 || low == 0 || index < 0 || int(index) >= len(files) || files[index] == nil {
			continue
		}
		u.declared[uint64(int64(low)+lines.shift)] = fixName(files[index].Name)
	}
	return u
}

// lookup finds the unit covering addr and calls f with it; the first
// unit for which f returns true wins. Unbounded units are tried last.
func (lines *lines) lookup(addr uint64, f func(*unitLines) bool) {
	// i is the first range starting after addr; ranges may nest across
	// units, so walk back through those starting at or before it.
	i, _ := slices.BinarySearchFunc(lines.units, addr, func(r unitRange, a uint64) int {
		if r.lo > a {
			return 1
		}
		return -1
	})
	for j := i - 1; j >= 0; j-- {
		r := lines.units[j]
		if addr < r.hi && f(lines.unit(r.off)) {
			return
		}
	}
	for _, off := range lines.unbounded {
		if f(lines.unit(off)) {
			return
		}
	}
}

// DeclFile returns the file a function starting at addr was written in;
// empty when the debug info doesn't say.
func (lines *lines) DeclFile(addr uint64) (file string) {
	if lines == nil {
		return ""
	}
	lines.lookup(addr, func(u *unitLines) bool {
		file = u.declared[addr]
		return file != ""
	})
	return file
}

// At returns the source position covering addr; zero values when no row
// covers it.
func (lines *lines) At(addr uint64) (file string, line int) {
	if lines == nil {
		return "", 0
	}
	lines.lookup(addr, func(u *unitLines) bool {
		// The last row at or before addr. A sequence's end row shares
		// its address with the next sequence's first row and sorts
		// before it (line 0), so the row with a position wins.
		i, _ := slices.BinarySearchFunc(u.rows, addr, func(row lineRow, a uint64) int {
			if row.addr > a {
				return 1
			}
			return -1
		})
		if i == 0 {
			return false
		}
		file, line = u.rows[i-1].file, u.rows[i-1].line
		return file != ""
	})
	return file, line
}

// unjoinCompDir undoes debug/dwarf joining an absolute file name onto
// the compilation directory. Its pathJoin documents that the name must
// be relative, but clang records absolute names, and DWARF says the
// directory is then ignored, so "/build/dir" + "/src/prog.c" arrives as
// "/build/dir/src/prog.c". The join is only undone when the path it
// produced is missing and the plain one is there, so a project that
// really does have that layout keeps working.
func unjoinCompDir(compDir, name string) string {
	if compDir == "" || !strings.HasPrefix(name, compDir) ||
		len(name) == len(compDir) || !os.IsPathSeparator(name[len(compDir)]) {
		return name
	}
	if _, err := os.Stat(name); err == nil {
		return name
	}
	// A DOS-style join drops the drive from the name; put it back.
	absolute := filepath.VolumeName(compDir) + name[len(compDir):]
	if _, err := os.Stat(absolute); err != nil {
		return name
	}
	return absolute
}
