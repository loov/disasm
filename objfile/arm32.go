package objfile

import (
	"cmp"
	"encoding/binary"
	"slices"
)

// armRegion starts an ARM ($a), Thumb ($t) or data ($d) region, per the
// ELF for the Arm Architecture mapping symbols.
type armRegion struct {
	addr uint64
	kind byte // 'a', 't' or 'd'
}

type armRegions struct {
	regions []armRegion // sorted by addr
}

// armRegionsBuilder collects the two sources of regions while the
// symbol table is walked: mapping symbols, and failing those, the Thumb
// bit of function symbols.
type armRegionsBuilder struct {
	mapping []armRegion
	funcs   []armRegion
	thumb   bool
}

// addMapping records a mapping symbol; the caller checks it lies in a
// text section.
func (b *armRegionsBuilder) addMapping(name string, addr uint64) {
	if len(name) < 2 || name[0] != '$' {
		return
	}
	switch name[1] {
	case 'a', 't', 'd':
		if len(name) == 2 || name[2] == '.' {
			b.mapping = append(b.mapping, armRegion{addr: addr, kind: name[1]})
		}
	}
}

// addFunc records a function symbol's raw value, whose low bit marks a
// Thumb function.
func (b *armRegionsBuilder) addFunc(value uint64) {
	if value == 0 {
		return
	}
	kind := byte('a')
	if value&1 != 0 {
		kind, b.thumb = 't', true
	}
	b.funcs = append(b.funcs, armRegion{addr: value &^ 1, kind: kind})
}

// regions returns the mapping-symbol regions, or the function-derived
// ones when there are no mapping symbols; nil when every function is
// ARM.
func (b *armRegionsBuilder) regions() *armRegions {
	regions := b.mapping
	if len(regions) == 0 {
		if !b.thumb {
			return nil
		}
		regions = b.funcs
	}
	slices.SortStableFunc(regions, func(x, y armRegion) int { return cmp.Compare(x.addr, y.addr) })
	return &armRegions{regions: regions}
}

// at returns the kind of the region containing addr and where the next
// region begins (or limit, whichever comes first). Addresses before the
// first mapping symbol are taken as ARM code.
func (r *armRegions) at(addr, limit uint64) (kind byte, end uint64) {
	kind, end = 'a', limit
	i, found := slices.BinarySearchFunc(r.regions, addr, func(s armRegion, a uint64) int {
		return cmp.Compare(s.addr, a)
	})
	if !found {
		i--
	}
	// Several mapping symbols may share an address; the last one wins.
	for i+1 < len(r.regions) && r.regions[i+1].addr == addr {
		i++
	}
	if i >= 0 {
		kind = r.regions[i].kind
	}
	if i+1 < len(r.regions) && r.regions[i+1].addr < end {
		end = r.regions[i+1].addr
	}
	return kind, end
}

// armPool finds the literal-pool words of an ARM-mode body from the
// pc-relative LDR and VLDR that read them, keyed by offset into code.
// Used when the binary has no mapping symbols.
func armPool(code []byte) map[int]bool {
	pool := map[int]bool{}
	n := len(code) &^ 3
	for i := 0; i < n; i += 4 {
		w := binary.LittleEndian.Uint32(code[i:])
		if w>>28 == 0xF { // unconditional space: PLD etc., not a load
			continue
		}
		var off, size int
		switch {
		case w&0x0F7F0000 == 0x051F0000: // LDR Rt, [PC, ±imm12]
			off, size = int(w&0xFFF), 4
		case w&0x0F3F0E00 == 0x0D1F0A00: // VLDR Fd, [PC, ±imm8*4]
			off, size = int(w&0xFF)*4, 4
			if w&0x100 != 0 { // double precision
				size = 8
			}
		default:
			continue
		}
		if w&0x00800000 == 0 { // U bit clear: subtract the offset
			off = -off
		}
		target := i + 8 + off
		for j := 0; j < size; j += 4 {
			if p := target + j; 0 <= p && p+4 <= n {
				pool[p] = true
			}
		}
	}
	return pool
}
