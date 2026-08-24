package objfile

import (
	"bytes"
	"debug/dwarf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"strings"
)

// Mach-O is read in place: debug/macho materializes every symbol with a
// copied name on open, which for a large binary is most of what
// opening it would cost. Only the 64-bit layout exists for the
// supported CPUs. Debug info still goes through debug/macho, on first
// use.
const (
	machoMagic64   = 0xfeedfacf
	machoCPUAmd64  = 0x01000007
	machoCPUArm64  = 0x0100000c
	machoSegment64 = 0x19
	machoSymtab    = 0x2
	// Section flags marking code.
	machoPureInstructions = 0x80000000
	machoSomeInstructions = 0x00000400
	machoStab             = 0xe0 // N_STAB mask in n_type
)

func openMachO(data []byte) (*Binary, error) {
	var order binary.ByteOrder = binary.LittleEndian
	switch binary.LittleEndian.Uint32(data) {
	case machoMagic64:
	case 0xcffaedfe:
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("unsupported Mach-O magic %#x (only 64-bit files)", binary.LittleEndian.Uint32(data))
	}
	if len(data) < 32 {
		return nil, fmt.Errorf("truncated Mach-O header")
	}
	bin := &Binary{byteOrder: binary.LittleEndian}
	switch order.Uint32(data[4:]) {
	case machoCPUAmd64:
		bin.Arch = "amd64"
	case machoCPUArm64:
		bin.Arch = "arm64"
	default:
		return nil, fmt.Errorf("unsupported Mach-O cpu %#x", order.Uint32(data[4:]))
	}
	ncmds := order.Uint32(data[16:])
	cmds := sectionSlice(data, 32, uint64(order.Uint32(data[20:])))
	if cmds == nil {
		return nil, fmt.Errorf("truncated Mach-O load commands")
	}

	name16 := func(b []byte) string {
		return string(b[:16][:bytes.IndexByte(append(b[:16:16], 0), 0)])
	}
	var symoff, nsyms, stroff, strsize uint32
	var pclntab []byte
	for range ncmds {
		if len(cmds) < 8 {
			return nil, fmt.Errorf("truncated Mach-O load command")
		}
		cmd, size := order.Uint32(cmds), order.Uint32(cmds[4:])
		if uint64(size) > uint64(len(cmds)) || size < 8 {
			return nil, fmt.Errorf("corrupt Mach-O load command")
		}
		body := cmds[:size]
		cmds = cmds[size:]
		switch cmd {
		case machoSegment64:
			if len(body) < 72 {
				return nil, fmt.Errorf("truncated segment command")
			}
			segname := name16(body[8:])
			vmaddr, vmsize := order.Uint64(body[24:]), order.Uint64(body[32:])
			if segname != "__PAGEZERO" {
				bin.addRange(vmaddr, vmsize)
			}
			nsects := order.Uint32(body[64:])
			secs := body[72:]
			for range nsects {
				if len(secs) < 80 {
					return nil, fmt.Errorf("truncated section header")
				}
				sec := secs[:80]
				secs = secs[80:]
				sectname := name16(sec)
				addr, size := order.Uint64(sec[32:]), order.Uint64(sec[40:])
				off, flags := order.Uint32(sec[48:]), order.Uint32(sec[64:])
				switch {
				case segname == "__TEXT" && flags&(machoPureInstructions|machoSomeInstructions) != 0:
					bin.addText(addr, sectionSlice(data, uint64(off), size))
					if sectname == "__text" {
						bin.textAddr = addr
					}
				case sectname == "__gopclntab":
					pclntab = sectionSlice(data, uint64(off), size)
				}
			}
		case machoSymtab:
			if len(body) < 24 {
				return nil, fmt.Errorf("truncated symtab command")
			}
			symoff, nsyms = order.Uint32(body[8:]), order.Uint32(body[12:])
			stroff, strsize = order.Uint32(body[16:]), order.Uint32(body[20:])
		}
	}
	if bin.texts == nil {
		return nil, fmt.Errorf("no __text section")
	}

	// nlist_64: n_strx u32, n_type u8, n_sect u8, n_desc u16, n_value u64.
	syms := sectionSlice(data, uint64(symoff), uint64(nsyms)*16)
	strs := sectionSlice(data, uint64(stroff), uint64(strsize))
	if nsyms > 0 && (syms == nil || strs == nil) {
		return nil, fmt.Errorf("truncated Mach-O symbol table")
	}
	for i := range int(nsyms) {
		e := syms[i*16:]
		// Stab entries describe source info, not symbols.
		if e[4]&machoStab != 0 {
			continue
		}
		strx := order.Uint32(e)
		if strx >= uint32(len(strs)) {
			continue
		}
		name := strings.TrimPrefix(cstring(strs, strx), "_")
		value := order.Uint64(e[8:])
		kind := symData
		if bin.textAt(value) != nil {
			kind = symText
		}
		bin.addSym(name, value, 0, kind)
	}
	bin.loadPclntab(pclntab)
	bin.dwarf = func() (*dwarf.Data, error) {
		mf, err := macho.NewFile(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		return mf.DWARF()
	}
	return bin, nil
}
