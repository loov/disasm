// The wasm formatter mirrors the instruction syntax of watgo's printer
// (github.com/eliben/watgo/internal/printer), which is public domain
// under the Unlicense; the mnemonic tables are generated from its
// instruction catalog.

package objfile

//go:generate go run ./gen/wasmnames -out wasm_names_gen.go

import (
	"math"
	"strconv"
	"strings"

	"github.com/eliben/watgo"
	"github.com/eliben/watgo/wasmir"
)

// wasmInstText renders one instruction as linear WAT, matching what
// watgo's printer emits for a module without names. Kinds it does not
// know are rendered through the printer on a single-instruction
// module, so every kind prints correctly; only the common ones print
// cheaply.
func wasmInstText(in *wasmir.Instruction) string {
	name := wasmOpNames[in.Kind]
	switch in.Kind {
	case wasmir.InstrBlock, wasmir.InstrLoop, wasmir.InstrIf:
		switch {
		case in.BlockTypeUsesIndex:
			return name + " (type " + utoa(uint64(in.BlockTypeIndex)) + ")"
		case in.BlockType != nil:
			return name + " (result " + wasmValueType(*in.BlockType) + ")"
		}
		return name
	case wasmir.InstrElse, wasmir.InstrEnd:
		return name
	case wasmir.InstrLocalGet, wasmir.InstrLocalSet, wasmir.InstrLocalTee:
		return name + " " + utoa(uint64(in.LocalIndex))
	case wasmir.InstrCall, wasmir.InstrReturnCall, wasmir.InstrRefFunc:
		return name + " " + utoa(uint64(in.FuncIndex))
	case wasmir.InstrBr, wasmir.InstrBrIf, wasmir.InstrBrOnNull, wasmir.InstrBrOnNonNull:
		return name + " " + utoa(uint64(in.BranchDepth))
	case wasmir.InstrBrTable:
		var b strings.Builder
		b.WriteString(name)
		for _, depth := range in.BranchTable {
			b.WriteByte(' ')
			b.WriteString(utoa(uint64(depth)))
		}
		b.WriteByte(' ')
		b.WriteString(utoa(uint64(in.BranchDefault)))
		return b.String()
	case wasmir.InstrGlobalGet, wasmir.InstrGlobalSet:
		return name + " " + utoa(uint64(in.GlobalIndex))
	case wasmir.InstrCallIndirect, wasmir.InstrReturnCallIndirect:
		s := name
		if in.TableIndex != 0 {
			s += " " + utoa(uint64(in.TableIndex))
		}
		return s + " (type " + utoa(uint64(in.CallTypeIndex)) + ")"
	case wasmir.InstrSelect:
		if in.SelectType == nil {
			return name
		}
		return name + " (result " + wasmValueType(*in.SelectType) + ")"
	case wasmir.InstrI32Const:
		return name + " " + strconv.FormatInt(int64(in.I32Const), 10)
	case wasmir.InstrI64Const:
		return name + " " + strconv.FormatInt(in.I64Const, 10)
	case wasmir.InstrF32Const:
		return name + " " + wasmF32(in.F32Const)
	case wasmir.InstrF64Const:
		return name + " " + wasmF64(in.F64Const)
	case wasmir.InstrMemorySize, wasmir.InstrMemoryGrow, wasmir.InstrMemoryFill:
		if in.MemoryIndex == 0 {
			return name
		}
		return name + " " + utoa(uint64(in.MemoryIndex))
	case wasmir.InstrMemoryCopy:
		if in.MemoryIndex == 0 && in.SourceMemoryIndex == 0 {
			return name
		}
		return name + " " + utoa(uint64(in.MemoryIndex)) + " " + utoa(uint64(in.SourceMemoryIndex))
	}
	switch {
	case wasmMemOps[in.Kind]:
		s := name
		if in.MemoryIndex != 0 {
			s += " " + utoa(uint64(in.MemoryIndex))
		}
		if in.MemoryOffset != 0 {
			s += " offset=" + utoa(in.MemoryOffset)
		}
		if in.MemoryAlign != 0 {
			s += " align=" + utoa(uint64(1)<<in.MemoryAlign)
		}
		return s
	case wasmPlainOps[in.Kind]:
		return name
	}
	return wasmPrintedText(in)
}

// wasmPrintedText renders an instruction through watgo's module
// printer, for kinds wasmInstText does not format itself.
func wasmPrintedText(in *wasmir.Instruction) string {
	wat, err := watgo.PrintWAT(&wasmir.Module{
		Types: []wasmir.TypeDef{{Kind: wasmir.TypeDefKindFunc}},
		Funcs: []wasmir.Function{{Body: []wasmir.Instruction{*in}}},
	})
	if err != nil {
		return wasmOpNames[in.Kind]
	}
	for line := range strings.Lines(string(wat)) {
		text := strings.TrimSpace(line)
		if text != "" && !strings.HasPrefix(text, "(") && !strings.HasPrefix(text, ")") {
			return text
		}
	}
	return wasmOpNames[in.Kind]
}

func utoa(v uint64) string { return strconv.FormatUint(v, 10) }

// wasmValueType names a value type as the printer does for the types
// Go and TinyGo emit; reference types with a heap type spell out.
func wasmValueType(vt wasmir.ValueType) string {
	if vt.Kind == wasmir.ValueKindRef {
		if vt.Nullable {
			switch vt.HeapType.Kind {
			case wasmir.HeapKindFunc:
				return "funcref"
			case wasmir.HeapKindExtern:
				return "externref"
			}
		}
		return wasmPrintedType(vt)
	}
	return vt.String()
}

// wasmPrintedType renders a value type through the printer via a typed
// select, for the reference types wasmValueType does not name.
func wasmPrintedType(vt wasmir.ValueType) string {
	text := wasmPrintedText(&wasmir.Instruction{Kind: wasmir.InstrSelect, SelectType: &vt})
	_, t, _ := strings.Cut(text, "(result ")
	return strings.TrimSuffix(t, ")")
}

func wasmF32(bits uint32) string {
	if bits&0x7f800000 == 0x7f800000 && bits&0x007fffff != 0 {
		return wasmNaN(bits&0x80000000 != 0, uint64(bits&0x007fffff))
	}
	return wasmFloat(float64(math.Float32frombits(bits)), 32)
}

func wasmF64(bits uint64) string {
	if bits&0x7ff0000000000000 == 0x7ff0000000000000 && bits&0x000fffffffffffff != 0 {
		return wasmNaN(bits&0x8000000000000000 != 0, bits&0x000fffffffffffff)
	}
	return wasmFloat(math.Float64frombits(bits), 64)
}

func wasmNaN(neg bool, payload uint64) string {
	s := "nan:0x" + strconv.FormatUint(payload, 16)
	if neg {
		return "-" + s
	}
	return s
}

func wasmFloat(v float64, bits int) string {
	switch {
	case math.IsNaN(v):
		return "nan"
	case math.IsInf(v, 1):
		return "inf"
	case math.IsInf(v, -1):
		return "-inf"
	}
	return strconv.FormatFloat(v, 'g', -1, bits)
}
