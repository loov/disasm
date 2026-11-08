// Package analysis finds properties of disassembled code that matter
// for performance: stack traffic from spills and reloads, bounds
// checks, heap allocations and write barriers.
package analysis

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/loov/disasm/objfile"
)

// StackAccess is how one instruction touches the stack frame.
type StackAccess struct {
	// Regs is the number of registers moved: 2 for arm64 paired loads
	// and stores, the range length for s390x load/store-multiple, 1
	// otherwise. Zero when the instruction does not touch the stack.
	Regs int
	// Slots is the number of 8-byte stack slots touched: 2 for a
	// 16-byte access (arm64 STP, amd64 MOVUPS), 4 for a 32-byte FSTPQ,
	// 1 for anything 8 bytes or narrower.
	Slots int
	// Store reports a write to the stack, a spill. Otherwise the
	// access reads it, a reload.
	Store bool
}

// StackAccesses reports the stack access of each instruction in
// insts, which are the instructions of one function in order. arch is
// the GOARCH of the binary.
//
// Besides spills and reloads it reports stack-passed call arguments
// and prologue register saves, because they use the same addressing.
// Regs and Slots weigh the same access two ways. Regs follows register
// pressure. Slots follows memory traffic, and stays the same when the
// compiler swaps a pair or vector access for scalar ones.
//
// When a frame is too large for a direct displacement, the compiler
// reaches it through a scratch register, as in
//
//	arm64    ADD $off, RSP, R27
//	amd64    LEAQ off(SP), DI
//	riscv64  LUI $k, X31; ADD X2, X31, X31
//	loong64  LU12IW $k, R30; ADDV R3, R30
//
// These setup instructions count zero because they move no data.
// Memory operands through the scratch register count as stack accesses
// until another instruction overwrites the register or a call clobbers
// it.
//
// Register-indexed stack operands such as 0x10(SP)(BX*8) and
// (RSP)(R2) count zero. They index stack arrays rather than spill
// slots, and counting them would mostly add noise from loops. Bulk
// copies and clears through runtime.duffzero, runtime.duffcopy or
// REP MOVS have no per-site stack operand, so they count zero too.
func StackAccesses(arch string, insts []objfile.Inst) []StackAccess {
	out := make([]StackAccess, len(insts))
	// alias is the set of registers currently holding a stack address.
	// The scan ignores control flow. The compiler sets up the scratch
	// register right before its uses, so joins don't matter.
	alias := map[string]bool{}
	sp := spName[arch]
	for i, in := range insts {
		if in.Op == "" {
			continue
		}
		op, _, _ := strings.Cut(in.Op, ".")
		_, rest, ok := strings.Cut(in.Text, " ")
		if !ok {
			continue
		}
		// ppc64 GoSyntax joins operands with a bare comma and the other
		// architectures with comma-space, so the space is optional.
		// Register pairs like (R0, R1) split in two, which is harmless
		// because neither fragment matches anything below.
		var args []string
		for arg := range strings.SplitSeq(rest, ",") {
			args = append(args, strings.TrimPrefix(arg, " "))
		}
		isStack := func(arg string) bool {
			_, ok := StackRef(arch, arg)
			return ok || alias[memBase(arg)]
		}

		if !leaOps[op] && slices.ContainsFunc(args, isStack) {
			regs, slots := weight(op, args)
			out[i] = StackAccess{
				Regs:  regs,
				Slots: slots,
				// The destination is the last operand in Go syntax.
				Store: isStack(last(args)) && !readOnly(op),
			}
		}

		if sp == "" {
			continue
		}
		switch {
		case op == "CALL" || op == "JAL" || op == "JALR":
			clear(alias)
		case addOps[op] && len(args) >= 2 && last(args) != sp && slices.Contains(args[:len(args)-1], sp):
			alias[last(args)] = true
		case movOps[op] && len(args) == 2 && args[0] == sp && args[1] != sp:
			alias[args[1]] = true
		case leaOps[op] && len(args) == 2:
			if _, ok := StackRef(arch, args[0]); ok {
				alias[args[1]] = true
			} else {
				delete(alias, args[1])
			}
		case readOnly(op):
			// Comparisons and tests write no operand.
		case len(args) > 0:
			// Any other write to a scratch register ends its alias.
			delete(alias, last(args))
		}
	}
	return out
}

// StackRef reports whether a rendered operand is a stack-pointer
// displacement on arch, such as 0x10(SP) on amd64 or -112(RSP) on
// arm64, and returns its register part: (SP), (RSP). Wasm has no
// stack-pointer register, so every operand reports false.
func StackRef(arch, arg string) (reg string, ok bool) {
	re := spDisp[arch]
	if re == nil {
		return "", false
	}
	m := re.FindStringSubmatch(arg)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// spDisp maps each architecture to the operand pattern of its
// stack-pointer displacements, as rendered by GoSyntax: 0x10(SP) on
// amd64/386, -112(RSP) on arm64, 16(X2) on riscv64, -128(R1) on ppc64,
// 48(R3) on loong64, -0x50(R13) on arm, and on s390x both the plain
// -104(R15) form and the indexed -104(R0)(R15*1) form. An empty arch
// matches the SP, RSP and X2 forms, for callers that do not know it.
var spDisp = map[string]*regexp.Regexp{
	"":        spPattern(`\(SP\)|\(RSP\)|\(X2\)`),
	"amd64":   spPattern(`\(SP\)`),
	"386":     spPattern(`\(SP\)`),
	"arm64":   spPattern(`\(RSP\)`),
	"riscv64": spPattern(`\(X2\)`),
	"ppc64":   spPattern(`\(R1\)`),
	"ppc64le": spPattern(`\(R1\)`),
	"loong64": spPattern(`\(R3\)`),
	"arm":     spPattern(`\(R13\)`),
	"s390x":   spPattern(`\(R15\)|\(R0\)\(R15\*1\)`),
}

// spPattern builds a stack-displacement matcher from alternatives for
// the register part. The offset before it is optional, hex on
// amd64, 386 and arm, decimal elsewhere.
func spPattern(tail string) *regexp.Regexp {
	return regexp.MustCompile(`^(?:-?(?:0x[0-9a-f]+|\d+))?(` + tail + `)$`)
}

// pairSlots maps the arm64 mnemonics that move two registers per
// memory access to the number of 8-byte stack slots they touch: 1 for
// the 32-bit pairs, 2 for the 64-bit ones, 4 for the 128-bit ones.
var pairSlots = map[string]int{
	"LDPW": 1, "STPW": 1, "LDPSW": 1, "FLDPS": 1, "FSTPS": 1,
	"LDP": 2, "STP": 2,
	"FLDPD": 2, "FSTPD": 2,
	"FLDPQ": 4, "FSTPQ": 4,
}

// multiOps are the s390x 64-bit load and store multiple mnemonics. A
// stack access by one of them moves one register and touches one slot
// for each register in its range. The 32-bit STM and STMY are left out
// because Go's s390x linkage never emits them.
var multiOps = map[string]bool{"LMG": true, "STMG": true}

// vec16Ops are the amd64 16-byte vector moves, which move one register
// and touch two slots. The compiler also uses them to clear or copy
// stack memory 16 bytes at a time, as in MOVUPS X15, 0x28(SP) with the
// fixed zero register X15.
var vec16Ops = map[string]bool{"MOVUPS": true, "MOVOU": true, "MOVO": true}

// leaOps are the mnemonics whose memory-shaped operand is address
// arithmetic, not a memory access.
var leaOps = map[string]bool{"LEAQ": true, "LEAL": true, "LEAW": true}

// addOps are the mnemonics that yield a stack address when a source
// operand is the stack pointer. arm64 uses ADD $off, RSP, R27. On
// riscv64 and loong64 a LUI or LU12IW first loads the offset into the
// destination register, and the ADD adds the stack pointer to it.
var addOps = map[string]bool{
	"ADD": true, "SUB": true,
	"ADDV": true, "ADDVU": true, "SUBV": true, "SUBVU": true,
}

// movOps are the register-to-register moves that can copy the stack
// pointer into another register, in each architecture's spelling.
var movOps = map[string]bool{"MOV": true, "MOVD": true, "MOVV": true}

// spName is the stack-pointer register as it is rendered in register
// (non-memory) operands, for the architectures whose compilers
// materialize stack addresses into scratch registers. The other
// architectures only use direct displacements and have no entry.
var spName = map[string]string{
	"amd64":   "SP",
	"386":     "SP",
	"arm64":   "RSP",
	"riscv64": "X2",
	"loong64": "R3",
}

// readOnly reports the mnemonics that read their last operand instead
// of writing it. These are comparisons, tests, and the s390x LMG,
// which lists the register range first just like STMG.
func readOnly(op string) bool {
	// BTS, BTR and BTC write their operand, so match the plain bit
	// tests by name instead of by the BT prefix.
	switch op {
	case "LMG", "BTQ", "BTL", "BTW":
		return true
	}
	return strings.HasPrefix(op, "CMP") || strings.HasPrefix(op, "TEST")
}

// weight is the number of registers a stack access by op moves and
// the number of 8-byte stack slots it touches.
func weight(op string, args []string) (regs, slots int) {
	if s, ok := pairSlots[op]; ok {
		return 2, s
	}
	if vec16Ops[op] {
		return 1, 2
	}
	if multiOps[op] && len(args) == 3 {
		if a, aok := regNum(args[0]); aok {
			if b, bok := regNum(args[1]); bok {
				// The register range wraps modulo 16, so STMG R14, R2
				// stores R14, R15, R0, R1 and R2.
				r := (b-a+16)%16 + 1
				return r, r
			}
		}
	}
	return 1, 1
}

// regNum returns the number of a rendered s390x general register.
func regNum(s string) (int, bool) {
	num, ok := strings.CutPrefix(s, "R")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(num)
	return n, err == nil && n < 16
}

// memBase returns the base register of a rendered memory operand such
// as (R27) or -8(R27), or "" when arg is not that shape.
func memBase(arg string) string {
	if !strings.HasSuffix(arg, ")") {
		return ""
	}
	i := strings.LastIndex(arg, "(")
	if i < 0 {
		return ""
	}
	if off := arg[:i]; off != "" {
		if _, err := strconv.ParseInt(off, 0, 64); err != nil {
			return ""
		}
	}
	return arg[i+1 : len(arg)-1]
}

// last returns the final operand, which is the destination in Go
// syntax.
func last(args []string) string {
	return args[len(args)-1]
}
