package analysis

import "strings"

// CallKind is what a call to a runtime or library function means for
// performance.
type CallKind int

const (
	// CallOther is any call not listed below.
	CallOther CallKind = iota
	// CallBoundsCheck is the failure path of an index or slice bounds
	// check. The conditional branch that jumps to it is the check.
	CallBoundsCheck
	// CallAlloc allocates on the heap. In Go this is where escape
	// analysis moved a value to the heap or a slice grew.
	CallAlloc
	// CallWriteBarrier records a pointer write for the Go garbage
	// collector.
	CallWriteBarrier
)

func (k CallKind) String() string {
	switch k {
	case CallBoundsCheck:
		return "bounds check"
	case CallAlloc:
		return "allocation"
	case CallWriteBarrier:
		return "write barrier"
	}
	return "other"
}

// callKinds maps name prefixes of called symbols to their kind. A
// prefix also covers the numbered and ABI variants, such as
// runtime.gcWriteBarrier2 and runtime.panicIndex.abi0.
var callKinds = []struct {
	prefix string
	kind   CallKind
}{
	// Go has one function per check shape. Newer releases use
	// panicBounds* instead.
	{"runtime.panicIndex", CallBoundsCheck},
	{"runtime.panicSlice", CallBoundsCheck},
	{"runtime.panicBounds", CallBoundsCheck},
	{"runtime.goPanicIndex", CallBoundsCheck},
	{"runtime.goPanicSlice", CallBoundsCheck},
	// Rust, demangled.
	{"core::panicking::panic_bounds_check", CallBoundsCheck},
	{"core::slice::index::slice_start_index_len_fail", CallBoundsCheck},
	{"core::slice::index::slice_end_index_len_fail", CallBoundsCheck},
	{"core::slice::index::slice_index_order_fail", CallBoundsCheck},

	{"runtime.newobject", CallAlloc},
	{"runtime.newarray", CallAlloc},
	{"runtime.mallocgc", CallAlloc},
	{"runtime.makeslice", CallAlloc},
	{"runtime.growslice", CallAlloc},
	{"runtime.makemap", CallAlloc},
	{"runtime.makechan", CallAlloc},
	{"runtime.convT", CallAlloc},
	{"malloc", CallAlloc},
	{"calloc", CallAlloc},
	{"realloc", CallAlloc},
	{"operator new", CallAlloc},
	{"__rust_alloc", CallAlloc},
	{"__rust_alloc_zeroed", CallAlloc},
	{"__rust_realloc", CallAlloc},
	{"__rustc::__rust_alloc", CallAlloc},
	{"__rustc::__rust_alloc_zeroed", CallAlloc},
	{"__rustc::__rust_realloc", CallAlloc},

	{"runtime.gcWriteBarrier", CallWriteBarrier},
	{"runtime.wbMove", CallWriteBarrier},
	{"runtime.wbZero", CallWriteBarrier},
}

// ClassifyCall returns the kind of a call to the symbol name, as
// objfile.Binary.Lookup returns it. Native symbols may carry a version
// suffix, as in malloc@GLIBC_2.2.5. ClassifyCall ignores leading
// underscores on both the name and the prefix, because a Mach-O name
// can keep an extra one, as in ___rust_alloc.
func ClassifyCall(name string) CallKind {
	name = strings.TrimLeft(name, "_")
	for _, c := range callKinds {
		rest, ok := strings.CutPrefix(name, strings.TrimLeft(c.prefix, "_"))
		if !ok {
			continue
		}
		// malloc must not match malloc_usable_size. Go names can go on
		// with digits, dots or letters, as in panicIndexU and convT64.
		if strings.HasPrefix(c.prefix, "runtime.") || rest == "" || rest[0] == '@' || rest[0] == '(' || rest[0] == '<' || strings.HasPrefix(rest, "::") {
			return c.kind
		}
	}
	return CallOther
}
