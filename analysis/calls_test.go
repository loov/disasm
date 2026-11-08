package analysis

import "testing"

func TestClassifyCall(t *testing.T) {
	tests := []struct {
		name string
		want CallKind
	}{
		{"runtime.panicIndex", CallBoundsCheck},
		{"runtime.panicSliceAlen.abi0", CallBoundsCheck},
		{"runtime.panicBounds64<abi0>", CallBoundsCheck},
		{"core::panicking::panic_bounds_check::h1234", CallBoundsCheck},
		{"runtime.newobject", CallAlloc},
		{"runtime.convTstring", CallAlloc},
		{"_malloc", CallAlloc},
		{"__rust_alloc", CallAlloc},
		{"_rust_alloc", CallAlloc},
		{"__rust_alloc_zeroed", CallAlloc},
		{"__rust_realloc", CallAlloc},
		{"__rustc::__rust_alloc", CallAlloc},
		{"__rust_dealloc", CallOther},
		{"malloc@GLIBC_2.2.5", CallAlloc},
		{"malloc_usable_size", CallOther},
		{"operator new(unsigned long)", CallAlloc},
		{"runtime.gcWriteBarrier2", CallWriteBarrier},
		{"runtime.morestack_noctxt", CallOther},
		{"main.main", CallOther},
	}
	for _, tt := range tests {
		if got := ClassifyCall(tt.name); got != tt.want {
			t.Errorf("ClassifyCall(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
