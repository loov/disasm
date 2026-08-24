# disasm

Go packages for reading executables and decoding their machine code,
shared by [lensm](https://github.com/loov/lensm) and
[ixdiff](https://github.com/loov/ixdiff).

- `objfile` — opens ELF, Mach-O, PE, WebAssembly (modules and
  components) and Go compile archives; lists functions with their code,
  resolves symbols, maps addresses to source positions from the Go
  pclntab or DWARF, and disassembles into Go and native syntax for
  amd64, 386, arm64, arm (ARM and Thumb), riscv64/32, ppc64/le, s390x,
  loong64, avr, xtensa and wasm.
- `thumbasm` — a Thumb/Thumb-2 decoder generated from ARM's ISA XML.
- `avrasm`, `xtensaasm` — hand-written decoders for AVR and Xtensa.

`objfile.Open` memory-maps the file and reads only headers and symbol
tables; function bodies, line tables and debug info are read on first
use, so a large binary costs what is looked at.

```go
bin, err := objfile.Open("prog")
defer bin.Close()
fn := bin.Func("main.main")
insts, err := bin.Disassemble(fn)
for _, in := range insts {
	file, line := bin.PCToLine(in.Addr)
	fmt.Printf("%#x %s %s:%d\n", in.Addr, in.Text, file, line)
}
```

## Testing

`objfile/testdata` holds binaries for every supported format and
architecture; `go test ./objfile` compares their complete disassembly
and line mapping against `testdata/golden`. After an intended change in
output, regenerate with `go test ./objfile -update` and review the diff.
Set `OBJFILE_DUMP=dir` to write the full dumps for comparing two
versions.
