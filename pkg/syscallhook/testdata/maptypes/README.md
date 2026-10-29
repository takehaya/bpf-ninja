# Missing map type CLI integration test

`program.c` declares a typed map, while `loader.go` deliberately creates that map without BTF before loading the ELF program.
`legacy.c` instead declares the map by sizes and retains a named value struct and two flavors with reversed member order separately in ELF BTF.
The check compares the opaque baseline with automatic ELF types, the legacy definition with explicit type names, then verifies that an existing typed map refuses supplementation.
The `named` mode refuses a same-size reordered type that would override the typed ELF map; names have fill-only semantics.
For the legacy definition, it checks that `record` selects the exact layout among flavors and that the nonexistent exact name `record___new` is refused before the loader becomes ready, leaving no hooks.
It sends three distinct 64-byte packets with identities 7, 8 and 7 using `BPF_PROG_TEST_RUN`, waits for capture readiness, and verifies that the final pcapng contains exactly the first and third packets with no reported capture losses.
No interface attachment is required.

From the repository root, build static binaries and compile the fixtures locally:

```sh
DATA=$(mktemp -d)
mkdir -p "$DATA/vm"
CGO_ENABLED=0 go build -o "$DATA/vm/bpf-ninja" ./cmd/bpf-ninja
CGO_ENABLED=0 go build -o "$DATA/vm/loader" ./pkg/syscallhook/testdata/maptypes/loader.go
clang -O2 -g -target bpf -c pkg/syscallhook/testdata/maptypes/program.c -o "$DATA/vm/program.o"
clang -O2 -g -target bpf -c pkg/syscallhook/testdata/maptypes/legacy.c -o "$DATA/vm/legacy.o"
cp scripts/test/map-types.py "$DATA/vm/"
```

In a root-capable Linux x86-64 VM with Python 3, program BTF, ptrace and fentry support, change to the copied directory and run:

```sh
python3 ./map-types.py ./bpf-ninja ./loader ./program.o results ./legacy.o
```

`results` must not exist.
The script keeps each command's arguments, stdout, stderr and exit status, the map BTF ID, hook JSON, member listings, packet files and loader input/output records.
It creates `results/PASS` only after all checks succeed; optimized Python (`-O` or `PYTHONOPTIMIZE`) is refused.
Timed-out foreground commands have their process group killed and reaped.
Repeat with a new output directory on each target kernel.
The unprivileged unit checks are `go test ./pkg/syscallhook -run TestMapTypes -v`; ELF tests need clang with BPF support.

The committed Go supervisor test also checks kernel hook BTF and existing-BTF refusal, and independently checks that `extractRaw` retains a live map's BTF ID:

```sh
go test -c -tags integration -o "$DATA/vm/syscallhook.test" ./pkg/syscallhook
# In the VM, using the already compiled program.o (clang is not required there):
SYSCALLHOOK_MAP_TYPES_ELF=./program.o ./syscallhook.test -test.run '^TestIntegrationMapTypes$' -test.v
```

Without `SYSCALLHOOK_MAP_TYPES_ELF`, the Go test compiles the fixture locally.
