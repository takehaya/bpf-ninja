# Missing map type CLI integration test

`program.c` declares a typed map, while `loader.go` deliberately creates that map without BTF before loading the ELF program.
`legacy.c` instead declares the map by sizes and retains a named value struct separately in ELF BTF.
The check compares the opaque baseline with automatic ELF types, explicit type names and the legacy definition, then verifies that an existing typed map refuses supplementation.
It sends three distinct 64-byte packets with identities 7, 8 and 7 using `BPF_PROG_TEST_RUN`, waits for capture readiness, and verifies that the final pcapng contains exactly the first and third packets with no reported capture losses.
No interface attachment is required.

From the repository root, build static binaries and compile the fixtures locally:

```sh
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
It creates `results/PASS` only after all assertions succeed.
Repeat with a new output directory on each target kernel.
The unprivileged unit checks are `go test ./pkg/syscallhook -run TestMapTypes -v`; ELF tests need clang with BPF support.
