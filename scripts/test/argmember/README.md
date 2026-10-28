# Inject-hook argument filter test

Build static binaries and BPF objects on the development host:

```sh
scripts/test/argmember/build.sh /tmp/argmember-vm
```

Copy that directory into a disposable x86-64 VM and run `./run.sh` as root.
The build host needs clang with BPF support and Linux/libbpf headers.
Runtime needs bpffs, `timeout`, and `tcpdump`.
The script creates private bpffs pins, removes them on exit, and uses
`BPF_PROG_TEST_RUN` without attaching a program to an interface.
Diagnostics and pcaps live in a temporary directory outside the copied directory.

The 21 checks cover an inject-run-generated hash-map hook's member schema,
`==`, `!=`, `be16`, ranges and AND, entry/exit/gated capture, a set keyed by
`key->dport` (explicit and implicit mapping, including runtime deletion),
walkthrough bloom/queue `[0]` schemas and comparisons, and dispatch NULL tests
in entry, exit and gated capture.
Each successful capture must contain exactly three packets with the expected
destination port(s), as decoded by tcpdump.
The two negative captures must time out with empty pcaps.

The loader supplies an empty BTF key type to the walkthrough queue map so the
kernel retains its scalar value type; without a key type, map creation retries
without BTF and inject-run only sees opaque bytes.
On 6.1, dispatch uses `static_untrusted` because that kernel predates
`arg:untrusted`; static XDP ctx reads use the fault-handled kernel-read helper.

The related privileged Go tests are:

```sh
mkdir -p /tmp/argmember-kernel
go test -c -o /tmp/argmember-kernel/x.test ./internal/program
# Run as root inside the VM:
./x.test -test.run 'TestBpfArgMember|TestIntegerArgFilterByteIdentical' -test.v
```

They cover integer/member comparisons and echo, struct/union/scalar/void NULL
predicates, signed widening, mixed argument/member set keys, NULL set rejection,
and entry/exit/gated packet capture with a packet DSL condition.
`TestIntegerArgFilterByteIdentical` pins the original integer filter bytecode.
