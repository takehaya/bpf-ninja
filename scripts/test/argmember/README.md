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
Diagnostics, configurations and pcaps are retained in a unique
`argmember-results.*` directory inside the copied directory, including on failure.
The exit message prints its path, so VM runners can copy the artifacts back.

The 22 checks cover an inject-run-generated hash-map hook's member schema,
`==`, `!=`, `be16`, ranges and AND, entry/exit/gated capture, a set keyed by
`key->dport` (explicit and implicit mapping, dotted set names and runtime deletion),
walkthrough bloom/queue `[0]` schemas and comparisons, and dispatch NULL tests
in entry, exit and gated capture.
Each successful capture must contain exactly three packets with the expected
destination port(s), as decoded by tcpdump.
The two negative captures must time out with empty pcaps.

The loader supplies an empty BTF key type to the walkthrough queue map so the
kernel retains its scalar value type; without a key type, map creation retries
without BTF and inject-run only sees opaque bytes.
On the 6.1, 6.6, 6.12 and 6.15 matrix kernels, dispatch uses `static_untrusted`
because they reject `arg:untrusted`.
A small, unattached load probe checks the target's direct XDP context reads.
Only targets rejected with a scalar context use the fault-handled kernel-read
helper; static helpers that accept direct reads keep their original bytecode.
Exit capture on the fallback path obtains the action with `bpf_get_func_ret`
instead of assuming the discarded BTF prototype describes the trampoline.

The related privileged Go tests are:

```sh
mkdir -p /tmp/argmember-kernel
go test -c -o /tmp/argmember-kernel/x.test ./internal/program
# Run as root inside the VM:
./x.test -test.run 'TestBpfArgMember|TestBpfStaticXDP|TestIntegerArgFilterByteIdentical' -test.v
```

They cover integer/member comparisons and echo, struct/union/scalar/void NULL
predicates, signed widening, mixed argument/member set keys, NULL set rejection,
and entry/exit/gated packet capture with a packet DSL condition.
`TestIntegerArgFilterByteIdentical` pins the original integer filter bytecode.
The static XDP tests compare entry, exit and gated-exit bytecode against
`origin/main` (060811d) for a ctx-only static helper, check the selected capture
prologues, and force a failed ctx read to verify depth and hold cleanup.
They also check the action recorded for a four-argument static hook, including
both gated images and matching/nonmatching exit action predicates.
`TestBpfArgMemberReadFailure` forces a non-NULL member-read fault in filter and
echo instructions; its filter cases echo only an integer to avoid masking errors.
