# Privileged test coverage

`make test-bpf` runs the host profile in `scripts/test/privileged.py`. It requires
root, clang with the BPF target, libbpf headers, libpcap, writable bpffs and
cgroup v2, veth, and a kernel with tcx support. The integration CI job provisions
these dependencies and runs the same command before the shell capture suite.
The Go suites run sequentially so fixtures using fixed interface names do not
collide. Do not run another host suite or integration setup concurrently.

| Profile | Required selection | Environment |
|---|---|---|
| Host | Every `Test*` in internal/program, internal/attach, internal/capture/..., cmd/bpf-ninja, and pkg/kunai/dsltest | Integration job, Ubuntu 26.04 runner |
| Kernel matrix | Every `TestBpf*` in internal/program and cmd/bpf-ninja; all tests in internal/attach, internal/capture/..., and pkg/kunai/dsltest | vimto, kernels 6.1/6.6/6.12/6.15/6.18/7.0/7.1/7.2/7.3-rc4 |

The host profile includes `TestLinearHeadClampAtCgroupSKB`,
`TestVlanUntagAtTCIngress` and `TestBpfVlanWireFrameAtTC` (tagged, untagged and
QinQ frames over a veth pair, by default and with `--tc-vlan-reinsert`). It also exercises all attach discovery tests. The
matrix includes literal/slice, grouping, IPv6 length, and TCP option tests via
the complete DSL suite, plus tracing read-window tests with variable headers.
`python3 scripts/test/privileged.py --kernel 6.12` runs a matrix cell locally.
The matrix also sets `KUNAI_VERIFIER_STRICT=1`, so `TestVerifierStats` fails
when a probe's processed instruction count exceeds 1.5 times its per-kernel
baseline or the kernel has no baseline; the host profile only logs the numbers
(see docs/ja/adr/0003-mask-bpf-loop-cursor.md).

The runner enumerates the selected tests independently, captures Go JSON events,
and rejects missing completions, package failures, and unexpected skips,
including skipped children of passing parent tests. The only skip exceptions
are exact TC corpus cases documenting mandatory VLAN matching the default tc
host rejects (`TestBpfVlanTCWireLoads` loads them with `--tc-vlan-reinsert`),
netfilter on kernel 6.1, and the tail-call and VLAN wire-frame veth fixtures in
the matrix images without a veth driver. Each exception also checks the diagnostic reason. The
host job must execute the veth and netfilter cases. Missing clang or BTF fixture
parameters are errors. The shell integration suite rejects all skips in CI.

The JSON report defaults to `/tmp/bpf-ninja-privileged.jsonl`; use `--log` to
retain another path. Matrix jobs publish both JSON and readable logs. Each Go
suite has a fifteen-minute timeout; the matrix job has a twenty-minute timeout.
The program suite contains bounded three-second negative argument-filter waits,
so its duration dominates the smaller attach, capture, and DSL suites.

Shell capture tests inspect the **final merged pcap-ng** using the independent
Python reader in `scripts/test/assert_pcap.py`. Packet counts are checked against
the shutdown summary for unsplit captures; split/capped captures must contain
packets with the expected length. Action interface names, Ethernet versus raw
IP link types, and explicit capture lengths are checked without an optional
tshark fallback. Missing, header-only, or truncated files fail. The reader and
privileged audit both have fault-injection tests under `scripts/tests`.

`TestBpfPrunedSubprog` in internal/program and `TestBpfPrunedSubprogCLI` in
cmd/bpf-ninja cover loaded `func_info` diagnostics using
`internal/program/testdata/pruned_subprog.c`.
The tests check fentry/fexit, explicit requests, function and parameter lists, multiple programs, and JSON
exclusion of skipped targets.
On 7.0 the disabled global call is removed; 6.1 retains that global function,
while removing the disabled static functions.
The CLI test uses two distinct disabled static functions for all-skipped selections
and checks that repeating one absent name retains the single-target explanation.
For a VM without clang, compile the fixture with
`clang -target bpf -O2 -g -c internal/program/testdata/pruned_subprog.c -o hooks.o`
and set `BPF_NINJA_SUBPROG_OBJECT` to that object's path when running the test
binaries.
Without that variable the tests compile the fixture with the usual test helper.
