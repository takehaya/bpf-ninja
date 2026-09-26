# Privileged test coverage

`make test-bpf` runs the host profile in `scripts/test/privileged.py`. It requires
root, clang with the BPF target, libbpf headers, libpcap, writable bpffs and
cgroup v2, veth, and a kernel with tcx support. The integration CI job provisions
these dependencies and runs the same command before the shell capture suite.
The Go suites run sequentially so fixtures using fixed interface names do not
collide. Do not run another host suite or integration setup concurrently.

| Profile | Required selection | Environment |
|---|---|---|
| Host | Every `Test*` in internal/program, internal/attach, internal/capture/..., cmd/bpf-ninja, and pkg/kunai/dsltest | Integration job, Ubuntu 24.04 runner |
| Kernel matrix | Every `TestBpf*` in internal/program and cmd/bpf-ninja; all tests in internal/attach, internal/capture/..., and pkg/kunai/dsltest | vimto, kernels 6.1/6.6/6.12/6.15/6.18/7.0 |

The host profile includes `TestLinearHeadClampAtCgroupSKB` and
`TestVlanUntagAtTCIngress`. It also exercises all attach discovery tests. The
matrix includes literal/slice, grouping, IPv6 length, and TCP option tests via
the complete DSL suite, plus tracing read-window tests with variable headers.
`python3 scripts/test/privileged.py --kernel 6.12` runs a matrix cell locally.

The runner enumerates the selected tests independently, captures Go JSON events,
and rejects missing completions, package failures, and unexpected skips,
including skipped children of passing parent tests. The only skip exceptions
are exact TC corpus cases documenting unsupported mandatory VLAN matching,
netfilter on kernel 6.1, and the tail-call veth fixture in the matrix images
without a veth driver. Each exception also checks the diagnostic reason. The
host job must execute the veth and netfilter cases. Missing clang or BTF fixture
parameters are errors. The shell integration suite rejects all skips in CI.

The JSON report defaults to `/tmp/bpf-ninja-privileged.jsonl`; use `--log` to
retain another path. Matrix jobs publish both JSON and readable logs. Each Go
suite has a five-minute timeout; the matrix job has a twenty-minute timeout.
The program suite contains bounded three-second negative argument-filter waits,
so its duration dominates the smaller attach, capture, and DSL suites.

Shell capture tests inspect the **final merged pcap-ng** using the independent
Python reader in `scripts/test/assert_pcap.py`. Packet counts are checked against
the shutdown summary for unsplit captures; split/capped captures must contain
packets with the expected length. Action interface names, Ethernet versus raw
IP link types, and explicit capture lengths are checked without an optional
tshark fallback. Missing, header-only, or truncated files fail. The reader and
privileged audit both have fault-injection tests under `scripts/tests`.
