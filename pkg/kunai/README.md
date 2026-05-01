[日本語版あり](./README.ja.md).

# kunai

`kunai` is a small Go library that compiles a one-liner packet-filter DSL into target-portable eBPF instructions, using P4-flavoured vocabulary files to describe protocol headers.

It was extracted from [xdp-ninja](https://github.com/takehaya/xdp-ninja) and is the engine behind its `--dsl` flag, but the package is self-contained: it has no XDP-specific dependencies in its public surface and can be wired into any tracing / fentry / fexit / tc / userspace BPF host that exposes a contiguous packet-bytes window.

> **Status**: pre-1.0. The public API is small (one `Compile` call) but may shift as the surface stabilises. Expect breaking changes between minor versions until 1.0.

## What it does

Given an expression like:

```text
eth/ipv4/udp/vxlan/eth/ipv4/tcp[dport=443]
eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where outer.dst == 0xc0a80101
eth/mpls{1,8}/ipv4/tcp where ipv4.total_length > 100 capture headers+64
```

`kunai.Compile` returns:

- A main eBPF instruction stream that writes `1` (accept) or `0` (reject) into `R2`.
- Optional bpf2bpf callback subprograms (used internally by the `+`/`*`/`{n,m}` chain quantifiers, which lower to `bpf_loop`).
- A `CaptureInfo` describing how many bytes of each packet the host should hand to perf-buffer / ring-buffer output.

The output is **target-agnostic**: it assumes only a contiguous packet window between two registers and a small set of working registers. Callers wrap it in a host-specific prologue (load packet pointers, copy into a scratch buffer, etc.) — see [`codegen/codegen.go`](./codegen/codegen.go) package doc for the exact ABI.

## Installation

```bash
go get github.com/takehaya/xdp-ninja/pkg/kunai
```

Requires Go 1.25+.

## Quick start

```go
package main

import (
    "fmt"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/asm"
    "github.com/takehaya/xdp-ninja/pkg/kunai"
    "github.com/takehaya/xdp-ninja/pkg/kunai/codegen"
)

func main() {
    // Zero Capabilities: target-agnostic filter (no action atoms).
    // For an XDP fexit attach point, import pkg/kunai/host/xdp and
    // pass xdp.FexitCapabilities() instead.
    out, err := kunai.Compile("eth/ipv4/tcp[dport=443]", codegen.Capabilities{})
    if err != nil {
        panic(err)
    }

    // out.Main is the filter body. Wrap it with your host's prologue
    // (load R0=packet_start, R1=packet_end, R9=pkt_len, then jump in)
    // and trailing `Mov.Imm(R0, 0); Return()` for the BPF program.
    prog := asm.Instructions{
        // ... host-specific prologue setting R0/R1/R9 ...
    }
    prog = append(prog, out.Main...)
    prog = append(prog, out.Callbacks...) // bpf_loop callbacks (BTF-tagged)

    fmt.Printf("filter is %d insns + %d callback insns; capture cap = %d bytes\n",
        len(out.Main), len(out.Callbacks), out.Capture.MaxCapLen)

    _ = ebpf.ProgramSpec{}.Type
}
```

For a complete worked example (XDP fentry/fexit attach + perf-event capture), see [`internal/program/program.go`](https://github.com/takehaya/xdp-ninja/blob/main/internal/program/program.go) in the parent xdp-ninja repo.

## Architecture (one paragraph)

The pipeline is `expr → AST → IR → asm.Instructions`. The AST is built by a hand-written recursive-descent parser; the IR holds vocabulary-resolved layer instances and binds every field reference to a concrete `*vocab.ProtocolSpec`; codegen lowers the IR to [cilium/ebpf](https://github.com/cilium/ebpf) `asm.Instructions` with verifier-safe bounds checks at every layer boundary. Variable-length quantifiers (`+`, `*`, `{n,m>4}`) and parser-machine self-loops emit a `bpf_loop` helper call into a bpf2bpf subprogram, which lands in **Linux 5.17**. Predicate codegen sticks to the BPF_END byte-swap family so it does not require BSWAP (`0xd7`, 6.6+). CI gates the matrix on 6.1 / 6.6 / 6.12 / 6.18 (`vimto`); chains without quantifiers or parser-machine self-loops can run on even older kernels.

The formal EBNF lives in [`docs/ja/dsl-grammar.md`](https://github.com/takehaya/xdp-ninja/blob/main/docs/ja/dsl-grammar.md). Code-level entry points: `pkg/kunai/codegen/codegen.go` (compile pipeline + ABI), `pkg/kunai/vocab/p4lite/` (P4-16 strict subset parser), `pkg/kunai/codegen/parser_machine.go` (variable-length header codegen).

## API

The public surface is intentionally tiny. Sub-packages are exported but considered semi-internal — they are needed to type the return value of `Compile` and to author custom vocabulary files at runtime, not as a programming surface.

```go
// kunai
func Compile(expr string, caps codegen.Capabilities) (codegen.Output, error)

// codegen
type Capabilities struct {
    // Action: symbolic name → integer for `where action == NAME`.
    // nil disables action atoms (the resolver rejects them).
    Action map[string]int32
    // ActionFetcher emits insns that load the action u32 into R3.
    // Required iff Action is non-nil.
    ActionFetcher ActionFetcher
    // ReservedLabels: symbol names @label cannot collide with.
    ReservedLabels map[string]bool
}

type ActionFetcher interface {
    EmitFetch(dst asm.Register) asm.Instructions
}

type Output struct {
    Main      asm.Instructions
    Callbacks asm.Instructions  // bpf2bpf subprograms (if any)
    Capture   CaptureInfo
}
type CaptureInfo struct {
    MaxCapLen int  // 0 = caller default
}
```

The host wires kunai to its specific BPF attach point by constructing a `Capabilities` value. The kunai core ships no host-specific helpers; canonical adapters live under [`host/`](./host/) sub-packages. For an XDP fexit attach point:

```go
import xdphost "github.com/takehaya/xdp-ninja/pkg/kunai/host/xdp"

caps := xdphost.FexitCapabilities()
out, err := kunai.Compile(expr, caps)
```

Other hosts (tc clsact, userspace `BPF_PROG_TEST_RUN`, custom tracing) supply their own `ActionFetcher` + symbolic-name map by adding a `host/<name>/` package alongside `host/xdp/`. See [`codegen/caps.go`](./codegen/caps.go) for the `Capabilities` / `ActionFetcher` contract and [`codegen/codegen.go`](./codegen/codegen.go)'s package doc for the runFilter ABI the host wraps.

Errors are returned as-is from each phase. Recognise them with `errors.As`/`errors.Is`:

- Lexer / parser errors are `*lexer.SyntaxError`.
- Resolver errors are `*resolve.Error` (alias of the syntax error type, with file/line/col preserved).
- Codegen errors include `codegen.ErrNotImplemented` for valid DSL that the MVP codegen has not yet emitted (use `errors.Is(err, codegen.ErrNotImplemented)` to distinguish from real bugs).

## Bundled vocabulary

The library ships with 16 baked-in protocol definitions: `eth`, `vlan`, `qinq`, `cw`, `mpls`, `ipv4`, `ipv6`, `tcp`, `udp`, `icmp`, `icmp6`, `gre`, `vxlan`, `geneve`, `gtp`, `srv6`. They live as `.p4` files under [`protocols/`](./protocols/) and are embedded at build time via `//go:embed`.

To add a new protocol, drop a `<name>.p4` file into `protocols/` and follow the dispatch-constant naming convention. The loader's regex tables in [`pkg/kunai/vocab/loader.go`](./vocab/loader.go) (search for `classifyConsts` and `re*` regexes) are the authoritative reference — any malformed name is rejected at startup.

The `.p4` files are a strict subset of P4-16 syntax — they pass the official `p4c --parse-only` (CI verifies this on every change). See `docker/p4c-check/` in the parent repo for the test harness.

Vocabulary parsing is memoised: `dslvocab.Bundled()` (in `pkg/kunai/dslvocab/`) wraps `vocab.Load` with `sync.Once`, so the 16 `.p4` files are parsed once per process and every subsequent `kunai.Compile()` call reuses the cached `ProtocolSpec` map. There is no persistent (on-disk / build-time) cache — parsing the bundled set takes microseconds and is dwarfed by BPF program load, so the in-memory cache is sufficient.

## Versioning & stability

- Public API: `kunai.Compile`, `codegen.Capabilities`, `codegen.ActionFetcher`, `codegen.Output`, `codegen.CaptureInfo`, the `host/xdp` adapter package, and the error types listed above.
- Everything else (AST nodes, IR types, vocab loader internals, parser internals, the `dslvocab.Bundled` cache) may change without notice.
- `pkg/kunai/dsltest` (the gopacket-based packet-level harness) is **experimental** until 1.0 — its `Runner` API and packet builders may change without notice. Pin a tagged version if downstream tests depend on it.
- The protocol vocabulary is treated as part of the public surface — adding new protocols is non-breaking; renaming or removing one is a breaking change.

## Related projects

- [xdp-ninja](https://github.com/takehaya/xdp-ninja) — non-invasive XDP observability tool that is the primary consumer of this package.
- [cilium/ebpf](https://github.com/cilium/ebpf) — the BPF assembler / loader the codegen targets.
- [cloudflare/cbpfc](https://github.com/cloudflare/cbpfc) — alternative classical-BPF (tcpdump syntax) compiler, used by xdp-ninja when `--dsl` is not set.
- [p4lang/p4c](https://github.com/p4lang/p4c) — official P4 compiler, used in CI to verify our `.p4` vocab files stay within P4-16.

## License

Same as the parent xdp-ninja repository.
