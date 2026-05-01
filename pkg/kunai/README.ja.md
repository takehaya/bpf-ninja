[English version is available](./README.md).

# kunai

`kunai` は一行のパケットフィルタ DSL を target-portable な eBPF 命令列にコンパイルする小さな Go ライブラリ。プロトコルヘッダの記述には P4 風の vocabulary ファイルを使う。

[xdp-ninja](https://github.com/takehaya/xdp-ninja) から切り出されたもので、その `--dsl` フラグの実体だが、パッケージ自体は self-contained。public surface に XDP 固有の依存はなく、連続したパケットバイト列のウィンドウを露出するホストであれば tracing / fentry / fexit / tc / userspace BPF など何にでも組み込める。

> **ステータス**: pre-1.0。public API は小さい (`Compile` 1 つ) が、surface が安定するまでは変動しうる。1.0 までは minor バージョン間で breaking change があり得る。

## 何をするか

次のような式を:

```text
eth/ipv4/udp/vxlan/eth/ipv4/tcp[dport=443]
eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where outer.dst == 0xc0a80101
eth/mpls{1,8}/ipv4/tcp where ipv4.total_length > 100 capture headers+64
eth/ipv4/udp/gtp[opt.next_ext == 0]/ipv4/tcp                            # auxiliary header field
eth/ipv6/srv6/tcp where any(srv6.segments.addr == fc00::1)              # aux header stack quantifier
eth/ipv4/tcp where tcp.options.MSS.value == 1460                        # TCP option lookup
```

`kunai.Compile` に渡すと以下が返る:

- main eBPF 命令列 (`R2` に `1` (accept) または `0` (reject) を書き込む)
- オプションの bpf2bpf callback subprogram (`+`/`*`/`{n,m}` の chain quantifier が `bpf_loop` に lower される際に内部で使う)
- `CaptureInfo` (各パケットのうち何バイトを perf-buffer / ring-buffer 出力に渡すべきかを示す)

出力は **target-agnostic**: 2 レジスタ間の連続したパケットウィンドウと少数のワーキングレジスタを仮定するだけ。呼び出し側がホスト固有の prologue (パケットポインタのロード、scratch buffer への copy など) で wrap する。正確な ABI は [`codegen/codegen.go`](./codegen/codegen.go) のパッケージ doc を参照。

## インストール

```bash
go get github.com/takehaya/xdp-ninja/pkg/kunai
```

Go 1.25+ が必要。

## クイックスタート

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
    // 0 値の Capabilities = target-agnostic (action atom 不可)。
    // XDP fexit attach では pkg/kunai/host/xdp を import して
    // xdp.FexitCapabilities() を渡す。
    out, err := kunai.Compile("eth/ipv4/tcp[dport=443]", codegen.Capabilities{})
    if err != nil {
        panic(err)
    }

    // out.Main がフィルタ本体。ホスト側の prologue で wrap する
    // (R0=packet_start, R1=packet_end, R9=pkt_len をロードしてから jump in)
    // 末尾には BPF プログラム用の `Mov.Imm(R0, 0); Return()` を付ける。
    prog := asm.Instructions{
        // ... R0/R1/R9 を設定するホスト固有 prologue ...
    }
    prog = append(prog, out.Main...)
    prog = append(prog, out.Callbacks...) // bpf_loop callback (BTF tag 付き)

    fmt.Printf("filter is %d insns + %d callback insns; capture cap = %d bytes\n",
        len(out.Main), len(out.Callbacks), out.Capture.MaxCapLen)

    _ = ebpf.ProgramSpec{}.Type
}
```

完全な動作例 (XDP fentry/fexit attach + perf-event capture) は親リポジトリ xdp-ninja の [`internal/program/program.go`](https://github.com/takehaya/xdp-ninja/blob/main/internal/program/program.go) を参照。

## アーキテクチャ (一段落)

パイプラインは `expr → AST → IR → asm.Instructions`。AST は手書きの再帰下降パーサで構築、IR は vocab 解決済みの layer instance を保持し、すべてのフィールド参照を具体的な `*vocab.ProtocolSpec` にバインドする。codegen は IR を [cilium/ebpf](https://github.com/cilium/ebpf) の `asm.Instructions` に lower し、各 layer 境界で verifier-safe な bounds check を emit する。可変長 quantifier (`+`, `*`, `{n,m>4}`) と parser machine の self-loop は `bpf_loop` ヘルパ呼び出しを bpf2bpf subprogram に対して emit するため、**Linux 5.17+** が必要。predicate codegen は BPF_END byte-swap family を使うので BSWAP (`0xd7`、6.6+) には依存しない。CI matrix は `vimto` で 6.1 / 6.6 / 6.12 / 6.18 を gating。quantifier / parser-machine self-loop を含まない chain ならさらに古い kernel でも動作する。

formal な EBNF は [`docs/ja/dsl-grammar.md`](https://github.com/takehaya/xdp-ninja/blob/main/docs/ja/dsl-grammar.md) にある。コード側のエントリポイント: `pkg/kunai/codegen/codegen.go` (compile pipeline + ABI)、`pkg/kunai/vocab/p4lite/` (P4-16 strict subset parser)、`pkg/kunai/codegen/parser_machine.go` (可変長 header codegen)。

## API

public surface は意図的に最小。サブパッケージは export されているが semi-internal 扱い — `Compile` の戻り値の型付けや、runtime に独自 vocabulary ファイルを書く用途には必要だが、プログラミングインタフェースとして使うことは想定していない。

```go
// kunai
func Compile(expr string, caps codegen.Capabilities) (codegen.Output, error)

// codegen
type Capabilities struct {
    // Action: symbolic 名 → 整数 (`where action == NAME` 用)。
    // nil で action atom を無効化 (resolver が拒否)。
    Action map[string]int32
    // ActionFetcher: action u32 を R3 にロードする命令列を emit。
    // Action が non-nil なら必須。
    ActionFetcher ActionFetcher
    // ReservedLabels: @label と衝突させない symbol 集合。
    ReservedLabels map[string]bool
}

type ActionFetcher interface {
    EmitFetch(dst asm.Register) asm.Instructions
}

type Output struct {
    Main      asm.Instructions
    Callbacks asm.Instructions  // bpf2bpf subprogram (あれば)
    Capture   CaptureInfo
}
type CaptureInfo struct {
    MaxCapLen int  // 0 = caller default
}
```

ホストは `Capabilities` 値を構築して kunai を自分の BPF attach point に接続する。kunai コアは host 固有 helper を持たず、canonical adapter は [`host/`](./host/) サブパッケージに置かれる。XDP fexit 例:

```go
import xdphost "github.com/takehaya/xdp-ninja/pkg/kunai/host/xdp"

caps := xdphost.FexitCapabilities()
out, err := kunai.Compile(expr, caps)
```

他ホスト (tc clsact / userspace `BPF_PROG_TEST_RUN` / 独自 tracing) は `host/xdp/` と並ぶ形で `host/<name>/` を追加し、独自の `ActionFetcher` + symbol map を提供する。`Capabilities` / `ActionFetcher` の契約は [`codegen/caps.go`](./codegen/caps.go)、host が wrap すべき runFilter ABI は [`codegen/codegen.go`](./codegen/codegen.go) の package doc を参照。

エラーは各フェーズからそのまま返る。`errors.As` / `errors.Is` で識別する:

- Lexer / parser エラーは `*lexer.SyntaxError`
- Resolver エラーは `*resolve.Error` (syntax error 型のエイリアス、file/line/col を保持)
- Codegen エラーには `codegen.ErrNotImplemented` が含まれる。これは MVP codegen がまだ emit していない有効な DSL に対するエラーで、本物のバグと区別するには `errors.Is(err, codegen.ErrNotImplemented)` を使う

## 同梱 vocabulary

ライブラリには 16 個のプロトコル定義が組み込み済み: `eth`, `vlan`, `qinq`, `cw`, `mpls`, `ipv4`, `ipv6`, `tcp`, `udp`, `icmp`, `icmp6`, `gre`, `vxlan`, `geneve`, `gtp`, `srv6`。これらは [`protocols/`](./protocols/) 以下に `.p4` ファイルとして置かれ、ビルド時に `//go:embed` で埋め込まれる。

新プロトコルを追加するには、`<name>.p4` を `protocols/` に置き、dispatch-constant の命名規約に従う。命名規約の正規定義は [`pkg/kunai/vocab/loader.go`](./vocab/loader.go) の `classifyConsts` 周辺の regex 群を参照。vocabulary loader は regex ベースで、起動時に malformed な名前を reject する。

`.p4` ファイルは P4-16 構文の strict subset であり、公式 `p4c --parse-only` を通る (CI で全変更について検証している)。テストハーネスは親リポジトリの `docker/p4c-check/` を参照。

vocabulary のパースは `dslvocab.Bundled()` 内で `sync.Once` により **process 内で 1 回限り**にキャッシュされる (`pkg/kunai/dslvocab/dslvocab.go`)。同 process で `kunai.Compile()` を複数回呼んでも 16 ファイルの再パースは発生しない。永続キャッシュ (build-time / on-disk) は parse コストが microsecond オーダーで意義が薄いため未実装。

## バージョニングと安定性

- public API: `kunai.Compile`, `codegen.Capabilities`, `codegen.ActionFetcher`, `codegen.Output`, `codegen.CaptureInfo`, `host/xdp` adapter パッケージ、上記のエラー型
- それ以外 (AST node、IR 型、vocab loader 内部、parser 内部、`dslvocab.Bundled` キャッシュ) は予告なく変更される可能性あり
- `pkg/kunai/dsltest` (gopacket-based packet-level harness) は **experimental**。1.0 までは `Runner` API / packet builder を予告なく変更する可能性あり。下流 test が依存する場合は tag 固定推奨
- プロトコル vocabulary は public surface の一部として扱う — 新プロトコル追加は非破壊変更、リネーム/削除は破壊変更

## 関連プロジェクト

- [xdp-ninja](https://github.com/takehaya/xdp-ninja) — 本パッケージのメイン consumer である非侵襲 XDP 観測ツール
- [cilium/ebpf](https://github.com/cilium/ebpf) — codegen のターゲットである BPF アセンブラ / ローダ
- [cloudflare/cbpfc](https://github.com/cloudflare/cbpfc) — 代替の classical-BPF (tcpdump 構文) コンパイラ。xdp-ninja は `--dsl` 未指定時にこれを使う
- [p4lang/p4c](https://github.com/p4lang/p4c) — 公式 P4 コンパイラ。`.p4` vocab ファイルが P4-16 内に収まっていることを CI で検証するのに使う

## ライセンス

親リポジトリ xdp-ninja と同じ。
