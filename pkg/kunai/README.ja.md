[English version is available](./README.md).

# kunai

`kunai` は、一行のパケットフィルタ DSL を target-portable な eBPF 命令列にコンパイルする小さな Go ライブラリです。プロトコルヘッダの記述には P4 風の vocabulary ファイルを使います。

[bpf-ninja](https://github.com/takehaya/bpf-ninja) から切り出されたライブラリで、bpf-ninja のデフォルト DSL フィルタモードの実体です。ただしパッケージ自体は自己完結しており、public surface に XDP 固有の依存はありません。連続したパケットバイト列のウィンドウを見せられるホストであれば、tracing、fentry/fexit、tc、userspace BPF のどれにでも組み込めます。

> ステータスは pre-1.0 です。public API は `Compile` 1 つと小さいものの、surface が安定するまでは変わる可能性があります。1.0 までは minor バージョン間で breaking change が起こり得ます。

## 何をするか

次のような式を `kunai.Compile` に渡します。

```text
eth/ipv4/udp/vxlan/eth/ipv4/tcp[dport==443]
eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where outer.dst == 0xc0a80101
eth/mpls{1,8}/ipv4/tcp where ipv4.total_length > 100 capture headers+64
eth/ipv4/udp/gtp[opt.next_ext == 0]/ipv4/tcp                            # auxiliary header field
eth/ipv6/srv6/tcp where any(srv6.segments.addr == fc00::1)              # aux header stack quantifier
eth/ipv4/tcp where tcp.options.MSS.value == 1460                        # TCP option lookup
```

すると以下が返ります。

- main eBPF 命令列。`R2` に accept なら `1`、reject なら `0` を書き込みます。
- bpf2bpf callback subprogram。chain quantifier の `+`/`*`/`{n,m}` が `bpf_loop` に lower されるときに内部で使われます。無ければ空です。
- `CaptureInfo`。各パケットのうち何バイトを perf-buffer / ring-buffer 出力に渡すべきかを示します。
- `Extractions` と `Warnings`。前者は `field in @set` 述語のためにフィルタが stack slot へ書き出したフィールドの一覧、後者は非致命的なコンパイル時の注意です。

出力は target-agnostic です。2 つのレジスタで挟まれた連続パケットウィンドウと、少数のワーキングレジスタだけを仮定します。呼び出し側は、パケットポインタのロードや scratch buffer へのコピーといったホスト固有の prologue で出力を包みます。正確な ABI は [`codegen/codegen.go`](./codegen/codegen.go) のパッケージ doc を参照してください。

## インストール

```bash
go get github.com/takehaya/bpf-ninja/pkg/kunai
```

Go 1.25 以上が必要です。

## クイックスタート

```go
package main

import (
    "fmt"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/asm"
    "github.com/takehaya/bpf-ninja/pkg/kunai"
    "github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

func main() {
    // 0 値の Capabilities = target-agnostic (action atom 不可)。
    // XDP fexit attach では pkg/kunai/host/xdp を import して
    // xdp.FexitCapabilities() を渡す。
    out, err := kunai.Compile("eth/ipv4/tcp[dport==443]", codegen.Capabilities{})
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

XDP fentry/fexit attach と perf-event capture を含む完全な動作例は、親リポジトリ bpf-ninja の [`internal/program/program.go`](https://github.com/takehaya/bpf-ninja/blob/main/internal/program/program.go) を参照してください。

## アーキテクチャ

パイプラインは `expr → AST → IR → asm.Instructions` です。AST は手書きの再帰下降パーサが構築します。IR は vocab 解決済みの layer instance を保持し、すべてのフィールド参照を具体的な `*vocab.ProtocolSpec` にバインドします。codegen は IR を [cilium/ebpf](https://github.com/cilium/ebpf) の `asm.Instructions` に lower し、各 layer 境界で verifier-safe な bounds check を emit します。可変長 quantifier の `+`、`*`、`{n,m>4}` と parser machine の self-loop は bpf2bpf subprogram への `bpf_loop` 呼び出しに落ちるため、Linux 5.17 以上が必要です。predicate codegen は BPF_END 系の byte-swap を使うので、6.6 で入った BSWAP 命令 `0xd7` には依存しません。CI は `vimto` で 6.1 / 6.6 / 6.12 / 6.15 / 6.18 / 7.0 の matrix を検証します。quantifier も parser machine の self-loop も含まない chain なら、さらに古い kernel でも動きます。

formal な EBNF は [`docs/ja/dsl-grammar.md`](https://github.com/takehaya/bpf-ninja/blob/main/docs/ja/dsl-grammar.md) にあります。コード側のエントリポイントは、compile pipeline と ABI を記述した `pkg/kunai/codegen/codegen.go`、P4-16 strict subset パーサの `pkg/kunai/vocab/p4lite/`、そして可変長 header codegen を担う `pkg/kunai/codegen/` の `parser_state.go` / `parser_trail.go` / `parser_select.go` / `parser_loop.go` の 4 ファイルです。4 ファイルへの分割はレビューしやすさのためです。

## API

public surface は意図的に最小です。サブパッケージは export されていますが semi-internal 扱いです。`Compile` の戻り値の型付けと、実行時に独自 vocabulary ファイルを与える用途のために公開しているだけで、プログラミングインタフェースとしての利用は想定していません。

```go
// kunai
func Compile(expr string, caps codegen.Capabilities) (codegen.Output, error)

// codegen — フェーズ別の 3 グループを束ねる薄い集約体。
type Capabilities struct {
    Lex  LexCaps    // parser: label の予約
    Lang LangCaps   // resolver + codegen: action / set atom
    Host HostLayout // codegen: ホストのパケットレイアウト
}

type LexCaps struct {
    // ReservedLabels: @label が衝突してはならない symbol 名の集合。
    // nil なら Compile が Lang.Action のキーから導出する。
    ReservedLabels map[string]bool
}

type LangCaps struct {
    // Action: `where action == NAME` 用の symbolic 名 → 整数。
    // nil で action atom を無効化 (resolver が拒否する)。
    Action map[string]int32
    // ActionFetcher: action の u32 を R3 にロードする命令列を emit する。
    // Action が non-nil のとき必須。
    ActionFetcher ActionFetcher
    // SetSlots: `field in @set` 述語を、抽出フィールドを格納する
    // R10 stack slot に解決する。nil で `in @set` を無効化。
    SetSlots SetSlotResolver
}

type HostLayout struct {
    // VlanInMetadata: kernel が outer VLAN tag を skb metadata へ
    // 抜き出し済み (tc)。true なら vlan/qinq を含む chain を
    // コンパイル時に拒否する。
    VlanInMetadata bool
    // PacketStartsAtL3: パケットウィンドウが L3 ヘッダから始まる
    // (cgroup-skb)。true なら resolver は eth root の chain に警告する。
    PacketStartsAtL3 bool
}

type ActionFetcher interface {
    EmitFetch(dst asm.Register) asm.Instructions
}

type Output struct {
    Main        asm.Instructions
    Callbacks   asm.Instructions // bpf2bpf subprogram (あれば)
    Capture     CaptureInfo
    Extractions []ExtractSlot    // `in @set` の map lookup 用に埋めた stack slot
    Warnings    []string         // 非致命的な resolver / codegen の注意
}
type CaptureInfo struct {
    MaxCapLen       int // 0 = caller default (ホストの DefaultCapLen に fallback)
    FilterMinPrefix int // フィルタが実際に読むバイト数 (0 = caller fallback)
}
```

`MaxCapLen` は、ホストが ringbuf に確保しパケットからコピーすべき payload バイト数です。非ゼロの値は明示的な `capture` 節に由来します。たとえば `capture headers` は 54 B、`capture headers+64` は 118 B、`capture absolute 96` は 96 B になります。DSL に `capture` 節が無い場合は 0 のままで、ホストは自身のデフォルトに fallback します。bpf-ninja は libpcap / tcpdump の全パケット挙動に合わせて `DefaultCapLen = 1500` を使います。節の省略は `capture all` の糖衣です。ringbuf 確保量を絞って throughput を稼ぎたい場合は、`capture headers` で明示的に opt-in するか、ホスト CLI の `--snaplen` で縮めます。

`FilterMinPrefix` は、コンパイル済みフィルタがパケットから読む最大バイトオフセットです。chain の自然なヘッダ prefix 長と、マージ済み where 節の最右フィールド末尾を合成した値になります。tracing ホストの LoadEntry / LoadExit はこれを使って per-CPU scratch map への `bpf_probe_read_kernel` の読み取り量を決めるので、`eth/ipv4/tcp where tcp.dport == 443` のような単純なフィルタは 54 B だけを読み、保守的な `ScratchBufSize` 分のコピーを避けられます。0 は解析を断念したことを意味します。quantifier 付き chain や heterogeneous alternation がこれに当たり、ホストは scratch 全読みに fallback します。`FilterMinPrefix` は `MaxCapLen` から独立です。scratch 読みの最適化は、ユーザーが `capture headers` で ringbuf 側の最適化に opt-in したかどうかに関わらず常に効きます。

ホストは `Capabilities` 値を構築して、kunai を自分の BPF attach point に接続します。kunai コアはホスト固有の helper を持たず、canonical adapter は [`host/`](./host/) 以下のサブパッケージにあります。現在は `host/xdp`、`host/tc`、`host/cgroupskb` の 3 つです。XDP fexit の場合は次のように書きます。

```go
import xdphost "github.com/takehaya/bpf-ninja/pkg/kunai/host/xdp"

caps := xdphost.FexitCapabilities()
out, err := kunai.Compile(expr, caps)
```

userspace の `BPF_PROG_TEST_RUN` や独自 tracing のような他のホストは、`host/xdp/` と並ぶ形で `host/<name>/` パッケージを追加し、独自の `ActionFetcher` と symbol map を提供します。`Capabilities` / `ActionFetcher` の契約は [`codegen/caps.go`](./codegen/caps.go) を、ホストが wrap すべき runFilter ABI は [`codegen/codegen.go`](./codegen/codegen.go) のパッケージ doc を参照してください。

エラーは各フェーズからそのまま返ります。`errors.As` / `errors.Is` で識別します。

- lexer / parser のエラーは `*lexer.SyntaxError` です。
- resolver のエラーは `*resolve.Error` です。syntax error 型のエイリアスで、file / line / col を保持します。
- codegen のエラーには `codegen.ErrNotImplemented` が含まれます。これは MVP codegen がまだ emit していない有効な DSL に対するエラーで、本物のバグと区別するには `errors.Is(err, codegen.ErrNotImplemented)` を使います。

## 同梱 vocabulary

ライブラリは `eth`, `vlan`, `qinq`, `cw`, `mpls`, `ipv4`, `ipv6`, `tcp`, `udp`, `icmp`, `icmp6`, `gre`, `esp`, `vxlan`, `geneve`, `gtp`, `srv6` の 17 プロトコル定義を同梱しています。[`protocols/`](./protocols/) 以下に `.p4` ファイルとして置かれ、ビルド時に `//go:embed` で埋め込まれます。

新しいプロトコルを追加するには、`<name>.p4` を `protocols/` に置き、dispatch 定数の命名規約に従います。命名規約の正規定義は [`pkg/kunai/vocab/loader.go`](./vocab/loader.go) の `classifyConsts` 周辺の regex 群です。loader は malformed な名前を起動時に reject します。

`.p4` ファイルは P4-16 構文の strict subset で、公式の `p4c --parse-only` を通ります。CI がすべての変更でこれを検証します。テストハーネスは親リポジトリの `docker/p4c-check/` にあります。

vocabulary のパース結果は、`pkg/kunai/dslvocab/` の `dslvocab.Bundled()` が `sync.Once` でキャッシュします。同一プロセスで `kunai.Compile()` を何度呼んでも、17 ファイルのパースは 1 回だけです。パースは microsecond オーダーで BPF プログラムのロードに比べて誤差のため、on-disk やビルド時の永続キャッシュは持ちません。

## バージョニングと安定性

- public API は次のとおりです。`kunai.Compile`、カスタム vocab を受け入れる `kunai.CompileWithVocab`、bpf-ninja の `--dsl-help` が使う `kunai.SyntaxHelp` / `kunai.ExamplesHelp` / `kunai.WriteProtocolCatalogue` / `kunai.WriteProtocolHelp`、`codegen.Capabilities` とその構成要素 `LexCaps` / `LangCaps` / `HostLayout` / `SetSlotResolver`、`codegen.ActionFetcher`、`codegen.Output` と `CaptureInfo` / `ExtractSlot`、host wrapper 用の `codegen.MainFilterFuncBTF`、位置情報付きエラー型の `codegen.PositionedError`、`host/xdp` / `host/tc` / `host/cgroupskb` の adapter パッケージ、上記のエラー型です。
- それ以外の AST node、IR 型、vocab loader 内部、parser 内部、`dslvocab.Bundled` キャッシュは、予告なく変わる可能性があります。
- gopacket ベースのパケットレベルハーネス `pkg/kunai/dsltest` は experimental です。1.0 までは `Runner` API と packet builder を予告なく変更する可能性があるので、下流のテストが依存する場合は tag を固定してください。
- プロトコル vocabulary は public surface の一部として扱います。新プロトコルの追加は非破壊変更、リネームや削除は破壊変更です。

## 関連プロジェクト

- [bpf-ninja](https://github.com/takehaya/bpf-ninja) は、本パッケージのメイン consumer である非侵襲 BPF 観測ツールです。XDP / tc / cgroup-skb のフックポイントを扱います。
- [cilium/ebpf](https://github.com/cilium/ebpf) は、codegen がターゲットにする BPF アセンブラ / ローダです。
- [cloudflare/cbpfc](https://github.com/cloudflare/cbpfc) は、tcpdump 構文の classical BPF を変換する代替コンパイラです。bpf-ninja は `--cbpf` 指定時の legacy 経路で使います。
- [p4lang/p4c](https://github.com/p4lang/p4c) は公式の P4 コンパイラです。`.p4` vocab ファイルが P4-16 に収まっていることを CI で検証するのに使います。

## ライセンス

親リポジトリ bpf-ninja と同じです。
