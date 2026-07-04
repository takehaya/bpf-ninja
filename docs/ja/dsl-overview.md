# xdp-ninja DSL ドキュメント

xdp-ninja の filter 式である DSL のドキュメント index です。GTP-U や MPLS、VXLAN、SRv6 のような多段カプセル化は legacy の `--cbpf` が使う tcpdump 構文では書きにくいので、これをプロトコルスタックの形のまま書けるようにするのが目的です。DSL は xdp-ninja の default filter syntax です。

## 役割別にどこから読むか

| あなたは | 読む順 |
|---|---|
| 使いたい (CLI のフィルタ式を書く) | [`dsl-usage.md`](./dsl-usage.md) → [`dsl-grammar.md`](./dsl-grammar.md) (詳しい文法) |
| library として使いたい (Go から `kunai.Compile`) | [`pkg/kunai/README.md`](../../pkg/kunai/README.md) (英語) |
| vocab を書きたい (新プロトコル追加) | [`dsl-vocab-authoring.md`](./dsl-vocab-authoring.md) (hands-on 完全版) + [`pkg/kunai/protocols/`](../../pkg/kunai/protocols/) の既存 .p4 |
| 可変長構造をどう vocab で表すか知りたい (chain vs aux の判断) | [`dsl-internals.md` §6](./dsl-internals.md#6-可変長構造の分類と表現) |
| TCP 多 option フィルタの codegen を知りたい (bit accumulator + forget) | [`dsl-multi-option-accumulator.md`](./dsl-multi-option-accumulator.md) |
| 型 / 演算子の意味を知りたい (異幅 cmp、bit-slice、Bool、CIDR、各種 literal) | [`dsl-types.md` Part I](./dsl-types.md) (実装者向け実用仕様) |
| 形式仕様を読みたい (抽象構文、typing judgments、操作的意味論) | [`dsl-types.md` Part II](./dsl-types.md#part-ii-形式仕様-構文論--操作的意味論) (§11-§15) |
| 中身をレビューしたい (codegen / verifier) | [`dsl-internals.md` §2.3-§2.5](./dsl-internals.md#23-パッケージごとのツアー-依存順leaf--root) (パッケージ別ツアー + キー概念 + チェックリスト) |
| 何が残っているか見たい | [`dsl-followups.md`](./dsl-followups.md) |
| 性能比較したい | [`dsl-benchmark.md`](./dsl-benchmark.md) |
| 設計思想を物語形式で読みたい (連載 3 部作) | [`kunai-overview-article.md`](./kunai-overview-article.md) → [`kunai-dsl-deepdive.md`](./kunai-dsl-deepdive.md) → [`kunai-codegen-deepdive.md`](./kunai-codegen-deepdive.md) |

## ファイル一覧

| ファイル | 内容 | 行数目安 |
|---|---|---|
| [`dsl-usage.md`](./dsl-usage.md) | ユーザー向け CLI ガイド (例文豊富) | ~360 |
| [`dsl-grammar.md`](./dsl-grammar.md) | formal EBNF (filter 式 + p4lite) + 例文 + parser 関数マッピング | ~360 |
| [`dsl-types.md`](./dsl-types.md) | 言語仕様書 Part I (型・widening・fit check・エラーカタログ・実装ステージング) + Part II (抽象構文・typing rules・操作的意味論・soundness sketch) | ~1340 |
| [`dsl-internals.md`](./dsl-internals.md) | 設計動機 / アーキテクチャ / パッケージ別ツアー / codegen ABI / vocab 開発ガイド / P4-16 互換性 / レビューチェックリスト | ~960 |
| [`dsl-vocab-authoring.md`](./dsl-vocab-authoring.md) | vocab 開発の hands-on ガイド。.p4 の書き方全規約 (const / parser block / annotation)、可変長 8 機構の書き分け、loader 制約早見表、テスト手順、実例 walkthrough | ~570 |
| [`dsl-followups.md`](./dsl-followups.md) | 残作業 (P0 完 / P1 完 / P2 / B / P3 / P4 階層) | ~470 |
| [`dsl-benchmark.md`](./dsl-benchmark.md) | cbpfc vs DSL のベンチ方法論 | ~160 |
| [`kunai-overview-article.md`](./kunai-overview-article.md) | 連載 3 部作の第 1 回。なぜ kunai を作ったか / DSL で書ける式 / 全体アーキ (読み物) | ~250 |
| [`kunai-dsl-deepdive.md`](./kunai-dsl-deepdive.md) | 連載 3 部作の第 2 回。lexer / parser / resolver の実装読み込み (読み物) | ~340 |
| [`kunai-codegen-deepdive.md`](./kunai-codegen-deepdive.md) | 連載 3 部作の第 3 回。IR → BPF lowering / ABI / chain quantifier 戦略 (読み物) | ~335 |
| [`../../pkg/kunai/README.md`](../../pkg/kunai/README.md) | library 利用者向け (英語、godoc/pkg.go.dev 想定) | - |

## 30 秒でわかる概要

```
filter expr  →  AST  →  IR (vocab 解決済)  →  asm.Instructions  →  cilium/ebpf load
   ↑                ↑                              ↑
   one-liner       parser                          codegen
                   (pkg/kunai/parser/)          (pkg/kunai/codegen/)
```

- `eth/ipv4/tcp[dport==443]` 風の layer chain が書けます。各 layer は vocab `.p4` ファイル (`pkg/kunai/protocols/*.p4`) で定義された protocol です。
- vocab は P4-16 の strict subset である p4lite を Go 側の `pkg/kunai/vocab/p4lite/` で parse します。p4c で標準パースできるのが目標です。詳しくは internals §5 を参照してください。
- 出力は cilium/ebpf の `asm.Instructions` で、target portable な eBPF subprogram です。kunai コアは XDP / tc 等の host 知識を持たず、host adapter は `pkg/kunai/host/<name>/` サブパッケージに局所化しています。`host/xdp` は XDP fentry/fexit、`host/tc` は TC clsact fentry/fexit です。
- caller (`internal/program/program.go`) は `kunai.Compile(expr, caps)` に host capability (`xdphost.FexitCapabilities()` / `tchost.FexitCapabilities()` 等) を渡すことで host を選びます。zero `Capabilities` だと、action atom を使えない target-agnostic な filter が出ます。

## 関連コード

- DSL 本体: `pkg/kunai/`
- Vocab: `pkg/kunai/protocols/*.p4`
- Host adapter: `pkg/kunai/host/xdp/` (XDP fentry/fexit) + `pkg/kunai/host/tc/` (TC clsact fentry/fexit、sk_buff data/len offset を BTF で実行時解決)。新 host を追加するときは `host/<name>/` を並べます
- ABI 契約 (kunai ↔ host): `pkg/kunai/codegen/codegen.go` の package doc + `KunaiStackTop` constant
- 既存 fentry/fexit との接続: `internal/program/program.go::compileFilter`
- CLI 入口: `cmd/xdp-ninja/main.go` の `resolveFilterSyntax()` (DSL がデフォルト、`--cbpf` で legacy)
