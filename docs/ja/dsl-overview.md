# xdp-ninja DSL ドキュメント

`--dsl` フラグで使う一行フィルタ DSL のドキュメント index。tcpdump 構文で書きにくい多段カプセル化 (GTP-U / MPLS / VXLAN / SRv6 …) を「プロトコルスタックの形」のまま書けるのが目的。

## 役割別にどこから読むか

| あなたは | 読む順 |
|---|---|
| **使いたい** (CLI で `--dsl` を叩く) | [`dsl-usage.md`](./dsl-usage.md) → [`dsl-grammar.md`](./dsl-grammar.md) (詳しい文法) |
| **library として使いたい** (Go から `kunai.Compile`) | [`pkg/kunai/README.md`](../../pkg/kunai/README.md) (英語) |
| **vocab を書きたい** (新プロトコル追加) | [`pkg/kunai/protocols/`](../../pkg/kunai/protocols/) の既存 .p4 を参考に + [`pkg/kunai/vocab/loader.go`](../../pkg/kunai/vocab/loader.go) の `classifyConsts` で命名規約を確認 |
| **中身をレビューしたい** (codegen / verifier) | [`dsl-walkthrough.md`](./dsl-walkthrough.md) (コード読解ガイド) |
| **何が残ってるか見たい** | [`dsl-followups.md`](./dsl-followups.md) |
| **性能比較したい** | [`dsl-benchmark.md`](./dsl-benchmark.md) |

## ファイル一覧

- [`dsl-usage.md`](./dsl-usage.md) — ユーザー向け CLI ガイド
- [`dsl-grammar.md`](./dsl-grammar.md) — formal EBNF (filter 式 + p4lite) + 例文 + parser 関数マッピング
- [`dsl-walkthrough.md`](./dsl-walkthrough.md) — `pkg/kunai/` のコードを読み下すための内部ガイド (レビュー用)
- [`dsl-followups.md`](./dsl-followups.md) — 残作業 (P0 → P5)
- [`dsl-benchmark.md`](./dsl-benchmark.md) — cbpfc vs DSL のベンチ方法論
- [`../../pkg/kunai/README.md`](../../pkg/kunai/README.md) — library 利用者向け (英語、godoc/pkg.go.dev 想定)

## 30 秒でわかる概要

```
filter expr  →  AST  →  IR (vocab 解決済)  →  asm.Instructions  →  cilium/ebpf load
   ↑                ↑                              ↑
   one-liner       parser                          codegen
                   (pkg/kunai/parser/)          (pkg/kunai/codegen/)
```

- `eth/ipv4/tcp[dport==443]` 風の **layer chain** が書ける。各 layer は vocab `.p4` ファイル (`pkg/kunai/protocols/*.p4`) で定義された protocol。
- vocab は **p4lite** = P4-16 の strict subset を Go 側で parse (`pkg/kunai/vocab/p4lite/`)。p4c で標準パースできるのが目標 (詳細は internals §5)。
- 出力は cilium/ebpf の `asm.Instructions`、target portable な eBPF subprogram。kunai コアは XDP / tc 等の host 知識を持たず、host adapter は `pkg/kunai/host/<name>/` サブパッケージに局所化 (現状 `host/xdp` のみ)。
- caller (`internal/program/program.go`) は `kunai.Compile(expr, caps)` に host capability (`xdphost.FexitCapabilities()` 等) を渡すことで host を選ぶ。zero `Capabilities` だと target-agnostic な filter (action atom 不可) が出る。

## 関連コード

- DSL 本体: `pkg/kunai/`
- Vocab: `pkg/kunai/protocols/*.p4`
- Host adapter: `pkg/kunai/host/xdp/` (XDP fentry/fexit 用、新 host を追加するときは `host/<name>/` を並べる)
- ABI 契約 (kunai ↔ host): `pkg/kunai/codegen/codegen.go` の package doc + `KunaiStackTop` constant
- 既存 fentry/fexit との接続: `internal/program/program.go::compileFilter`
- CLI 入口: `cmd/xdp-ninja/main.go` の `--dsl` 分岐
