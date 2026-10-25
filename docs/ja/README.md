# bpf-ninja ドキュメント

bpf-ninja を使うときは、導入、目的に合う手順、式の詳細の順に参照してください。
この索引は同じ checkout の実装を対象とします。
過去の設計判断と公開論文は、それぞれに記された版と条件で読んでください。

## 導入と操作

| 目的 | 読む資料 |
|---|---|
| 必要条件を確認して導入する | [Getting started](getting-started.md) |
| ロードせずフィルタを確認する | [Examples](examples/README.md) |
| mode、出力、set の操作を調べる | [利用ガイド](dsl-usage.md) |
| command と flag の現在の定義を見る | `./bpf-ninja --help`、`./bpf-ninja set --help`、各 subcommand の `--help` |
| フィルタを書く | [DSL 索引](dsl-overview.md)、[文法](dsl-grammar.md)、[型と意味](dsl-types.md) |
| 終了とファイルの完成を判断する | [Capture lifecycle](../capture-lifecycle.md)（英語） |
| 環境を用意して動作確認する | [手動試験](handtest.md)、[privileged tests](../privileged-tests.md)（英語） |
| 性能を測って調整する | [Tuning](tuning.md) |

## 実装と設計判断

- [Capture datapath](capture-datapath.md)：カーネルから出力までの実装。
- [DSL internals](dsl-internals.md)：compiler と host ABI。
- [Vocab 作成](dsl-vocab-authoring.md)：protocol を追加する手順。
- [kunai API](../../pkg/kunai/README.ja.md)：Go ライブラリとして使う場合。
- [ADR](adr/)：採用、却下、置換を含む設計判断の履歴。
- [Lean 仕様](../../spec/lean/README.md)と[意味論の決定記録](../../spec/lean/DECISIONS.md)：実装の説明と区別して読む形式モデル。

## 研究と公開成果

- [DSL benchmark](dsl-benchmark.md)：比較方法と測定対象。
- [attach under load の調査](attach-under-load-rcu-finding.md)：特定条件での観測と仮説。
- [eBPF Workshop 2026 artifact](../publications/ebpf_workshop_2026/README.md)：固定版の論文資料。
- [保存データと再計算](../publications/ebpf_workshop_2026/data/README.md)：測定条件、集計方法、データの出典。

測定結果を現在の環境に適用するときは、実装版、kernel、hardware、負荷、capture/export の条件を確認してください。
仕様上の対応、コンパイル成功、kernel load 成功、実パケットの取得は別の検証です。

[全言語の入口](../README.md)
