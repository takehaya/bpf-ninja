# bpf-ninja ドキュメント

bpf-ninja を使うときは、導入、目的に合う手順、式の詳細の順に参照してください。
この索引は、手元でチェックアウトした版の実装を対象とします。
過去の設計判断と公開論文は、それぞれに記された版と条件で読んでください。

## 導入と操作

| 目的 | 読む資料 |
|---|---|
| 必要条件を確認して導入する | [Getting started](getting-started.md) |
| ロードせずフィルタを確認する | [Examples](examples/README.md) |
| mode、出力、set の操作を調べる | [capture](cli/capture.md)、[output](cli/output.md)、[sets](cli/sets.md) |
| command、flag、protocol の現在の定義を見る | [CLI reference](cli/README.md) |
| map 操作を列挙し、ロード時に観測 hook を追加する | [inject-run](../en/inject-run.md)、[--list-progs --list-maps から始める手順](../en/inject-walkthrough.md)（英語、実験的機能） |
| BTF のない map の hook 引数に型を補う | [Loader の ELF から map の型を補う](inject-map-types.md) |
| inject hook で集計、CPU ID、経過時間を観測する | [observer examples](../en/inject-observers.md)（英語） |
| フィルタを書く | [DSL 索引](dsl-overview.md)、[文法](dsl-grammar.md)、[型と意味](dsl-types.md) |
| 終了とファイルの完成を判断する | [Capture lifecycle](../capture-lifecycle.md)（英語） |
| 環境を用意して動作確認する | [手動試験](handtest.md)、[privileged tests](../privileged-tests.md)（英語） |
| 性能を測って調整する | [Tuning](tuning.md) |
| 起動、0件、未完成の出力を切り分ける | [Troubleshooting](troubleshooting.md) |

## 実装と設計判断

[実装を読むための案内](architecture/README.md)から、処理の順序とコードの責務を辿れます。

- [Capture datapath](capture-datapath.md)：カーネルから出力までの実装。
- [hook 実行相関の準備部品](run-correlation.md)：capture からまだ使っていない実行対応の部品を説明する。
- [DSL internals](dsl-internals.md)：compiler と host ABI。
- [Map 操作の injection](../en/lookup-site-injection.md)と[u32 load site の typed injection](../en/typed-injection.md)：変換 API、hook ABI、呼び出し側の監査条件（英語）。
- [BPF syscall hook の設計](../en/bpf-syscall-hook-design.md)：`inject-run` の構成と実装状況（英語）。
- [Vocab 作成](dsl-vocab-authoring.md)：protocol を追加する手順。
- [kunai API](../../pkg/kunai/README.ja.md)：Go ライブラリとして使う場合。
- [ADR](adr/)：採用、却下、置換を含む設計判断の履歴。
- [Lean 仕様](../../spec/lean/README.md)と[意味論の決定記録](../../spec/lean/DECISIONS.md)：実装の説明と区別して読む形式モデル。

## 研究と公開成果

[Research 索引](research/README.md)で資料の種類、対象版、根拠、再現範囲を確認できます。

- [DSL benchmark](dsl-benchmark.md)：比較方法と測定対象。
- [attach under load の調査](attach-under-load-rcu-finding.md)：特定条件での観測と仮説。
- [eBPF Workshop 2026 artifact](../publications/ebpf_workshop_2026/README.md)：固定版の論文資料。
- [保存データと再計算](../publications/ebpf_workshop_2026/data/README.md)：測定条件、集計方法、データの出典。

測定結果を現在の環境に適用するときは、実装版、kernel、hardware、負荷、capture/export の条件を確認してください。
仕様上の対応範囲、コンパイルの成否、カーネルへのロードの成否、実パケットの取得結果は、それぞれ分けて確認してください。

[全言語の入口](../README.md)
