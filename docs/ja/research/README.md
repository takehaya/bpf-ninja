# 研究資料と実験の根拠

この索引は既存の公開資料を分類します。
索引作成時に確認したソースは `43752fa9c40016e580edb4b9d2c654d7baeabf43` です。
実験をこの版で再測定したわけではありません。
未公開草稿、内部メモ、raw research data の新規公開は含めません。
[公開境界の方針](../../../CONTRIBUTING.md)に従います。

## 資料の種類と適用範囲

| 資料 | 種類と状態 | 対象と限界 | 根拠と再現方法 |
|---|---|---|---|
| [DSL benchmark](../dsl-benchmark.md) | 比較方法論 | compiler cost、生成命令、runtime を区別。文中の出力例を最新の性能値として引用しない | 記載の benchmark/test command。kernel load と packet 実行は別途必要 |
| [高負荷 attach 調査](../attach-under-load-rcu-finding.md) | 過去の観測と原因分析 | kernel 6.15.0-rc6 custom、64 論理 CPU、E810、cpumap 負荷。流量の閾値を他環境へ一般化しない | 本文の stack、条件、修正説明。正確な実験 commit と公開 raw data の対応は本文だけでは確定できない |
| [ADR-0001](../adr/0001-fast-reader-zero-copy-flush.md) | 却下した案の記録 | reader のコピーと ownership の判断 | 本文の測定と判断。現行実装への適用は code と照合 |
| [ADR-0002](../adr/0002-split-core-capture-optimal-width.md) | 条件付き測定に基づく採用判断 | 64 論理 CPU、E810、128B、3〜4 Mpps offered、約11〜12秒窓 | 本文の N sweep。正確な実験 commit/反復数/分散は記録を追加するまで未確定 |
| [ADR-0003](../adr/0003-mask-bpf-loop-cursor.md) | verifier 対策の採用判断 | kernel ごとの load cost と安全性修正の影響 | 本文の kernel commit、比較、回帰試験 |
| [Tuning](../tuning.md) | 運用の測定手順と過去の参考値 | 現在の環境で baseline を取り、条件を固定して比較する | 測定条件が不足する数値を推奨値として扱わない |
| [Lean 形式仕様](../../../spec/lean/README.md) | 実行可能な意味論モデル | DSL と parser machine の範囲。codegen 全体の形式証明ではない | pinned toolchain、vectors、[D-NNN](../../../spec/lean/DECISIONS.md) |
| [eBPF Workshop artifact](../../publications/ebpf_workshop_2026/README.md) | 固定版の公開 artifact | compiler `v0.23.1`。main の性能説明と混ぜない | [保存データ](../../publications/ebpf_workshop_2026/data/README.md)、[図の対応](../../publications/ebpf_workshop_2026/paper/figures/README.md) |

## 公開 artifact の読み方

Workshop のデータガイドには Linux 6.15、Xeon 8362、E810、100 GbE、native XDP_DROP の条件と、verifier 比較の複数 kernel が記載されています。
datapath の集計では母標準偏差（population SD）、runtime summary では標本標準偏差（sample SD）を使っています。
比較するときは、それぞれの標準偏差の定義を確認してください。
論文では F5 が ICMP、F6 が QinQ、compiler の `v0.23.1` tests は逆です。
比較時は番号だけでなく式を照合します。

artifact 内の `make data` は保存された CSV の再集計です。
traffic の送信、BPF load、実験自体の再実行ではありません。
論文、CSV、図の source mapping、版は元の場所に保持します。
公開状態は artifact README に従い、文書整理だけを理由に変更しません。

## 新しい測定を追加するとき

1. 検証する主張と、まだ検証していない範囲を書く。
2. compiler の tag/commit、kernel、hook、hardware、driver、traffic を記録する。
3. baseline、反復数、時間窓、単位、集計と分散の定義、capture/export の有無を残す。
4. 公開可能なデータ、実行 script、結果、PR/commit を相互参照する。
5. 再計算できる範囲と、実機を必要とする範囲を分ける。
6. 現行実装でも適用できるか、未再検証か、別の結果に置換されたかを示す。

不足する条件は「未記録」「未確認」と明記し、数値を推定して埋めません。
仮説と測定結果を区別して記録し、過去の結果を新しい値で上書きしません。
仕様や操作上の制約は利用ガイドへ、実装の理由は [Architecture](../architecture/README.md) と ADR へ接続します。
