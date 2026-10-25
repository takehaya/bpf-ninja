# bpf-ninja 性能チューニングガイド

対象は現在の checkout の操作と、既存文書に残る条件付きの測定です。
新しい測定結果は追加していません。
まず実際の損失と律速箇所を測り、変更前後で同じ負荷と出力条件を使ってください。
flag と既定値は `bpf-ninja --help`、履歴と根拠は [研究資料索引](research/README.md)を参照します。

## 1. 性能の上限を理解する

capture の律速候補には packet の読取り、filter、ringbuf、reader、整形、storage、観測対象自身があります。
以前の高 pps 調査では cold read と memory latency が支配的と解釈されましたが、全 hardware と workload に共通する結論ではありません。
cache、メモリ帯域、CPU 配分、転送処理を別々に確認し、測定していない環境の限界を断定しないでください。

## 2. 現状を測定する

commit、kernel、CPU topology、NIC/driver、hook、式、snaplen、offered rate、実行時間、出力先を記録します。
同じ条件で複数回測り、平均とばらつきを残してください。

- `--null-output` と `-w` を比較すると、保存処理の寄与を調べられます。出力を捨てても filter と reader の処理は残ります。
- NIC receive、対象 program の処理数、filter 一致数、終了 summary、ring loss、出力件数を区別します。
- captured が XDP 到達数より少ないだけでは ring overflow と断定できません。filter、停止時点、hold loss 等も確認します。
- `complete` と損失指標の関係は [capture lifecycle](../capture-lifecycle.md)に従います。

## 3. 効果の大きい順に設定を変える

この見出しは旧リンクを保持しています。実際の優先順位は測定した律速箇所で決めます。
一度に一つの条件を変え、必要な packet bytes と待ち時間を満たす範囲で比較します。

### 3.1 snaplen を下げる

`--snaplen N` または DSL の capture 句で保存長を指定します。
packet の読取り量と ring の占有量を減らせますが、後段で必要な header/payload を切り落とさないよう、pcap を確認します。
`--snaplen 0` は強制長を無効にする指定です。

### 3.2 --fast-reader を常用する

見出しは旧リンクを維持するために残していますが、`--fast-reader` の常用は測定結果に基づいて判断してください。
`--fast-reader` は mmap と atomic を使う reader です。
既定 reader と同じ負荷で比較し、CPU 使用量、損失、latency を確認して採否を決めます。

### 3.3 --ringbuf-size を増やす

`--ringbuf-size` は全体の MiB 容量で、shard 間で分割します。
burst を吸収できても、継続的に consumer が遅い状態は解決しません。
メモリ制約と、停止時に drain する量も確認します。

### 3.4 --raw-dump で出力経路を軽くする

`--raw-dump` は整形を後段の `convert` に回します。
`--in-memory-buffer` は raw-dump の per-shard mmap buffer です。
総メモリ消費と Close 時の書込みを含めて比較してください。
reader や target が律速なら、形式を変えても効果が小さいことがあります。

### 3.5 --no-wakeup を有効にする

`--no-wakeup` は `--fast-reader` が必要です。
wakeup を減らす代わりに、到着から読取りまでの latency が変わるため、throughput だけで判断しません。

過去の本文には、p50 が約 100 µs から 2.6 ms に変わったという記録があります。
cgroup-skb/loopback の約 0.2 Mpps の負荷では、observer cost が約 3.3 µs から 123 ns に変わったと記録されています。
正確な commit、反復数、公開データへの対応が不足しているため、これらは当時の参考値として保持し、現在の改善率や保証値には使いません。
再検証する場合は同じ hook、traffic、計数方法を記録します。

### 3.6 split-core でコアを分離する

`--rx-cores N` は全 shard の reader を許可された CPU ID のうち N 以上へ配置します。
RX の affinity は別に設定し、queue 数だけで CPU 配置が決まると考えないでください。
`--busy-poll` は CPU を消費するため、target の処理能力と idle の余裕を同時に測ります。
NIC queue や IRQ の変更は運用に影響するため、別の作業として扱います。
専用検証環境で現在の設定と復旧方法を記録してから行ってください。

| 既存の記録 | 条件と扱い |
|---|---|
| 旧 tuning 本文の「64 coreなら32+32」、出力約30%向上 | workload と実験 commit の対応が不足。一般的な最適値としては採用しない |
| [ADR-0002](adr/0002-split-core-capture-optimal-width.md)の16+16、約19%向上 | 64論理CPU、E810、128B、cpumap、offered 3〜4 Mpps、約11〜12秒窓。N=8/16/24/32を比較した記録 |

32+32 と 16+16 は別の測定記録として参照してください。
ADR 当時の reader 配置と現在の「全 shard を指定範囲へ配置する」実装も照合し、環境を揃えるまでは最適 N を引き継がないでください。
target が総流量を処理できる範囲で配分を振り、capture と転送の両方を評価します。

## 4. 効果がなかった対策を避ける

過去には packet prefetch、CPUMAP による分離、wakeup の間引き、writev を試して改善しなかった記録があります。
これらは当時の飽和条件に対する結果です。
[ADR-0001](adr/0001-fast-reader-zero-copy-flush.md)のコピーと ownership の判断も参照し、測定条件を確認せず同じ案を再実装したり、全環境で無効と結論づけたりしません。

## 5. ワークロードごとに使い分ける

- standalone xdp は既定で `XDP_PASS` です。`--bench-drop` を明示した場合だけ drop するため、専用のベンチ環境で使います。
- XDP_TX、XDP_PASS、redirect では target と後段処理のコストが異なります。同じ throughput として比較しません。
- entry/exit は target を変更せず観測しますが、観測コストは発生します。観測なしの baseline と比較してください。

## 6. ハードウェアを選ぶ

cache 容量、メモリ特性、CPU topology、NIC queue/affinity の制御性は比較する項目です。
「DDR5は効かない」「大きいL3なら必ず改善する」といった一般化は、この資料の測定だけではできません。
購入や構成変更の判断には、対象 workload の再現測定を使ってください。
