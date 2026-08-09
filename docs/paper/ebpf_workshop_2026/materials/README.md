# eBPF'26 camera-ready の測定マテリアル

論文 (paper/) が使う測定データのうち、他に一次置き場が無いものをここに
置く。データパス性能 (Figure 5) の一次データは benchmark/results/
b4_xdp_drop_rep*.csv、生成手順は paper/figures/README.md を参照。

## verifier_insns_matrix.csv

Table 2 の「verifier」列の元データ。各フィルタのプローブを実ロードし、
bpf_prog_info.verified_insns (verifier がロード受理までに処理した命令数、
カーネル 5.16+) を記録したもの。数値はフィルタを埋め込んだ host fentry
プログラム込み。cbpfc 行は同等の pcap-filter 式が存在するフィルタのみ。
論文の verifier 列は kunai 行の 6 カーネル最大値。

- 計測日: 2026-08-01
- 計測コマンド (カーネルごと):
  `vimto -sudo -kernel :<ver> -- go test -v -count 1 ./internal/program/ -run TestBpfVerifierStats`
- テスト本体: internal/program/verifier_stats_test.go (v0.23.1 以降、
  CI の bpf_load_test マトリクスでも毎回ログに出る)
- カーネルイメージ: ghcr.io/cilium/ci-kernels

## verifier_insns_bisect.csv

6.6 → 6.12 間のコスト急増を 1 リリースに絞り込むための追加計測
(2026-08-05)。論文には使っていない。発表の Q&A・スライド素材用。

- 事実: 跳ねるのは 6.7 → 6.8 (F10 で約 50 倍)。全履歴の最大は 6.11 の
  292,820 (verifier 上限の 29%)。6.12 と 7.0 で改善しており単調悪化では
  ない。
- 仮説 (未確定): 6.8 のスカラー範囲追跡の精密化により状態の枝刈りが
  効きにくくなった。コミット単位の特定は未実施。
- 計測コマンドは matrix と同じ (kernel タグを 6.7〜6.11 に変える)。
