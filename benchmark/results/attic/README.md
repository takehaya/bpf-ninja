# attic/ — 旧ベンチ結果 / 廃止した手法のデータ

`benchmark/results/` から退避した、 論文と整合しない・もしくは廃止した実装の CSV。
削除はせず保存。

## B3 (end-to-end throughput) — ベンチごと廃止

throughput ベンチ B3 は論文から落とした (英語投稿版・日本語版とも本文に節も図も
無い)。 データ一式をここに退避。 図・スクリプトの退避先は
`docs/paper/ebpf_workshop_2026/paper/figures/README.md` の「退避済み」節を参照。

- `b3_throughput_ringbuf_v1.csv` — `bpf_ringbuf` バックエンドの run。 fig7 の入力
  だった B3 の正準データ。
- `b3_throughput_perf.csv` — `perf event array` バックエンドの run。 capture path が
  `bpf_ringbuf` 系 / fastrb に移行したため廃止した旧バックエンドのデータ。
- `b3_throughput_highload.csv` — 旧名 `b3_throughput.csv`。 高負荷 (~112 Mpps offered)
  での F1 throughput run。 他の B3 run (offered ~23 Mpps) と offered load が違うため、
  同じ表に並べると tool_pps が一桁ズレて読者を混乱させる。
