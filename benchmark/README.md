# Benchmark Harness

eBPF Workshop'26 投稿の評価 (E1-E5) で使うベンチマークの working tree。
詳細戦略は `../docs/paper/ebpf_workshop_2026/old/EVALUATION_STRATEGY.md` を参照。

**計測データと論文の主張の対応 (再生成手順つき) は [`REPRODUCE.md`](REPRODUCE.md) を参照。**

## ディレクトリ構造

```
benchmark/
├── filters/
│   ├── kunai/F{1..10}.kunai     # kunai DSL 構文 (確定済、2026-05-06)
│   └── pcap/F{1..10}.txt        # pcap-filter (tcpdump/xdpcap/pwru 用)
├── pcap_gen/                    # gopacket でのテストパケット生成 (Go)
├── pcaps/                       # 生成された .pcap ファイル
├── pipelines/                   # 各ツールの bench runner (bash)
│   ├── tcpdump_run.sh
│   ├── xdpcap_run.sh
│   ├── xdpdump_run.sh
│   ├── xdp-ninja_run.sh
│   └── kunai-tc_run.sh
├── trex/                        # T-Rex profile YAML (E3 用)
│   ├── profile_64B.yaml
│   ├── profile_256B.yaml
│   └── profile_1500B.yaml
├── microbench/                  # E2: 命令数 + verifier load time
│   └── run.sh                   # internal/program/bench_test.go を呼ぶ薄い wrapper
├── mesobench/                   # 補遺 C: per-packet cycle (BPF_PROG_TEST_RUN)
├── results/                     # CSV
│   ├── b1_insns.csv
│   ├── verifier_matrix.csv
│   └── b3_throughput.csv
└── analysis/                    # plot 系 (Python)
```

## Filter Set (F1-F10) 確定状況

詳細は `../docs/paper/ebpf_workshop_2026/old/filter-set.md`。要点:

- F1-F6: baseline (cBPF でも書ける、kunai でも書ける)
- F7-F10: kunai-only data point (tcpdump/xdpcap/tc-flower/nftables/pwru で書けない)
- 全 10 filter が `kunai.Compile()` で XDP host / tc host 両方の compile pass (2026-05-06 検証済)
- F6 は元 TCP SYN-only から **ICMP echo request** に差し替え (TCP flags non-byte-aligned codegen 未実装のため)

## 評価のスケジュール

| 週 | E | やること |
|---|---|---|
| Week 2 | E1 准備 | filter set 確定、pcap-filter 構文検証、Table 4 母集団 |
| Week 3 | E2 + E4 | microbench (insns / verifier load time) を 80 cell で取得 |
| Week 4 | E3 准備 | T-Rex setup、bench harness、(任意) E4 fuzzing |
| Week 5 | E3 本番 | 100 GbE で macrobench、Figure 7 |

## 既存資産との関係

新規実装ではなく、リポジトリ既存資産を活用:

- `internal/program/bench_test.go::countRawInsns()` → microbench/ から呼び出す
- `pkg/kunai/dsltest/runner.go` の BPF_PROG_TEST_RUN ハーネス → mesobench/ で再利用
- `pkg/kunai/dsltest/builders.go` の gopacket builder → pcap_gen/ で extend (GENEVE / SRv6 を追加、Week 2 T6)
- `scripts/test/run_tests.sh` の veth + XDP + tc 環境 → tc 経由の E5 で再利用
- `.github/workflows/bpf_load_test.yaml` の 4 kernel matrix → E4 verifier matrix そのまま使う
