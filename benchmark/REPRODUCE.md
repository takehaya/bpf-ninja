# 再現性ガイド (eBPF Workshop 2026)

このファイルは、`benchmark/` 配下の計測データを**論文の主張と 1:1 で対応づけ**、
誰が見ても (未来の自分を含めて) 同じ数字を再生成できるようにするための索引である。
ディレクトリ構造そのものの説明は [`README.md`](README.md) を参照。

すべてのデータは `paper/ebpf-workshop-2026` ブランチにのみ存在する。`main` には入れない。

## 計測環境 (canonical)

論文に出る数字は、すべて以下の単一構成で取得した。

| 項目 | 値 |
|---|---|
| DUT host | `lab-kiba-ocxma-dut-01` (本機) |
| DUT NIC | Intel E810-C QSFP, `8a:00.0` → `enp138s0f0np0`, 100 GbE 1 link |
| DUT kernel | `6.15.0-rc6-btf-fixed+` (macro/throughput 系)。verifier matrix のみ複数 kernel (下記) |
| トラフィック生成 | T-Rex master build (= v3.08, DPDK 25.07) hardware mode、host `ocxma-trex` (`lab-kiba-ocxma-trex-01`) |
| 物理結線 | `dut1:8a:00.0 (port0) ←→ ocxma-trex:8a:00.0 (port0)` |
| capture 出力先 | tmpfs (`/dev/shm`) — disk I/O を比較から排除 |
| 既定 run 長 | `DURATION=300s`, `WARMUP=30s` (`pipelines/common.sh`) |

T-Rex の bind / 起動手順、software-mode fallback、pktgen fallback は
[`trex/README.md`](trex/README.md) に集約。ストリーム生成器は `scripts/trex/`。

### RSS 設定の注意 (B4 を読むときの前提)

B4 macrobench は **per-core service rate** を測る実験である。
default-RSS の per-filter % は flow→queue 配分の交絡を受けるため、論文の clean な
数字は `ethtool -X <iface> equal 1` (single queue) で取得した `b4_eq1_*` 系列を使う。

- `b4_eq1_*` — single queue (`equal 1`)。**論文の正準系列。**
- `b4_eq16_*` — 16 queue。RSS 交絡を示す対照。
- `b4_rsseq_*` — RSS 感度スイープ。
- F4 / F5 を取るときは `rxvlan` / `vlan-filter` を **off** にすること (これを怠ると VLAN フィルタが効かない)。

## 論文の図表 ↔ データ ↔ 再生成手順

| 論文の場所 | 主張 / 図表 | データ | 生成スクリプト | 集計 |
|---|---|---|---|---|
| §5 命令数 (`figures/fig_insns.tex`) | F1–F10 の kunai vs pcap 命令数 | `results/b1_insns.csv` | `microbench/run.sh` | tex が直接読む |
| §5 per-packet コスト | kunai vs pcap の ns/pkt (n=10)、gap は命令数比に対応 | `results/b2_runtime_rep{1..10}.csv` → `b2_runtime_stats.csv` | `microbench/run_runtime_reps.sh` | `b2_runtime_stats.csv` (mean/sd) |
| §5 line-rate (B4) | single-queue per-core service rate (n=10) | `results/b4_eq1_rep{1..10}.csv` → `b4_xdp_drop_stats.csv` | `pipelines/b4_reps.sh` (`ethtool -X equal 1`) | `analysis/b4_stats.py`, 箱ひげ `analysis/b4_boxplot.py` |
| §5 RSS 交絡の議論 | default-RSS では per-filter % が queue 配分に依存 | `results/b4_eq16_rep{1..3}.csv`, `b4_rsseq_rep{1..5}.csv` | `pipelines/b4_rss_sweep.sh`, `b4_rss_sensitivity.sh` | `analysis/b4_stats.py` |
| §3.3 / §5 SRv6 (F8) | `bpf_loop` aux-walk の line-rate cost (callback 負荷) | `results/b4_srv6_rep{1..10}.csv` | `pipelines/b4_reps.sh` (F8) | `analysis/b4_stats.py` |
| §5 verifier load (E4) | 全 filter × 複数 kernel の load 可否 | `results/verifier_matrix.csv`, `verifier_load_summary.csv` | `.github/workflows/bpf_load_test.yaml` の kernel matrix (6.1/6.6/6.12/6.18/7.0) + `internal/program/` の load テスト | summary CSV |
| §5 verifier envelope | 可変長 quantifier の命令数 regime | `results/b5_envelope.csv` | `internal/program/m2_envelope_test.go` | 直接 |
| §5 visibility | observer 有無での XDP behavior 可視性 | `results/visibility_matrix.csv` | `pipelines/visibility_matrix.sh` | `analysis/plot_visibility.py` |

## 探索系 (`r*` series) — 本文外、discussion / 設計判断の裏付け

`r5`–`r45` は capture path を R5→R8 まで詰めた**性能改善ジャーニー**と、各種感度
スイープ。多くは論文本文の図にはならず、設計上の主張 (例: raw-dump + cilium/ebpf
bypass + `NO_WAKEUP` の累積で 1.71→5.49 Mpps、capture 天井は observer の per-packet
コストであって userland writer ではない) の裏付けとして残す。各 `r##_*.csv` の生成元は
同名の `pipelines/r##_*.sh`。下の付録に全ファイルの schema と producer を機械生成で列挙。

代表的なもの:

- `r7_*`, `r8_*` — ringbuf sweep / no-wakeup / fast-reader / 1500B など capture path tuning。
- `r38_observer_overhead.csv` + `r38_pidstat.log` — observer の CPU/RSS。capture 天井の根拠。
- `r42_latency_samples.tsv`, `r42b_*` — wakeup off/on の latency CDF (大きめの raw sample)。
- `r40_xdpcap_compare.csv`, `r21_xdpdump_vs_ninja.csv` — 他ツールとの対比。

## attic (`results/attic/`, `analysis/attic/`)

論文と整合しない・廃止した手法のデータ。**削除せず保存**。経緯は
[`results/attic/README.md`](results/attic/README.md)。要点:

- `b3_throughput_*.csv` — throughput ベンチ B3 はベンチごと論文から落とした。
- `b4_xdp_drop_*_<timestamp>.csv`, `*_prebpfloop_*` — `bpf_loop` 化前 / 旧 run の
  タイムスタンプ付きアーカイブ。現行の `b4_*_rep*.csv` に置き換わった。

## フィルタ定義

- `filters/kunai/F{1..10}.kunai` — kunai DSL 構文。
- `filters/pcap/F{1..10}.txt` — 等価な pcap-filter (F1–F5 のみ pcap で表現可能、F6–F10 は kunai-only)。
- 全 filter が XDP host / tc host 両方で `kunai.Compile()` を pass する。

---

## 付録: 全結果ファイルの索引 (機械生成)

`results/` 配下の全 CSV / TSV / log を schema (ヘッダ行) と producer スクリプトつきで
列挙。`—` は親 rep スクリプトのループ内で生成される (個別 sh を持たない) ことを示す。

<!-- AUTOGEN: benchmark/results の全ファイル。再生成は本ファイル冒頭の手順 (head -1 + grep producer) -->

| file | schema (header) | producer |
|---|---|---|
| `b1_insns.csv` | `filter,path,wall_ns,insns` | run_runtime.sh |
| `b2_runtime.csv` | `filter,path,ns_per_pkt` | run_runtime.sh |
| `b2_runtime_rep10.csv` | `filter,path,ns_per_pkt` | — |
| `b2_runtime_rep1.csv` | `filter,path,ns_per_pkt` | — |
| `b2_runtime_rep2.csv` | `filter,path,ns_per_pkt` | — |
| `b2_runtime_rep3.csv` | `filter,path,ns_per_pkt` | — |
| `b2_runtime_rep4.csv` | `filter,path,ns_per_pkt` | — |
| `b2_runtime_rep5.csv` | `filter,path,ns_per_pkt` | — |
| `b2_runtime_rep6.csv` | `filter,path,ns_per_pkt` | — |
| `b2_runtime_rep7.csv` | `filter,path,ns_per_pkt` | — |
| `b2_runtime_rep8.csv` | `filter,path,ns_per_pkt` | — |
| `b2_runtime_rep9.csv` | `filter,path,ns_per_pkt` | — |
| `b2_runtime_stats.csv` | `filter,path,n,mean_ns,sd_ns` | run_runtime_reps.sh |
| `b4_eq16_rep1.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_eq16_rep2.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_eq16_rep3.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_eq1_rep10.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_eq1_rep1.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_eq1_rep2.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_eq1_rep3.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_eq1_rep4.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_eq1_rep5.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_eq1_rep6.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_eq1_rep7.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_eq1_rep8.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_eq1_rep9.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_rsseq_rep1.csv` | `cell,path,stream,dur,xdp_total,xdp_matched,xdp_mpps,nic_rx_mpps` | — |
| `b4_rsseq_rep2.csv` | `cell,path,stream,dur,xdp_total,xdp_matched,xdp_mpps,nic_rx_mpps` | — |
| `b4_rsseq_rep3.csv` | `cell,path,stream,dur,xdp_total,xdp_matched,xdp_mpps,nic_rx_mpps` | — |
| `b4_rsseq_rep4.csv` | `cell,path,stream,dur,xdp_total,xdp_matched,xdp_mpps,nic_rx_mpps` | — |
| `b4_rsseq_rep5.csv` | `cell,path,stream,dur,xdp_total,xdp_matched,xdp_mpps,nic_rx_mpps` | — |
| `b4_srv6_rep10.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_srv6_rep1.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_srv6_rep2.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_srv6_rep3.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_srv6_rep4.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_srv6_rep5.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_srv6_rep6.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_srv6_rep7.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_srv6_rep8.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_srv6_rep9.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_xdp_drop.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | b4_xdp_drop.sh |
| `b4_xdp_drop_rep10.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_xdp_drop_rep1.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_xdp_drop_rep2.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_xdp_drop_rep3.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_xdp_drop_rep4.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_xdp_drop_rep5.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_xdp_drop_rep6.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_xdp_drop_rep7.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_xdp_drop_rep8.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_xdp_drop_rep9.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp_mpps,trex` | — |
| `b4_xdp_drop_stats.csv` | `# n=10 reps from: benchmark/results/b4_xdp_drop_rep10.csv, benchmark/r` | b4_reps.sh |
| `b5_envelope.csv` | `axis,param,insns,regime` | — |
| `r10_big_buf.csv` | `buffer_mib,packet,rep,duration_s,captured,pps,rx_dropped_delta,trex_tx` | — |
| `r10_buffer_sweep.csv` | `buffer_mib,rep,duration_s,captured,pps,rx_dropped_delta,trex_tx_pps` | — |
| `r10_fair_comparison.csv` | `tool,packet,rep,duration_s,captured,pps,rx_dropped_delta,trex_tx_pps` | — |
| `r10_matrix.csv` | `mode,packet,rep,duration_s,captured,pps,rx_dropped_delta,trex_tx_pps` | r11_pktgen_64B.sh |
| `r11_pktgen_64B.csv` | `mode,packet,rep,duration_s,captured,pps,rx_dropped_delta,offered_mpps_` | r11_pktgen_64B.sh |
| `r12_visibility_round1.csv` | `cell,observer,filter,rep,duration_s,trex_tx_mpps,trex_rx_mpps,trex_opa` | r12_visibility_round1.sh |
| `r12_visibility_round2.csv` | `cell,observer,filter,match_pct,rep,duration_s,trex_tx_mpps,trex_rx_mpp` | r12_visibility_round2.sh |
| `r14_uniform_paper.csv` | `variant,packet,rep,duration_s,captured,pps,rx_dropped_delta,trex_tx_mp` | r14_uniform_paper_bench.sh |
| `r15_bench_drop.csv` | `variant,packet,rep,duration_s,captured,pps,rx_drop_delta,trex_tx_mpps` | — |
| `r16_followup.csv` | `experiment,packet,duration_s,captured,pps,rx_drop_delta,trex_tx_mpps` | — |
| `r18_verify.csv` | `cell,output_path,format,captured_pkts,pps_Mpps,file_size_MB,expected_s` | — |
| `r21_xdpdump_vs_ninja.csv` | `tool,output_format,captured_pkts,pps_Mpps,file_size_MB,bytes_per_pkt,t` | — |
| `r27_filter_cost.csv` | `label,filter,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,nic_drop_delta_M` | r27_filter_cost.sh |
| `r28_multi_cpu_scaling.csv` | `rx_queues,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,nic_drop_delta_Mpps` | r28_multi_cpu_scaling.sh |
| `r29_production_scenario.csv` | `target,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,nic_drop_delta_Mpps,tr` | r29_production_scenario.sh |
| `r30_r31_fastreader_pcapng.csv` | `label,mode,fastrb,fast_pcapng_env,storage,captured_pkts,duration_s,pps` | — |
| `r32_dynamic_scratch.csv` | `label,filter,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,nic_drop_delta_M` | r32_dynamic_scratch.sh |
| `r33_filter_capture_all.csv` | `label,filter,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,nic_drop_delta_M` | r33_filter_capture_all.sh |
| `r34_observer_prefetch.csv` | `cell,observer,prefetch,filter,rep,duration_s,trex_tx_mpps,trex_rx_mpps` | r34_observer_prefetch.sh |
| `r35_packet_size_sweep.csv` | `pkt_size,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,trex_tx_mpps,file_MB` | r35_packet_size_sweep.sh |
| `r36_filter_complexity.csv` | `depth,filter,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,trex_tx_mpps,fil` | r36_filter_complexity.sh |
| `r37_xdp_target_matrix.csv` | `target,observer,prefetch,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,trex` | r37_xdp_target_matrix.sh |
| `r38_observer_overhead.csv` | `phase,cpu_pct,rss_kb,user_cpu_pct,system_cpu_pct` | r38_observer_overhead.sh |
| `r38_pidstat.log` | `Linux 6.15.0-rc6-btf-fixed+ (lab-kiba-ocxma-dut-01) 	05/16/2026 	_x86_` | r38_observer_overhead.sh |
| `r39_default_mode.csv` | `label,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,trex_tx_mpps,file_MB` | r39_default_mode.sh |
| `r40_xdpcap_compare.csv` | `tool,output,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,trex_tx_mpps,file` | r40_xdpcap_compare.sh |
| `r42b_latency_samples.tsv` | `597` | r42b_latency_cdf_wakeup_on.sh |
| `r42_latency_samples.tsv` | `23543` | r42_latency_cdf.sh |
| `r43_tc_hook.csv` | `mode,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,trex_tx_mpps,file_MB` | r43_tc_hook.sh |
| `r44_nic_hw_ts.csv` | `label,rx_hwts,captured_pkts,pps_Mpps,nic_rx_delta_Mpps,trex_tx_mpps,la` | r44_nic_hw_ts.sh |
| `r45_sustained.csv` | `ts_sec,utime_ticks,stime_ticks,total_cpu_pct,rss_kb,threads,anomaly_co` | r45_sustained.sh |
| `r5_fanout.csv` | `rep,n_workers,trex_tx_pps,trex_opackets,observer_captured,pps` | — |
| `r5_imix.csv` | `tool,rep,duration_s,trex_tx_pps,trex_opackets,observer_captured,pps` | — |
| `r5_multi_source.csv` | `tool,rep,duration_s,trex_tx_pps,trex_opackets,observer_captured,pps` | r5_matrix.sh |
| `r5_sustained.csv` | `config,duration_s,trex_tx_pps,trex_opackets,observer_captured,pps,rss_` | — |
| `r5_xdpcap_buffer.csv` | `rep,buffer_bytes,trex_tx_pps,trex_opackets,observer_captured,pps` | — |
| `r5_xdpdump_wakeup.csv` | `rep,perf_wakeup,trex_tx_pps,trex_opackets,observer_captured,pps` | — |
| `r7_cpu_affinity.csv` | `affinity,rep,duration_s,captured,pps` | — |
| `r7_napi_busypoll_negative.csv` | `busypoll,rep,duration_s,captured,pps` | — |
| `r7_preempt_raw_dump.csv` | `preempt,rep,duration_s,captured,pps` | — |
| `r7_raw_dump.csv` | `mode,rep,duration_s,captured,pps` | — |
| `r7_ringbuf_sweep.csv` | `ringbuf_mib,rep,duration_s,captured,pps` | — |
| `r8_1500b_packet.csv` | `snaplen,rep,duration_s,captured,pps` | — |
| `r8_1500b_ringbuf_sweep.csv` | `ringbuf_mib,rep,duration_s,captured,pps` | — |
| `r8_fast_reader.csv` | `fastreader,rep,duration_s,captured,pps` | — |
| `r8_imix.csv` | `config,rep,duration_s,captured,pps` | — |
| `r8_no_wakeup.csv` | `wakeup,rep,duration_s,captured,pps` | — |
| `r8_ringbuf_sweep.csv` | `ringbuf_mib,rep,duration_s,captured,pps` | — |
| `r9_matrix.csv` | `mode,packet,rep,duration_s,captured,pps,rx_dropped_delta,trex_tx_pps` | — |
| `verifier_load_summary.csv` | `suite,host,kernels,loads_per_kernel,excluded_per_kernel,total_loads,ve` | — |
| `verifier_matrix.csv` | `filter,host,verdict,kernel` | — |
| `visibility_matrix.csv` | `behavior,observer,rep,duration_s,trex_tx_pps,trex_opackets,observer_ca` | visibility_matrix.sh |

### attic/
| file | schema | producer |
|---|---|---|
| `b3_throughput_highload.csv` | `filter,tool,size,match_pct,rep,duration_s,trex_opackets,trex` | (退避) |
| `b3_throughput_perf.csv` | `filter,tool,size,match_pct,rep,duration_s,trex_opackets,trex` | (退避) |
| `b3_throughput_ringbuf_v1.csv` | `filter,tool,size,match_pct,rep,duration_s,trex_opackets,trex` | (退避) |
| `b4_xdp_drop_rep10_20260620_215216.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep10_20260626_061434.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep10_prebpfloop_20260624_183005.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep1_20260614_010348.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep1_20260614_070327.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep1_20260616_162024.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep1_20260616_163856.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep1_20260620_215216.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep1_20260626_061434.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep1_20260626_071116.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep1_prebpfloop_20260624_183005.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep2_20260614_010348.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep2_20260614_070327.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep2_20260616_162024.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep2_20260620_215216.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep2_20260626_061434.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep2_20260626_071116.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep2_prebpfloop_20260624_183005.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep3_20260614_070327.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep3_20260616_162024.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep3_20260620_215216.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep3_20260626_061434.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep3_20260626_071116.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep3_prebpfloop_20260624_183005.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep4_20260614_070327.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep4_20260616_162024.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep4_20260620_215216.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep4_20260626_061434.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep4_prebpfloop_20260624_183005.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep5_20260614_070327.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep5_20260616_162024.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep5_20260620_215216.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep5_20260626_061434.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep5_prebpfloop_20260624_183005.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep6_20260620_215216.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep6_20260626_061434.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep6_prebpfloop_20260624_183005.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep7_20260620_215216.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep7_20260626_061434.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep7_prebpfloop_20260624_183005.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep8_20260620_215216.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep8_20260626_061434.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep8_prebpfloop_20260624_183005.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep9_20260620_215216.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep9_20260626_061434.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_rep9_prebpfloop_20260624_183005.csv` | `cell,path,stream,filter,duration_s,xdp_total,xdp_matched,xdp` | (退避) |
| `b4_xdp_drop_stats_prebpfloop_20260624_183005.csv` | `# n=10 reps from: /home/ocxma/private/xdp-ninja/benchmark/re` | (退避) |
