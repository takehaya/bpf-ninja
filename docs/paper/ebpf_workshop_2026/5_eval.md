# 5 章「評価」の測定方法とデータ所在

このドキュメントは、論文 5 章の各評価を「**何を確かめたか / どう測ったか / 生データはどこか / どう再現するか**」で平易にまとめたもの。英語版を書くときや、数値の出どころを後から辿るための覚書。

数値そのものは本文（`hand_draft_ja_reviewed.md` の 5 章）と、ここに挙げる CSV が一次情報。

---

## 0. 全体像

5 章は Kunai を 4 つの観点で評価している。観点ごとに別の測定系を使う。

| 観点 | 本文 | 何を見るか | 測定系 | 一次データ |
|---|---|---|---|---|
| 表現可能性 | 5.2 | pcap-filter で書けない filter を Kunai で書けるか | 手作業の対応比較 | `benchmark/filters/` |
| verifier 受理 | 5.3 | 生成 bytecode が 5 kernel × 2 host で load できるか | vimto/QEMU で kernel を切替えて load | `benchmark/results/verifier_matrix.csv` |
| match/reject の正しさ | 5.3 | 受理された bytecode が期待どおり通す/落とすか | `BPF_PROG_TEST_RUN` で gopacket 製パケットを流す | テストコード内（CSV なし） |
| 命令数 | 5.4 | 生成 bytecode が何命令か | compile して命令を数える | `benchmark/results/b1_insns.csv` |
| per-packet 実行時間 | 5.4 | 1 packet あたり何 ns か | `BPF_PROG_TEST_RUN` の時間計測 | `benchmark/results/b2_runtime_stats.csv` |
| datapath 実機性能 | 5.4 | line rate で処理レートがどれだけ落ちるか | TRex + 100GbE 実機 | `benchmark/results/b4_xdp_drop_stats.csv` |

評価対象の filter は F1-F10 の 10 本（基準 filter set）と、構文を広く掃く 68 本の corpus。

---

## 1. Filter set（F1-F10）と corpus

### F1-F10

- **定義**: `internal/program/filterset_test.go` の `FilterSet`。各 entry は `ID` / `Expr`（Kunai DSL）/ `WantInsns`（命令数の期待値）/ `TCUnsupported`（tc で扱えない=VLAN/QinQ 系）を持つ。
- **DSL 文字列**: `benchmark/filters/kunai/F{1..10}.kunai`
- **pcap-filter 文字列**: `benchmark/filters/pcap/F{1..10}.txt`
- **選定理由**: `docs/paper/ebpf_workshop_2026/old/filter-set.md`
  - F1-F6 = cBPF でも Kunai でも書ける基準。
  - F7-F10 = Kunai 固有（tcpdump/xdpcap/tc-flower 等で書けない）。GTP-U / SRv6 / Geneve / TCP options。
  - F6 は元 TCP SYN から ICMP echo に差し替え済（非 byte 境界の bitmask codegen 未実装のため）。

### 68-expression corpus

- **定義とテスト**: `internal/program/filterset_corpus_test.go` の `VerifierCorpus`（`TestBpfFilterCorpusXDP` / `...TC` が使う）。ID は `C01`〜 で C/D/E/F/G/H プレフィクスの計 68 本（C 46 / D 8 / E 4 / F 4 / G 3 / H 3）。
- 目的は F1-F10 より広く DSL 構文（bracket predicate、where 句の算術、量化 layer、alternation、`@label`、aux-walk、capture 句）を verifier 受理の観点で掃くこと。**受理可否だけ**を見る（命令数・実行時間は測らない）。

### 取得方法（filter set と corpus を見る）

```bash
# F1-F10 の Kunai 式（1 ファイル 1 式）
cat benchmark/filters/kunai/F*.kunai

# F1-F10 の pcap-filter 式（F7-F10 は「なぜ書けないか」のコメント付き）
cat benchmark/filters/pcap/F*.txt

# 正準定義（Kunai 式 Expr + pcap 式 CBPFCExpr + 命令数 WantInsns を 1 箇所に持つ）
grep -nE 'ID:|Expr:|CBPFCExpr:|WantInsns:' internal/program/filterset_test.go

# corpus 68 式の一覧（ID は C/D/E/F/G/H プレフィクス）
grep -oE '\{"[A-Z][0-9]+", "[^"]+"\}' internal/program/filterset_corpus_test.go

# corpus の本数を数える（= 68）
grep -cE '^[[:space:]]*\{"[A-Z][0-9]+",' internal/program/filterset_corpus_test.go
```

---

## 2. 表現可能性（5.2）

- **やり方**: F1-F10 を pcap-filter と Kunai のそれぞれで書けるかを手作業で比較。pcap 側の文字列は `benchmark/filters/pcap/`、Kunai 側は `benchmark/filters/kunai/`。
- **結果**: F1-F6 は両者で書ける。F7-F10 は pcap-filter が構文として提供しない（固定 offset 化できない／list を loop できない／inner chain を辿れない／option walk がない）。
- これは性能数値ではなく能力の有無なので、**CSV は無く**、本文の表（F7-F10 の 4 行）が成果物。

### 取得方法（pcap vs Kunai を並べて見る）

```bash
# pcap-filter と Kunai を F ごとに並べて確認
for f in $(seq 1 10); do
  printf '== F%s ==\n  pcap : %s\n  kunai: %s\n' "$f" \
    "$(grep -v '^#' benchmark/filters/pcap/F$f.txt | head -1)" \
    "$(cat benchmark/filters/kunai/F$f.kunai)"
done

# 「なぜ pcap で書けないか」の根拠（pcap ファイル冒頭のコメント）
grep -H '^#' benchmark/filters/pcap/F{7,8,9,10}.txt

# filter set 選定の背景
cat docs/paper/ebpf_workshop_2026/old/filter-set.md
```

---

## 3. verifier 受理（5.3）

「生成した同じ bytecode が、複数の kernel version と 2 つの attach point で load できるか」を見る。

### どう回すか

- **CI 本番**: `.github/workflows/bpf_load_test.yaml`。kernel matrix = **6.1 / 6.6 / 6.12 / 6.18 / 7.0** の 5 つ。各 kernel ごとに [vimto](https://github.com/lmb/vimto)（QEMU で cilium/ci-kernels の kernel image を起動）の中で `go test ./internal/program/ -run TestBpf` を実行する。
  - `TestBpfFilterSetXDP/Fn` と `TestBpfFilterSetTC/Fn` が、各 filter を XDP host / tc host の BPF program に組み込んで実際に kernel に load する。pass/fail がそのまま verdict。
  - corpus 版は `TestBpfFilterCorpus{XDP,TC}`。
  - native XDP 直接実行版は `TestBpfXDPNativeFilterSet`。
- **手元での 1 kernel 確認**: `make test-bpf`（host kernel で同じ `TestBpf*` を sudo 実行）。特定 kernel なら `vimto -kernel :6.6 exec -- go test -v -count 1 ./internal/program/ -run TestBpf`。

### データ

- **`benchmark/results/verifier_matrix.csv`** — 列は `filter,host,verdict,kernel`。CI が各 subtest の PASS/FAIL を awk で抜いて生成（workflow の "Extract verifier matrix CSV" step）。
- 補助: `benchmark/results/verifier_load_summary.csv`。

### 本文の数字との対応

- 「5 kernel × 2 host で計 740 回 load、すべて受理」= verifier_matrix.csv の pass セル数。
- 「tc で F1-F10 の 2 件と corpus の 6 件を除外」= tc は outer VLAN を skb metadata に出すため、VLAN/QinQ を byte parser として読む filter（F4, F5 とそれに相当する corpus 6 本）を compile 段階で拒否する。`filterset_test.go` の `TCUnsupported: true` がそれ。

---

## 4. match/reject の正しさ（5.3）

「受理された bytecode が、通すべき packet を通し、落とすべき packet を落とすか」を packet 単位で確認する。

- **仕組み**: `pkg/kunai/dsltest/runner.go`。生成した kunai bytecode を XDP program に組み込み、gopacket で組んだ packet bytes を **`BPF_PROG_TEST_RUN`** で 1 発流す。bytecode は match なら R0=1（→ XDP_PASS 相当）、no-match なら R0=0 を返し、それを verdict として読む。
  - ヘルパ `MustMatch(pkt, why)` / `MustReject(pkt, why)` がテストから呼ばれ、期待と違えば fail。
  - 実行には root（CAP_SYS_ADMIN）が要る。非 root では skip。
- **テスト packet の生成**: `pkg/kunai/dsltest/builders.go`（gopacket。GENEVE / SRv6 を追加済）。protocol ごとに「match する / match しない / malformed」を網羅。例: GTP-U の optional field 有無・extension・truncated frame、SRv6 の segment 数 1 と 3・target SID 有無、TCP options の MSS 有無・NOP 介在・length 0/1 の壊れ option。
- **データ**: これは「全 case で期待どおり」を assert するテストなので、**CSV は無い**。結果はテストの pass/fail。本文の「すべての test case で期待した match/reject を返した」がそれ。

---

## 5. 命令数（5.4 / b1）

「生成 bytecode が何命令か」を静的に数える。実行環境に依らない指標。

- **数え方**: `internal/program/bench_test.go::BenchmarkFilterSet` が各 filter を `kunai.Compile()` し、`countRawInsns()` で `asm.Instructions`（main + bpf_loop callback subprogram）を数える。64-bit 即値 load（`lddw`）は 2 命令として数える。cbpfc 側は同じ filter を cBPF→eBPF に compile して数える。
- **回し方**: `BENCHTIME=3s bash benchmark/microbench/run.sh`（root 不要、compile するだけ）。
- **データ**: **`benchmark/results/b1_insns.csv`** — 列は `filter,path,wall_ns,insns`。`path` は `dsl`（Kunai）か `cbpfc`。`insns` が命令数、`wall_ns` は **compile 時間**（実行時間ではない。実行時間は b2/b4）。
- **図**: `paper/figures/fig_insns.{tex,pdf}`（図4）が b1_insns.csv の insns を棒グラフ化。
- 本文の「Kunai は cbpfc の 2.7〜14.7 倍、F7-F10 は 231〜405 命令」はこの csv。命令数は決定的なので `filterset_test.go` の `WantInsns` pin と一致する（ずれたら test 失敗）。

> 注意: codegen を変えると命令数が動く。PR #42 で F8 が bpf_loop 化し 450→332 に減ったため、b1 を再測定し図4 も再ビルドした。

---

## 6. per-packet 実行時間（5.4 / b2）— ns はどう測ったか

「1 packet を処理するのに何 ns かかるか」を syscall 経由で測る。**ここが「ns の値」の出どころ。**

### 測り方

- `internal/program/bench_test.go::BenchmarkFilterSetRun` が各 filter を**本物の tracing probe として kernel に load** し、**`BPF_PROG_TEST_RUN`** で同じ packet を大量回（Go benchmark の N 回）流して総時間を測り、`総時間 / N = ns/pkt` を出す。
- `BPF_PROG_TEST_RUN` は「load 済み BPF program を、指定 packet で kernel 内で N 回回して合計所要時間を返す」ioctl。**syscall の往復と probe の入口処理（x86 で約 600 ns）が必ず乗る**。この固定費は Kunai でも cbpfc でも同じなので、
  - **F0 = accept-all baseline**（filter なしの最小 program）を別に測り、各 filter の値から baseline を引いた**増分**が「filter 自体のコスト」。
  - 同じ理由で、Kunai と cbpfc の**差**だけが codegen の signal になる（共通の 600 ns は相殺）。
- **root 必須**（`BPF_PROG_TEST_RUN` は CAP_SYS_ADMIN）。

### 回し方

- 1 回: `BENCHTIME=3s sudo bash benchmark/microbench/run_runtime.sh` → `b2_runtime.csv`（列 `filter,path,ns_per_pkt`）。
- 10 reps + 集計（本文はこれ）: 10 回回して `b2_runtime_rep{1..10}.csv` に保存し、(filter,path) ごとに平均と標準偏差を取る。集計結果が **`benchmark/results/b2_runtime_stats.csv`**（列 `filter,path,n,mean_ns,sd_ns`）。

### 本文の数字との対応

- 「baseline 611-614 ns」= b2_runtime_stats.csv の F0 行（kunai 614.2 / cbpfc 611.3）。
- 「各 filter の増分は最大 +13 ns/pkt、baseline の約 2.0%」= 各 filter の mean − F0 mean の最大（F8）。
- 「Kunai と cbpfc の差は標準偏差と同程度で分離できない」= 共通 filter（F1-F4,F6）の kunai/cbpfc 差（≤7.4 ns）が sd（最大 11.7 ns）と同オーダー。

> PR #36 後の 2026-06-13 に再測定済。

---

## 7. datapath 実機性能（5.4 / b4）— line rate での処理レート

syscall 計測ではなく、**実際の NIC に line rate の traffic を流したときの処理レート低下**を測る。

### 構成（図5）

- TRex（traffic generator、ホスト `ocxma-trex`）と DUT を **100 GbE で直結**。
- DUT = Intel Xeon Platinum 8362 / Intel E810 NIC / Linux 6.15 / BPF JIT 有効。
- DUT で動かす program = **`benchmark/xdpdrop/main.go`**: packet 先頭を per-CPU scratch window に copy → filter を評価 → **全 packet を XDP_DROP**。これは運用時の fentry/tc observer と同じ window-copy 方式（native 直接実行は PR #33 で verifier-safe 化済だが、観測経路を再現するため copy 方式で測る）。

### 測り方

- TRex から各 stream を `DURATION` 秒流し、DUT が drop できた pps（`xdp_mpps`）を読む。stream 定義は `scripts/trex/trex_b4_streams.py`（DUT 側 `/opt/trex/v3.08/scripts/` に配備）。
- セルの種類: `floor`（copy も filter も無し）、stream 種別ごとの `accept_<stream>`（copy のみ、filter なし）、各 filter セル。
- **filter cost = accept_<stream>.xdp_mpps − filter セル.xdp_mpps**（飽和状態、offered > XDP 処理能力で評価）。同一 stream 内の差なので、stream 自体の絶対レート差（例: SRv6 は RSS が効かず低い）の影響を受けない。
- window copy 自体の固定費 = floor と accept の差。

### 回し方

- `REPS=5 DURATION=30 bash benchmark/pipelines/b4_reps.sh` が `b4_xdp_drop.sh` を 5 回回し `b4_xdp_drop_rep{1..5}.csv` を作る（前の rep は `results/attic/` に退避）。
- 集計: `python3 benchmark/analysis/b4_stats.py benchmark/results/b4_xdp_drop_rep*.csv` → **`benchmark/results/b4_xdp_drop_stats.csv`**（列 `metric,n,mean,sd`）。

### 本文の数字との対応（b4_xdp_drop_stats.csv）

- window copy 固定費 約 7.7%: `fixed%:window_copy_udp64` = −7.70 ± 0.16
- F7-F10 は accept-all 比 3.9〜7.3% 低下、最大 F8 7.3%:
  - `cost%:kunai_F7_vs_accept_gtpu` = −6.04 ± 0.25
  - `cost%:kunai_F8_vs_accept_srv6` = −7.25 ± 0.26
  - `cost%:kunai_F9_vs_accept_geneve` = −4.89 ± 0.24
  - `cost%:kunai_F10_vs_accept_tcpmss` = −3.91 ± 0.15
- 共通 filter F1 の Kunai vs cbpfc 差 0.6%: `gap%:kunai_F1_vs_cbpfc_F1` = −0.59 ± 0.14
- 生 mpps（floor 115.91、accept_udp64 106.98 など）も同 csv の `mpps:*` 行にある。

> n=10 は 2026-06-26 の full re-measure（cbpfc_F2/F3/F4/F6 を datapath にも追加、同一セッション）。旧 rep は `results/attic/` に退避。

---

## 8. 数値 → ファイル 早見表

| 本文の記述 | 出どころ |
|---|---|
| F1-F10 の命令数（199…405） | `benchmark/results/b1_insns.csv` / `filterset_test.go` の `WantInsns` |
| Kunai は cbpfc の 2.7〜14.7 倍 | `b1_insns.csv`（dsl/cbpfc 比） |
| 5 kernel × 2 host で 740 受理、tc で 8 除外 | `benchmark/results/verifier_matrix.csv` |
| match/reject すべて期待どおり | `pkg/kunai/dsltest/` のテスト pass/fail（CSV なし） |
| baseline 611-614 ns、最大増分 +13 ns/pkt | `benchmark/results/b2_runtime_stats.csv` |
| line rate で F7-F10 が 3.9〜7.3%（最大 F8 7.3%）、F1-F4 差 0.6〜1.3pp、copy 7.7% | `benchmark/results/b4_xdp_drop_stats.csv` |
| 図4（命令数） | `paper/figures/fig_insns.{tex,pdf}` ← b1 |
| 図5（測定 topology） | `paper/figures/fig_topology.{tex,pdf}` |

---

## 9. 再現コマンドまとめ

```bash
# 命令数 (b1, root 不要)
BENCHTIME=3s bash benchmark/microbench/run.sh
#   -> benchmark/results/b1_insns.csv

# per-packet ns (b2, root 必要, 10 reps + 集計は run_b2 ループで)
BENCHTIME=3s sudo bash benchmark/microbench/run_runtime.sh   # 1 rep
#   -> benchmark/results/b2_runtime.csv
#   10 reps -> b2_runtime_rep{1..10}.csv -> 集計 b2_runtime_stats.csv

# verifier 受理 (1 kernel, host)
make test-bpf
#   特定 kernel: vimto -kernel :6.6 exec -- go test -v -count 1 ./internal/program/ -run TestBpf
#   全 5 kernel: GitHub Actions bpf_load_test.yaml -> verifier_matrix.csv

# datapath 実機 (b4, TRex 稼働 + DUT iface up + passwordless sudo が前提)
REPS=5 DURATION=30 bash benchmark/pipelines/b4_reps.sh
python3 benchmark/analysis/b4_stats.py benchmark/results/b4_xdp_drop_rep*.csv
#   -> benchmark/results/b4_xdp_drop_stats.csv
```
