# DSL ベンチ方法論

xdp-ninja の DSL (`--dsl`) と既定の cbpfc (tcpdump 構文) を比べたい人向け。本ドキュメントは **再現手順** を残すのが目的で、特定環境の数値を載せることはしない (環境依存性が高すぎるため)。

## 何を測るか

3 つの軸を分けて測る。混ぜて測ると原因が切り分けにくくなる。

| 軸 | 何が出る | 用途 |
|---|---|---|
| **コンパイル時間** | `kunai.Compile` / cbpfc が 1 フィルタ式を eBPF 命令に変換するまでの μs | 起動レイテンシ。ホットパスではない |
| **生成命令数** | フィルタの emit 命令数 (内訳: main + bpf2bpf callbacks) | verifier 通過時間と pcap 取得開始までのウォーミング |
| **per-packet PPS** | フィルタが kernel で動くときのパケット/秒スループット | 真のホットパス。**これが本命** |

A 軸 + B 軸は go test -bench で取れる (`internal/program/bench_test.go`)。C 軸は kernel + ネットワーク負荷生成器が必要なので別建て。

## A/B 軸: Go ベンチ

```bash
go test -bench=BenchmarkCompile -benchmem -benchtime=1s ./internal/program/...
```

出力例 (Xeon 8362, Linux 6.x、参考値):

```
BenchmarkCompile/cbpfc/ICMP-64         17140   13939 ns/op   14.00 insns/op
BenchmarkCompile/dsl/ICMP-64           62308    3679 ns/op   27.00 insns/op
BenchmarkCompile/cbpfc/TCP_443-64       4726   48349 ns/op   60.00 insns/op
BenchmarkCompile/dsl/TCP_443-64        49881    4615 ns/op   32.00 insns/op
```

`b.ReportMetric` で命令数を `insns/op` で報告するので、`go test -bench` の 1 行に **時間と emit サイズが両方** 載る。

傾向:
- **コンパイル時間は DSL のほうが速い**。cbpfc は cBPF → eBPF の純粋トランスパイラで libpcap 経由のパース → cBPF byte-code → eBPF 命令変換と段が多く、起動コストが見えてくる。DSL は AST → IR → codegen の 3 段だが各段が軽量。
- **生成命令数は式によって逆転する**。簡単な `icmp` (= L2 + L3 のみフィルタ) は cbpfc が短い。`tcp port 443` のように L2/L3/L4 の bounds と dispatch を全部展開する式では cbpfc 側のほうが冗長になる傾向 (cBPF の絶対オフセットアクセスを 1:1 で eBPF に展開するため)。
- **これらは kernel ホットパスではない数値**。フィルタは load 時に 1 度しかコンパイルされないので μs オーダーの差は実利用に影響しない。本命は C 軸 (per-packet PPS)。

cbpfc が読めない式 (MPLS+, VXLAN inner, etc.) は DSL でしか測れない。逆に DSL が読めない式 (tcpdump の `dst host net 10.0.0.0/24`) は cbpfc でしか測れない。**「同じフィルタを両方で書ける」ケースだけ A/B 比較に意味がある**。

代表的に揃えて比較できるペア:

| 意図 | tcpdump (cbpfc) | DSL |
|---|---|---|
| ICMP | `icmp` | `eth/ipv4/icmp` |
| TCP/443 | `tcp port 443` | `eth/ipv4/tcp[dport==443]` |
| ホスト | `host 10.0.0.1` | (DSL は IP リテラル未対応 — 比較不可) |
| TCP and host | `tcp and host 10.0.0.1` | (同上) |

## C 軸: kernel PPS

ここからが本命。手順:

### 1. 受け側ホスト (capture)

```bash
sudo ip netns add testns
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns testns
sudo ip addr add 10.0.0.1/24 dev veth0
sudo ip netns exec testns ip addr add 10.0.0.2/24 dev veth1
sudo ip link set veth0 up
sudo ip netns exec testns ip link set veth1 up
sudo ip netns exec testns ip link set lo up

# Dummy XDP_PASS attachment
sudo ip link set dev veth0 xdp obj scripts/test/xdp_pass.o sec xdp
```

### 2. 送り側 (pktgen / iperf3 / トラフィック生成)

```bash
# pktgen (kernel module、より低レベル)
sudo modprobe pktgen
# /proc/net/pktgen/* で送信プロファイルを書く (省略 — manpage 参照)

# 簡易 (iperf3 を netns 内で動かす)
sudo ip netns exec testns iperf3 -s &
sudo iperf3 -c 10.0.0.2 -t 30 -P 4
```

### 3. xdp-ninja を走らせて pps を測定

3 パターンを同条件で比較:

```bash
# (A) Filter 無し (= XDP_PASS のみ)
sudo perf stat -e cycles,instructions,cache-misses,task-clock -- \
  timeout 30 xdp-ninja -i veth0 -c 0 > /dev/null

# (B) cbpfc filter 経由
sudo perf stat -e cycles,instructions,cache-misses,task-clock -- \
  timeout 30 xdp-ninja -i veth0 -c 0 "tcp port 443" > /dev/null

# (C) DSL filter 経由
sudo perf stat -e cycles,instructions,cache-misses,task-clock -- \
  timeout 30 xdp-ninja --dsl -i veth0 -c 0 "eth/ipv4/tcp[dport==443]" > /dev/null
```

`xdp-ninja` の stderr に `N packets captured` が出る。30s 走らせて N/30 で実効 pps。`perf stat` の `cycles` / `instructions` は kernel-side オーバーヘッドの目安。

### 4. 解釈

期待される傾向:

| パターン | 想定 pps (相対) | コメント |
|---|---|---|
| Filter 無し (A) | 100% | ベースライン (XDP_PASS + xdp_output コピー) |
| cbpfc (B) | 95-99% | フィルタ評価は線形、十数命令 |
| DSL (C, 単純チェーン) | 90-98% | layer 毎の bounds + dispatch があるので命令数は cbpfc より多いが、verifier が同等の最適化を入れる |
| DSL (C, bpf_loop chain) | 70-90% | bpf_loop callback 1 回あたり ~15 命令 + helper 呼出オーバーヘッド。MPLS 4 段なら ~80 命令分のオーバーヘッド |

**重要**: ベースラインに対する相対値を見る。絶対 pps は CPU / NIC / kernel バージョン / XDP target の最適化レベルで簡単に倍違う。

### 5. fexit の相対オーバーヘッド

`--mode exit` を加えると trampoline で XDP の戻り値も観測する。fentry より僅かに重いが filter 自体の比較性質は変わらない。

```bash
sudo xdp-ninja --dsl -i veth0 --mode exit -c 0 \
  "eth/ipv4/tcp where action == XDP_DROP" > /dev/null
```

## 既知の DSL コスト要因

C 軸で DSL が cbpfc より重く見える典型ケース:

1. **Capture `headers+N`**: 既定の libpcap snaplen (1500) より小さい場合、`bpf_xdp_output` のコピー量を抑えられる **メリット側**。逆は無い。
2. **Layered chain (`mpls+`, `vlan*`)**: bpf_loop helper の呼び出しが 1 回追加される (callback per iter は line-rate ベンチでは効きにくいがイテレーション数 × callback 命令数で線形に効く)。
3. **`where` 算術**: `ipv4.total_length > 100` のような算術比較は LDX + BSwap + 比較で済むので cbpfc とほぼ同等。
4. **alternation `(a|b)`**: 各 alt の dispatch を順に試すので、1 alt あたり線形コスト。`(a|b|c|d)` で worst case 4 倍だが、altCountCap=4 なので有界。

## ベンチで陥りがちな罠

- **uname r が違う環境を混ぜない**: bpf_loop は 5.17+。それより古いと DSL の chain は load 自体が失敗する。
- **scratch buffer のサイズ (256 byte) を超える** パケットでは filter は丸読みしない。capture 量とフィルタ評価範囲が分離されている事実を忘れない。
- **veth 環境は GRO/GSO の影響を受けやすい**。`ethtool -K vethX gso off tso off gro off` で揃える。
- **負荷源 (pktgen/iperf3) の上限が NIC でなく CPU** になっていないか `mpstat` で確認。
- **同じ pcap ファイルへの書き込み** で IO が律速していないか確認 (`-w /dev/null` に向けるか `-c 100` などで頭切る)。

## 公開用にまとめるとき

`docs/ja/` 配下に **数値付き** のレポートを書きたいときは:

- 環境 (kernel uname -r、CPU、NIC、xdp-ninja コミット) を冒頭に固定
- 同じハードで cbpfc/DSL/baseline を順番ではなく **インターリーブ** で測定 (温度ドリフト緩和)
- 標準偏差 / 95% CI を出す。1 回計測の数値は当てにならない
- フィルタ式は **同義のものだけ** 並べる (DSL でしか書けないやつは別表)

数値は環境特化なので、本ドキュメントには手順だけ残し、実測レポートは別ファイル (`docs/ja/benchmarks/<date>-<hwtag>.md`) に分けると保守しやすい。

## 参考

- [dsl-usage.md](./dsl-usage.md) — フィルタの書き方
- [`pkg/kunai/protocols/`](../../pkg/kunai/protocols/) — vocab 拡張は既存 .p4 ファイルを参考に
- `internal/program/bench_test.go` — Go ベンチ実装
- `scripts/test/setup.sh` — veth 環境セットアップの参考
