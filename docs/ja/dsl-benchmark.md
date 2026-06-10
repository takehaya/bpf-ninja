# DSL ベンチ方法論

xdp-ninja の DSL (default) と legacy cbpfc (`--cbpf`、tcpdump 構文) を比べたい人向けです。本ドキュメントは再現手順を残すのが目的で、環境依存性が高すぎるため特定環境の数値は載せません。

## 何を測るか

3 つの軸を分けて測ります。混ぜて測ると原因が切り分けにくくなります。

| 軸 | 何が出る | 用途 |
|---|---|---|
| コンパイル時間 | `kunai.Compile` / cbpfc が 1 フィルタ式を eBPF 命令に変換するまでの μs | 起動レイテンシ (ホットパスではない) |
| 生成命令数 | フィルタの emit 命令数 (内訳: main + bpf2bpf callbacks) | verifier 通過時間と pcap 取得開始までのウォーミング |
| per-packet PPS | フィルタが kernel で動くときのパケット/秒スループット | 真のホットパスであり、これが本命 |

A 軸 + B 軸は go test -bench (`internal/program/bench_test.go`) で取れます。C 軸は kernel + ネットワーク負荷生成器が必要なので別建てです。

## A/B 軸 (Go ベンチ)

```bash
go test -bench=BenchmarkCompile -benchmem -benchtime=1s ./internal/program/...
```

参考値として、Xeon 8362、Linux 6.x での出力例を示します。

```
BenchmarkCompile/cbpfc/ICMP-64         17140   13939 ns/op   14.00 insns/op
BenchmarkCompile/dsl/ICMP-64           62308    3679 ns/op   27.00 insns/op
BenchmarkCompile/cbpfc/TCP_443-64       4726   48349 ns/op   60.00 insns/op
BenchmarkCompile/dsl/TCP_443-64        49881    4615 ns/op   32.00 insns/op
```

`b.ReportMetric` で命令数を `insns/op` で報告するので、`go test -bench` の 1 行に時間と emit サイズが両方載ります。

### Per-pattern microbench (codegen path 単位)

`BenchmarkCompile` 1 件は 7 codegen path を conflate するので、path 単位の regression 検出には向きません。`internal/program/bench_test.go` に 9 microbench を追加して、codegen path を次のように分離しました。

| Bench | 計測対象 | 例 expression |
|---|---|---|
| `BenchmarkCompileBaseline` | 最小 chain (regression baseline) | `eth/ipv4/tcp` |
| `BenchmarkPredicateOnly` | bracket predicate (`predicate.go`) | `eth/ipv4[src==10.0.0.1]/tcp` |
| `BenchmarkWhereOnly` | where 句 (`where.go`) | `eth/ipv4/tcp where tcp.dport == 443` |
| `BenchmarkCaptureOnly` | capture metadata (`capture.go`) | `eth/ipv4/tcp capture headers+64` |
| `BenchmarkChainStatic` | 静的アンロール (`chain.go`) | `eth/vlan{1,3}/ipv4/tcp` |
| `BenchmarkChainBpfLoop` | bpf_loop callback (`bpfloop.go`) | `eth/vlan+/ipv4/tcp` |
| `BenchmarkAlternationSimple` | het-alt (`alternation.go`) | `eth/(vlan\|qinq)/ipv4/tcp` |
| `BenchmarkDynamicAuxLookup` | option slot allocation (`option_demand.go` + parser-machine TLV) | `eth/ipv4/tcp where tcp.options.MSS.value == 1460` |
| `BenchmarkVocabLoad` | vocab init (`dslvocab.Bundled` cache miss) | (first compile baseline) |

新 codegen path を 1 件追加するときは、対応する microbench を足すと regression 警告が早く出ます。`go test -bench=. -benchtime=1s ./internal/program/...` で全部 1 度に取れます。

傾向は次のとおりです。

- コンパイル時間は DSL のほうが速いです。cbpfc は cBPF → eBPF の純粋トランスパイラで、libpcap 経由のパース → cBPF byte-code → eBPF 命令変換と段が多く、起動コストが見えてきます。DSL は AST → IR → codegen の 3 段ですが、各段が軽量です。
- 生成命令数は式によって逆転します。簡単な `icmp` (L2 + L3 のみのフィルタ) は cbpfc が短くなります。`tcp port 443` のように L2/L3/L4 の bounds と dispatch を全部展開する式では、cBPF の絶対オフセットアクセスを 1:1 で eBPF に展開するため、cbpfc 側のほうが冗長になる傾向があります。
- これらは kernel ホットパスではない数値です。フィルタは load 時に 1 度しかコンパイルされないので、μs オーダーの差は実利用に影響しません。本命は C 軸 (per-packet PPS) です。

cbpfc が読めない式 (MPLS+、VXLAN inner など) は DSL でしか測れません。逆に DSL が読めない式 (tcpdump の `dst host net 10.0.0.0/24`) は cbpfc でしか測れません。同じフィルタを両方で書けるケースだけ、A/B 比較に意味があります。

代表的に揃えて比較できるペアを次に示します。

| 意図 | tcpdump (cbpfc) | DSL |
|---|---|---|
| ICMP | `icmp` | `eth/ipv4/icmp` |
| TCP/443 | `tcp port 443` | `eth/ipv4/tcp[dport==443]` |
| ホスト | `host 10.0.0.1` | (DSL は IP リテラル未対応のため比較不可) |
| TCP and host | `tcp and host 10.0.0.1` | (同上) |

## C 軸 (kernel PPS)

ここからが本命です。手順は次のとおりです。

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

3 パターンを同条件で比較します。

```bash
# (A) Filter 無し (= XDP_PASS のみ)
sudo perf stat -e cycles,instructions,cache-misses,task-clock -- \
  timeout 30 xdp-ninja -i veth0 -c 0 > /dev/null

# (B) cbpfc filter 経由 (--cbpf で legacy 構文に切替)
sudo perf stat -e cycles,instructions,cache-misses,task-clock -- \
  timeout 30 xdp-ninja --cbpf -i veth0 -c 0 "tcp port 443" > /dev/null

# (C) DSL filter 経由
sudo perf stat -e cycles,instructions,cache-misses,task-clock -- \
  timeout 30 xdp-ninja -i veth0 -c 0 "eth/ipv4/tcp[dport==443]" > /dev/null
```

`xdp-ninja` の stderr に `N packets captured` が出ます。30 秒走らせて、N/30 が実効 pps になります。`perf stat` の `cycles` / `instructions` は kernel-side オーバーヘッドの目安です。

### 4. 解釈

期待される傾向は次のとおりです。

| パターン | 想定 pps (相対) | コメント |
|---|---|---|
| Filter 無し (A) | 100% | ベースライン (XDP_PASS + xdp_output コピー) |
| cbpfc (B) | 95-99% | フィルタ評価は線形、十数命令 |
| DSL (C, 単純チェーン) | 90-98% | layer 毎の bounds + dispatch があるので命令数は cbpfc より多いが、verifier が同等の最適化を入れる |
| DSL (C, bpf_loop chain) | 70-90% | bpf_loop callback 1 回あたり ~15 命令 + helper 呼出オーバーヘッド (MPLS 4 段なら ~80 命令分のオーバーヘッド) |

重要なのは、ベースラインに対する相対値を見ることです。絶対 pps は CPU / NIC / kernel バージョン / XDP target の最適化レベルで簡単に倍違います。

### 5. fexit の相対オーバーヘッド

`--mode exit` を加えると、trampoline で XDP の戻り値も観測します。fentry よりわずかに重いですが、filter 自体の比較性質は変わりません。

```bash
sudo xdp-ninja -i veth0 --mode exit -c 0 \
  "eth/ipv4/tcp where action == XDP_DROP" > /dev/null
```

## 既知の DSL コスト要因

C 軸で DSL が cbpfc より重く見える典型ケースは次のとおりです。

1. Capture `headers+N` は、既定の libpcap snaplen (1500) より小さい場合に `bpf_xdp_output` のコピー量を抑えられるメリット側です。逆はありません。
2. Layered chain (`mpls+`、`vlan*`) では bpf_loop helper の呼び出しが 1 回追加されます。callback per iter は line-rate ベンチでは効きにくいですが、イテレーション数 × callback 命令数で線形に効きます。
3. `where` 算術では、`ipv4.total_length > 100` のような算術比較は LDX + BSwap + 比較で済むので、cbpfc とほぼ同等です。
4. alternation `(a|b)` は各 alt の dispatch を順に試すので、1 alt あたり線形コストになります。`(a|b|c|d)` で worst case 4 倍ですが、altCountCap=4 なので有界です。

## ベンチで陥りがちな罠

- uname -r が違う環境を混ぜてはいけません。bpf_loop は 5.17+ で、それより古いと DSL の chain は load 自体が失敗します。
- scratch buffer のサイズ (`ScratchBufSize = 512` byte) を超える packet では、filter は丸読みしません。capture 量とフィルタ評価範囲が分離されている事実を忘れないでください。per-CPU map にコピーする prefix 長は別で、`MaxCapLen` で制御します。
- veth 環境は GRO/GSO の影響を受けやすいので、`ethtool -K vethX gso off tso off gro off` で揃えてください。
- 負荷源 (pktgen/iperf3) の上限が NIC でなく CPU になっていないか、`mpstat` で確認してください。
- 同じ pcap ファイルへの書き込みで IO が律速していないか確認してください。`-w /dev/null` に向けるか、`-c 100` などで頭を切ります。

## 公開用にまとめるとき

`docs/ja/` 配下に数値付きのレポートを書きたいときは、次のようにまとめます。

- 環境 (kernel uname -r、CPU、NIC、xdp-ninja コミット) を冒頭に固定する
- 同じハードで cbpfc/DSL/baseline を順番ではなくインターリーブで測定する (温度ドリフト緩和)
- 標準偏差 / 95% CI を出す。1 回計測の数値は当てにならない
- フィルタ式は同義のものだけ並べる (DSL でしか書けない式は別表)

数値は環境特化なので、本ドキュメントには手順だけを残し、実測レポートは別ファイル (`docs/ja/benchmarks/<date>-<hwtag>.md`) に分けると保守しやすくなります。

## 参考

- [dsl-usage.md](./dsl-usage.md): フィルタの書き方
- [`pkg/kunai/protocols/`](../../pkg/kunai/protocols/): vocab 拡張は既存 .p4 ファイルを参考にする
- `internal/program/bench_test.go`: Go ベンチ実装
- `scripts/test/setup.sh`: veth 環境セットアップの参考
