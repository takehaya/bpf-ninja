# 0003 bpf_loop callback の cursor を mask してから書き戻す

- 状態：採用
- 日付：2026-10-15

## 背景

Linux 7.0 以降の kernel では、TCP option を読む filter の load が遅くなった。
dsltest の `TestSpecVectorsGenerated` は、kernel 6.18 の guest で 46 秒、7.0 から 7.3-rc4 の guest で 170〜200 秒かかり、Ubuntu 26.04 の host では 5 分の timeout を超えた。
1 回の load で見ると、最も遅い vector は約 30 ms から約 340 ms になった。
遅くなるのは option の walk を含む filter だけで、単純な filter の load 時間は変わらない。

原因は kernel 7.0 で入った commit f597664454bd (bpf: bpf_scc_visit instance and backedges accumulation for bpf_loop()) である。
この commit は v7.0 で初めて入り、6.19 には入っていない。
これは安全性の修正で、`Fixes:` に 96c6aa4c63af と c9e31900b54c を挙げている。
それまでの verifier は、bpf_loop の callback の中で作った checkpoint の precision の情報が不完全で、安全でない program を受け入れることがあった。
7.0 からは callback をループとして扱い、状態グラフの戻り辺に沿って precision を伝える。

kunai の option walk は bpf_loop の callback で、cursor を ctx に書き戻しながら反復する。
書き戻す cursor の値域や、他の register との定数差の関係は、option の種類と反復ごとに違う。
7.0 からは cursor の slot に precision が付くので、verifier はこの違いを厳密に比べ、状態を合流させなくなった。
verifier の log では、cursor の slot に対する `mark_precise` が P2 で 128 回から 1004 回に増えていた。

6.18 の速さは precision の伝播が不完全だったことの副産物なので、戻すべき基準ではない。

## 測定

filter ごとに、verifier が処理した命令数 (processed) と、同時に保持した状態の数の最大値 (peak_states) を比べた。
検証時間は kernel の build ごとの差が大きく、比較用の filter でも 7.1 と 7.2 だけが 3 倍ほど遅かったので、kernel をまたいだ比較には使わない。

測った filter は `pkg/kunai/dsltest/verifier_stats_test.go` の `verifierProbes` にある。
主なものは次のとおりである。

- S1 は `eth/ipv4/tcp where ipv4.options.valid and (tcp.options.valid and ((tcp.options.MSS.value == 1460) and (tcp.options.WS.shift == 7)))` で、IPv4 と TCP の両方の option を walk する。
- S4 は `eth/ipv4/tcp[mss.value == 1460, ws.shift == 7] where tcp.dport == 80` で、TCP option の accumulator を使う。
- P2 は `eth/ipv4/tcp where tcp.options.valid` で、TCP option の walk だけを含む。
- C1 は `eth/ipv6{1,5}/tcp`、C2 は `eth/vlan?/ipv6/tcp where ipv6.exts[ipv6.hop_limit].next_header == 6`、C3 は `eth/(ipv4|ipv6)/tcp` で、TCP option を読まない比較用の filter である。

mask を入れる前の processed は次のとおりで、7.1、7.2、7.3-rc4 は同じ値だった。

| filter | 6.18 | 7.0 | 7.1 以降 |
|---|---|---|---|
| S1 | 14141 | 55841 | 23520 |
| S4 | 6825 | 27693 | 11212 |
| P2 | 3819 | 6777 | 5252 |
| C1 | 12350 | 12915 | 12350 |
| C2 | 7424 | 7892 | 7424 |
| C3 | 1428 | 1458 | 1394 |

S1 の peak_states は、6.18 の 409 が 7.0 で 6063、7.1 以降で 2257 になった。
比較用の C1 から C3 は、どの kernel でもほとんど変わらない。

## 判断と理由

callback が cursor を ctx に書き戻す前に、cursor の複製に `0x3ff` を AND し、その複製を書く。
helper は `pkg/kunai/codegen/bpfloop.go` の `storeCallbackCursor` で、cursor を書き戻す 6 か所すべてがこれを使う。

書き戻す直前の cursor は、どの場所でも ScratchBufSize (512) 以下であることを check 済みである。
512 以下の値に `0x3ff` を AND しても値は変わらないので、実行時の動作は変わらない。
verifier から見ると、AND の結果は register の id、定数差の関係、下限を持たない。
そのため、option の種類や反復が違っても、書き戻した slot は同じ形になり、状態が合流する。
`0x1ff` は使えない。
packet が scratch をちょうど埋めると cursor は正当に 512 になり、`0x1ff` ではそれが 0 に巻き戻るからである。

mask は R3 そのものではなく、R0 に取った複製にかける。
書き戻しの後に、cursor の下限を読む命令が続く場所があるからである。
たとえば、IPv6 拡張 header の walk では書き戻しの直後に最小長の check があり、chain の callback では直後に cursor の下限を check してから負の offset を折り込む。
R3 を直接 mask すると、それまで静的に成立しなかった分岐が生きた分岐になり、反復ごとに状態が 1 つ増える。
R3 を直接 mask した版では、C2 は 7424 から 8364 に、C3 は 1394 から 1800 に増えた。
6 か所とも、書き戻しの後の R0 は読まれる前に必ず書き換えられる。

mask を入れた後の processed は次のとおりである。

| filter | 6.18 | 7.0 | 7.1 以降 |
|---|---|---|---|
| S1 | 14141 → 9051 | 55841 → 27916 | 23520 → 11928 |
| S4 | 6825 → 4303 | 27693 → 13705 | 11212 → 5554 |
| P2 | 3819 → 2537 | 6777 → 3177 | 5252 → 2620 |
| C1 | 12350 → 8383 | 12915 → 8483 | 12350 → 8323 |
| C2 | 7424 → 7540 | 7892 → 7832 | 7424 → 7608 |
| C3 | 1428 → 1794 | 1458 → 1814 | 1394 → 1794 |

TCP option の filter は、7.0 でほぼ半分になり、7.1 以降は 6.18 の元の値より小さくなった。
S1 の peak_states は、7.0 で 6063 から 3290 に、7.1 以降で 2257 から 1286 に減った。
6.1 と 6.6 はこの commit を持たないので、ほとんど変わらない。増える filter でも 3.5% 以内で、6.6 では S2 が 7599 から 3085 に減った。
spec vector は 9 つの kernel すべてで通った。

## トレードオフ

C3 は 6.12 以降で約 400 命令、率にして約 29% 増える。
この増加は IPv6 拡張 header の walk に入れた mask から来ていて、R3 を残す複製の形でも変わらなかった。
この mask を外すと、C1 の 3〜4 割の減少も消える。
C3 はもともと軽い filter で、増えた量は C1 で減った量の 1 割ほどなので、受け入れた。

書き戻しの後に R3 を直接 mask する形は、複製の形より processed が 0.3〜1.5% 少ないが、採らなかった。
chain の callback のように書き戻しの直後で R3 の下限を読む場所では、C2 や C3 と同じ型の悪化が出る。
場所ごとに安全性を示す手間に見合う差ではない。

## 測り直す手順

`TestVerifierStats` は root で動くと、filter ごとに 1 行の `VSTAT` を出し、最後に `verifierBaseline` の 1 行と同じ形の `VSTAT-BASELINE` を出す。
手元の kernel では次のように実行する。

```sh
sudo go test -count=1 -v -run TestVerifierStats ./pkg/kunai/dsltest
```

`scripts/test/privileged.py --kernel` は `KUNAI_VERIFIER_STRICT=1` を付けて実行する。
このとき、processed が `verifierBaseline` の値の 1.5 倍を超えた filter と、基準値のない kernel や filter は失敗になる。
kernel の key は release の先頭 2 つの数字なので、7.3-rc4 と 7.3 は同じ行を使う。
手元の kernel では基準値と比べた結果を log に出すだけで、失敗にはしない。

codegen の変更で processed が意図どおりに変わったときは、CI の log か artifact `verifier-matrix-kernel-*` の `verifier_stats_kernel_*.log` から `VSTAT-BASELINE` の行を集め、`verifierBaseline` の該当する行を置き換える。
kernel をまたいで比べるのは processed と状態の数だけにする。

## 未解決の点

7.1 で一部が戻った理由は特定していない。
v7.1 に入っていて v7.0 に入っていない commit のうち、仕組みが合う候補は次のとおりである。
どれも含まれていることは確かめたが、bisect はしていない。

- 2cb27158adb3: dead な stack slot を poison する
- 7ca5f68cda07、be23266b4a08: stack の liveness を 4 byte 単位で追う
- 6762e3a0bce5: (callsite, depth) ごとの func_instances
- f1606dd0ac49、b254c6d816e5: 静的に死んだ分岐の pruning

2026-10-08 に、bpf_loop の callback の pruning regression を直す patch が upstream に投稿された。
件名は bpf: Fix state pruning regression in bpf_loop() callbacks で、kernel-patches/bpf の #14273、patchwork の series 1181930 にある。
本文はまだ読めていない。
この patch が入った kernel では、mask の効果を測り直す。
