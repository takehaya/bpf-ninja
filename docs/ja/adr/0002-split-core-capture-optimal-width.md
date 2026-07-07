# 0002 split-core キャプチャの最適コア幅

- 状態：採用
- 日付：2026-07-07

## 背景

cpumap で全コアへパケットを分散するデータパス（対象の XDP プログラム）と同じホストで捕捉すると、捕捉スループットは reader とデータパスの CPU 競合で頭打ちになる。
プロファイル（`--null-output` でライブ経路のみ）では `EpollWait` が 74.8% を占めた。
これは epoll が重いのではなく、reader が同居するデータパスにコアを譲るための必要コストで、共有コアでは削れない。
`--busy-poll`（純 spin）で epoll を消すと、reader が全コアを占有してデータパスを枯渇させ、1.30 → 0.70 Mpps へ悪化した。

競合を断つ唯一の手立ては、reader に専用コアを与えることである。
それには、データパスの cpumap 幅を狭めてコアを空ける必要がある。
RSS や IRQ affinity や taskset では空けられない。
cpumap の kthread は redirect 先 CPU ごとに立つので、cpumap が全 64 コアを対象にする限り、どのコアにも kthread が載るからである。
この幅を狭める手段は対象データパス側の設定（本件では `PGWU_XDP_DISPATCH_CPUS`）にあり、xdp-ninja 単独や OS 設定では代替できない。

## 測定

対象データパスを `0..N-1` の N コアに confine し、RSS も N キューに絞り、reader を `--rx-cores N --busy-poll --no-wakeup` で `N..2N-1` に pin した。
N を振って捕捉 pps を測った（128B、高負荷、各 N を独立バーストで実効 11〜12 秒窓、64 論理 CPU、Intel E810）。

| N | reader 本数 | idle コア | captured |
|---|---|---|---|
| 8 | 8 | 48 | 1.46 Mpps |
| **16** | 16 | 32 | **1.60 Mpps** |
| 24 | 24 | 8 | 1.48 Mpps |
| 32 | 32 | 0 | 1.36 Mpps |
| 分離なし（64 共有）| — | 0 | 約 1.35 Mpps |

N=16 を頂点とする山型になった。

## 判断と理由

N を対象ホストのコア数のおよそ 1/4（この 64 コア機では 16）に取り、reader を同数の専用コアに置くのを既定の運用とする。

両端で落ちるのは、それぞれ別の要因による。
小さい N（=8）では reader が 8 本しかなく、シャードを drain しきれずに reader 側で頭打ちになる。
このとき対象データパスは 8 コアでも取りこぼし（NIC drop）ゼロなので、律速は reader の本数である。
大きい N（=32）では reader を 32 コアへ広げるが idle コアが 0 になり、busy-poll の spin が softirq とスケジューラの余地を奪って競合が戻る。
N=16 は、reader 本数が drain に足り、かつ 32 コアが idle でシステムに余裕がある釣り合いの点である。

分離なしの約 1.35 Mpps に対し、N=16 で 1.60 Mpps、およそ 19% の改善になる。

## 制約（データパス容量とのトレードオフ）

confine はデータパス自身の転送容量を削る。
この測定は offered が 3〜4 Mpps の条件で、対象データパスが 16 コアで取りこぼしなく捌けている前提で成り立つ。
総流量がそのホストの N コアで捌ける量を超えるなら、confine を強めれば対象データパス側が drop する。
総流量が大きいほど N を大きく取らざるを得ず、その分だけ reader の専用コアと idle 余裕が減って、捕捉の上限は分離なしの約 1.35 Mpps 側へ寄る。
つまり最適 N は固定値ではなく、「対象データパスが総流量を捌ける最小のコア数」に取り、残りを reader と idle に回す、という配分になる。

## 参考

- 競合と EpollWait のプロファイル、律速の切り分け：[../capture-datapath.md](../capture-datapath.md)
- 高負荷 attach ハングの修正（この測定の前提）：[../attach-under-load-rcu-finding.md](../attach-under-load-rcu-finding.md)
