# xdp-ninja 性能チューニングガイド

高 pps（>1 Mpps 級）の capture で取りこぼしを減らすための設定ガイド。通常用途では既定値で十分なので、まず取りこぼしが実際に出ているか測ってから手を入れること。

フラグの一覧と既定値は [dsl-usage.md の Performance flags](./dsl-usage.md#performance-flags) を参照。

## 1. 天井を理解する

xdp-ninja の capture スループットには、設定では越えられない物理的な天井がある。

ボトルネックは **packet データの cold read**。NIC が DMA したパケットは DDIO でいったん L3 に載るが、line rate ではキャプチャ処理が読む前に後続パケットで evict され、メモリから読み直すことになる（DRAM レイテンシ stall）。性質として:

- **メモリ帯域**ではなく**レイテンシ**律速。DDR5 にしても速くならない（DRAM の latency は世代でほぼ横ばい、長所の bandwidth は元々余っている）。
- 効くのは「大きい L3」。DDIO 領域にパケットが長く留まるほど cold miss が減る。巨大 L3 を積む CPU が有利。

設定でできるのは「天井をなるべく高くする」「天井に近づける」ことであって、天井そのものは消せない。これを踏まえた上で以下のレバーを使う。

## 2. まず測る

チューニング前に現状を数値で掴む。

- **`--null-output`** — 出力を捨てて reader の CPU コストだけ測る。取りこぼしゼロで何 Mpps 通せるかというパイプライン天井が出る。
- **`-w` 実出力** — 実効レート。`--null-output` より大きく落ちるなら producer-consumer の結合が効いている（→ §3.6 split-core）。
- **ringbuf drop** — 終了時に stderr へ出る。captured が「XDP に届いた数」より少ないなら ring が溢れている（→ §3.1 snaplen / §3.3 ringbuf-size）。

## 3. レバー（ROI 順）

### 3.1 snaplen を下げる ★最優先

`--snaplen N` で 1 パケットの保存バイト数を切る（または DSL の `capture` 句で指定）。効果が二重にある:

- **読む cache line 数が減る** → cold miss の回数が減る。
- **ringbuf 予約が縮む** → 同じ ring 容量により多くのレコードが入り、burst 吸収が増える。

ヘッダだけ要るなら `capture headers+0`、L4 ヘッダまで見たいなら 64〜128 B で足りることが多い。フルパケットが要らないなら必ず下げる。

### 3.2 `--fast-reader` ★高 rate は常時 on

mmap+atomic 直叩きの reader。cilium/ebpf の generic reader より低 CPU・高 throughput。高 rate では実質必須で、以下のフラグはすべて `--fast-reader` を前提にしている。

### 3.3 `--ringbuf-size`

per-CPU ring の容量（既定 16 MB）。瞬間的な burst で取りこぼすなら増やす。snaplen を下げる方が経済的だが、両方効く。

### 3.4 `--raw-dump`（+ `--in-memory-buffer`）

pcap-ng 整形を bypass し、パケットバイト + ヘッダをそのまま raw ファイルに追記する。後で `xdp-ninja convert` で pcap-ng 化。出力（writer / storage）が律速のとき有効。NVMe write が間に合わないなら `--in-memory-buffer N` で mmap 上のバッファに退避できる。

なお consumer 側が律速でない構成（§3.6 split-core 等）では raw-dump と pcap-ng の差はほぼ無い。出力経路がボトルネックのときだけ意味がある。

### 3.5 `--no-wakeup`

`BPF_RB_NO_WAKEUP` を全 submit に立て、reader を起こす eventfd を止める。throughput は上がるが、代わりに p50 latency が悪化する（おおよそ 100µs → ~2.6ms、polling 床 1ms）。`--fast-reader` 必須。レイテンシより総量を採る場面で使う。

### 3.6 split-core（`--rx-cores` + `--busy-poll`）

`-w` 実出力でレートが `--null-output` の半分近くまで落ちるときに効く。原因は producer（RX softirq）と consumer の結合 — 寝ている consumer を起こす経路が RX softirq に背圧をかけ、結果として両方が遅くなる。

分離の手順:

1. NIC queue を N に固定する: `ethtool -L combined N`（**ドライバ安定後に**実行。下の注意を必ず読むこと）。これで RX/capture が core `0..N-1` に閉じる。
2. `--rx-cores N` — consumer goroutine を core `N..2N-1` に pin し、RX softirq のコアから外す。
3. `--busy-poll --no-wakeup` — consumer を `epoll_wait` で寝かさず常時 drain させ、wakeup を不要にする。

コアを半々に分ける対称分割（例: 64 コアなら 32/32）が sweet spot。RX 側のコアを増やす非対称分割はむしろ逆効果になる（busy-poll spinner の memory トラフィックがレイテンシ律速の RX をかき乱す）。実測で `-w` 出力が +30%。

> **注意 — `ethtool -L` のタイミング**: `ethtool -L combined N` は名前は軽いが、実態は VSI 再構築で RTNL（netdev グローバルロック）を握る重い操作。`modprobe` 直後のドライバ初期化が完了していない状態で叩くと、ice 等のドライバが RTNL を握ったまま D-state でデッドロックし、udev / dmesg など box 全体に波及する（reboot 必須になる）。ドライバが十分安定してから実行すること。split-core を使わないなら queue 数はいじらなくてよい。

## 4. 効かないもの（実証済みの negative finding）

時間を溶かさないために — 以下は試して効果が無かった、または退行した:

- **packet prefetch**（kprobe / kfunc で次 batch のバッファを暖める）— 飽和した RX コア上で prefetcher を走らせても memory-latency の壁は越えられない。prefetch した cache line が working set を汚してむしろ微悪化する。
- **CPUMAP で capture を別コアへ decouple** — 全コアが RX softirq で飽和した box では cpumap kthread が starve し、ほぼ起動しない。逃がす空きコアが無い。
- **wakeup-batch**（N 回に 1 回だけ wakeup を強制）— 単体では効果ゼロ。結合を断つのはコアの物理分離（split-core）であって wakeup の頻度ではない。
- **writer の zero-copy 化（writev）** — syscall coalesce が既存の bufio に負けて退行。

要するに、capture rate を上げる実レバーは snaplen・split-core・サンプリング・ハードウェアであって、prefetch / cpumap / wakeup 頻度 / writer の小細工ではない。

## 5. ワークロード別の使い分け

- **capture アプライアンス（録って捨てる）** — `--mode xdp` で観測後そのまま XDP_DROP。split-core で最大スループットを狙える。
- **inline 観測（観測しつつ転送する）** — 転送アクション次第で大きく変わる。reflect 系（XDP_TX）はカーネルスタックを通らないので実用的なレートが出る。スタックへ流す（XDP_PASS）と skb 生成 + netif 経路が壁になり大幅に落ちるが、これは xdp-ninja ではなくカーネル netif 経路の性質で、設定では救えない。
- **fentry / fexit 観測** — 既存の XDP プログラムに非侵襲で相乗りする。コストは観測対象の動作（drop / tx / redirect）に依存する。

## 6. ハードウェア

- **大きい L3 が効く** — DDIO 領域にパケットが長く留まり cold miss が減る。
- **DDR5 は効かない** — 律速は latency であり、DDR5 の長所は bandwidth。DRAM latency は世代でほぼ横ばい。
- queue 数や IRQ affinity を制御できる NIC（ice / E810 等）だと split-core を組みやすい。
