# xdp-ninja 性能チューニングガイド

1 Mpps を超える高 pps の capture で取りこぼしを減らすための設定ガイドです。通常の用途では既定値で十分なので、まず取りこぼしが実際に出ているかどうかを測定してから手を入れてください。

フラグの一覧と既定値については [dsl-usage.md の Performance flags](./dsl-usage.md#performance-flags) を参照してください。

## 1. 性能の上限を理解する

xdp-ninja の capture スループットには、設定では越えられない物理的な上限があります。

ボトルネックは packet データの cold read です。NIC が DMA したパケットは DDIO でいったん L3 に載りますが、line rate ではキャプチャ処理が読む前に後続のパケットによって evict され、メモリから読み直すことになります。このとき DRAM のレイテンシによる stall が発生します。性質としては次のとおりです。

- メモリ帯域ではなくレイテンシによって律速されます。DDR5 にしても速くなりません。DRAM のレイテンシは世代でほぼ横ばいで、DDR5 の長所である帯域は元々余っているからです。
- 効くのは大きい L3 です。DDIO の領域にパケットが長く留まるほど cold miss が減るため、巨大な L3 を積む CPU が有利になります。

設定でできるのは、この上限をなるべく高くすることと、上限に近づけることです。上限そのものは消せません。これを踏まえた上で以下の対策を使ってください。

## 2. 現状を測定する

チューニングの前に、現状を数値で把握してください。

- --null-output を使うと、出力を捨てて reader の CPU コストだけを測れます。取りこぼしゼロで何 Mpps を通せるかという、パイプラインの上限が出ます。
- -w による実出力では実効レートが出ます。--null-output より大きく落ちる場合は、producer と consumer の結合が効いています。3.6 の split-core を参照してください。
- ringbuf drop は終了時に stderr へ出力されます。captured が XDP に届いた数より少ない場合は ring が溢れています。3.1 の snaplen や 3.3 の ringbuf-size を参照してください。

## 3. 効果の大きい順に設定を変える

### 3.1 snaplen を下げる

--snaplen N で 1 パケットあたりの保存バイト数を切り詰めます。DSL の capture 句でも指定できます。効果は二重にあります。

- 読み込む cache line の数が減るため、cold miss の回数が減ります。
- ringbuf の予約サイズが縮むため、同じ ring 容量により多くのレコードが入り、burst の吸収が増えます。

ヘッダだけが必要なら capture headers+0、L4 ヘッダまで見たいなら 64 から 128 バイトで足りることが多いです。フルパケットが必要でなければ必ず下げてください。これを最優先で検討してください。

### 3.2 --fast-reader を常用する

--fast-reader は mmap と atomic で直接読み出す reader です。cilium/ebpf の generic な reader より CPU が低く、スループットが高くなります。高 rate では実質的に必須で、以下のフラグはすべて --fast-reader を前提としています。

### 3.3 --ringbuf-size を増やす

--ringbuf-size は per-CPU の ring 1 個あたりの容量で、既定値は 16 MB です。瞬間的な burst で取りこぼすなら増やしてください。snaplen を下げる方が経済的ですが、両方とも効きます。

### 3.4 --raw-dump で出力経路を軽くする

--raw-dump は pcap-ng の整形を bypass し、パケットのバイト列とヘッダをそのまま raw ファイルに追記します。後から xdp-ninja convert で pcap-ng に変換します。writer や storage が律速になっているときに有効です。NVMe への書き込みが間に合わないなら、--in-memory-buffer N で mmap 上のバッファに退避できます。

なお consumer 側が律速になっていない構成、たとえば 3.6 の split-core では、raw-dump と pcap-ng の差はほとんどありません。出力経路がボトルネックのときにだけ意味があります。

### 3.5 --no-wakeup を有効にする

--no-wakeup は BPF_RB_NO_WAKEUP を全 submit に立て、reader を起こす eventfd を止めます。スループットは上がりますが、代わりに p50 のレイテンシが悪化します。おおよそ 100µs から 2.6ms 程度まで悪化し、polling の床が 1ms になります。--fast-reader が必須です。レイテンシより総量を優先する場面で使ってください。

### 3.6 split-core でコアを分離する

-w の実出力でレートが --null-output の半分近くまで落ちるときに効きます。原因は、producer である RX softirq と consumer の結合です。寝ている consumer を起こす経路が RX softirq に背圧をかけ、結果として両方が遅くなります。

コアを分離する手順は次のとおりです。

1. NIC の queue を N に固定します。ethtool -L combined N を実行します。実行のタイミングについては下の注意を必ず読んでください。これで RX と capture が core 0 から N-1 に閉じます。
2. --rx-cores N を指定すると、consumer の goroutine が core N から 2N-1 に pin され、RX softirq のコアから外れます。
3. --busy-poll と --no-wakeup を指定すると、consumer が epoll_wait で寝なくなり、常時 drain して wakeup が不要になります。

コアを半分ずつに分ける対称な分割が最も効きます。たとえば 64 コアなら 32 と 32 に分けます。RX 側のコアを増やす非対称な分割はむしろ逆効果になります。busy-poll の spinner が出すメモリトラフィックが、レイテンシ律速の RX をかき乱すからです。実測では -w の出力が 30% 向上しました。

> ethtool -L のタイミングに注意してください。ethtool -L combined N は名前こそ軽そうですが、実態は VSI の再構築で、netdev のグローバルロックである RTNL を握る重い操作です。modprobe の直後でドライバの初期化が完了していない状態で実行すると、ice などのドライバが RTNL を握ったまま D-state でデッドロックし、udev や dmesg など box 全体に波及します。この場合は reboot が必要になります。ドライバが十分に安定してから実行してください。split-core を使わないなら queue の数はいじらなくて構いません。

## 4. 効果がなかった対策を避ける

時間を無駄にしないために記録しておきます。以下は、試して効果がなかった対策と、退行した対策です。

- packet prefetch は効きませんでした。kprobe や kfunc で次の batch のバッファを暖める方法です。飽和した RX コアの上で prefetcher を走らせても memory-latency の壁は越えられません。prefetch した cache line が working set を汚し、むしろわずかに悪化します。
- CPUMAP で capture を別のコアへ decouple する方法も効きませんでした。全コアが RX softirq で飽和した box では cpumap の kthread が starve し、ほとんど起動しません。逃がす先の空きコアがないからです。
- wakeup-batch は効きませんでした。N 回に 1 回だけ wakeup を強制する方法ですが、単体では効果がありません。結合を断つのはコアの物理的な分離である split-core であって、wakeup の頻度ではありません。
- writev による writer の zero-copy 化は退行しました。syscall の coalesce が既存の bufio に負けます。

要するに、capture rate を上げる実効的な対策は snaplen、split-core、サンプリング、ハードウェアであって、prefetch や cpumap、wakeup の頻度、writer の小細工ではありません。

## 5. ワークロードごとに使い分ける

- capture アプライアンスとして録って捨てる用途では、--mode xdp で観測した後そのまま XDP_DROP します。split-core で最大のスループットを狙えます。
- inline で観測しつつ転送する用途では、転送アクションによって大きく変わります。reflect 系の XDP_TX はカーネルスタックを通らないので、実用的なレートが出ます。スタックへ流す XDP_PASS では skb の生成と netif の経路が壁になり大幅に落ちますが、これは xdp-ninja ではなくカーネルの netif 経路の性質であり、設定では救えません。
- fentry や fexit で観測する用途では、既存の XDP プログラムに非侵襲で相乗りします。コストは観測対象の動作によって変わり、観測対象が drop するか tx するか redirect するかで変わります。

## 6. ハードウェアを選ぶ

- 大きい L3 が効きます。DDIO の領域にパケットが長く留まり、cold miss が減るからです。
- DDR5 は効きません。律速しているのはレイテンシであり、DDR5 の長所は帯域だからです。DRAM のレイテンシは世代でほぼ横ばいです。
- queue の数や IRQ の affinity を制御できる NIC なら、split-core を組みやすくなります。ice や E810 などが該当します。
