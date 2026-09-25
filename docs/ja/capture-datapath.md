# capture datapath deep-dive フィルタ一致からパケット書き出しまで

> kunai は in-kernel フィルタを生成するコンパイラで、生成物は 2 レジスタ間のパケットウィンドウに対する accept/reject 判定だけを持つ target-agnostic な命令列です。詳しくは [codegen deep-dive](./kunai-codegen-deepdive.md) を参照してください。本稿はその先を扱います。つまりフィルタが accept したパケットが、どうカーネルからユーザ空間へ運ばれ、pcap-ng として書き出されるかです。コードでいうとカーネル側で emit する `internal/program` と、ユーザ空間の `internal/capture` および `internal/output` が主題になります。

## データパスの全体像

1 パケットがたどる経路は次の 5 ステージです。

```
[XDP プログラム実行]
   │  fentry / fexit / XDP-native でアタッチ
   ▼
① kunai (または cBPF) フィルタを inline 評価   ← accept なら続行、reject なら抜ける
   ▼
② capture epilogue: per-CPU ringbuf に reserve → metadata 28B + パケット本体を書く → submit
   ▼
③ per-CPU sharded ringbuf (ARRAY_OF_MAPS + CPU ごとの inner RingBuf)
   ▼
④ ユーザ空間 reader: shard ごとの goroutine が drain (default reader / fast reader の 2 実装)
   ▼
⑤ pcap-ng writer: Enhanced Packet Block を stdout または -w のファイルへ
```

①と②はカーネル内で動く 1 本の BPF プログラムです。kunai が出すのは①のフィルタ命令列だけで、②以降の epilogue は host 側の `internal/program` が被せます。これが kunai を target-agnostic と呼ぶことの具体的な意味です。

## ステージ① フィルタの位置づけ

kunai の出力は `R0` をパケット先頭、`R1` をパケット末尾として入力に取り、accept なら 1、reject なら 0 を `R2` に書いて `filter_result` ラベルへ到達する、というレジスタ規約だけを仮定します。ABI の詳細は [codegen deep-dive](./kunai-codegen-deepdive.md) にあります。

host 側はアタッチモードごとにこの規約を満たす前処理を被せます。

- tracing つまり fentry と fexit の場合、トレーシングプログラムは `xdp_buff` のパケット領域を直接は触れません。そのためまずパケット先頭を `PTR_TO_MAP_VALUE` である per-CPU の filter scratch map へコピーし、その scratch を `R0` と `R1` として渡します。この処理は `internal/program/program.go` の `loadProbe` と `buildTracingInsns` にあります。
- XDP-native の場合、パケットに直接アクセスできるので scratch コピーは不要です。

フィルタが reject すると `exit` ラベルに飛び、何も emit せずにプログラムを抜けます。accept したパケットだけがステージ②へ進みます。

## ステージ② capture epilogue で ringbuf へ書き込む

accept 後の書き出しは、tracing の `captureWithRingbuf` と XDP-native の `captureXDPNative` が担います。前者は `internal/program/program.go`、後者は `internal/program/program_xdp.go` にあります。両者はほぼミラーで、流れは次のとおりです。

1. `bpf_ktime_get_ns()` でタイムスタンプを取り、スタックに退避します。XDP-native では HW タイムスタンプ kfunc が使えればそちらを優先します。
2. `bpf_get_smp_processor_id()` で自分の CPU 番号を取り、それを key にして自分の CPU の inner ringbuf を outer ARRAY_OF_MAPS から `emitShardedRBReserve` で引きます。
3. `bpf_ringbuf_reserve` で `metadataSize + maxCapLen` バイトの固定長スロットを予約します。
4. スロット先頭 28B に、後述の on-wire 形式で metadata を書きます。set にマッチしたときはその value である tag も host スタックの専用スロットから metadata に書きます。
5. パケット本体を `min(pkt_len, maxCapLen)` バイトだけスロットの 28B 目以降にコピーします。tracing は `bpf_probe_read_kernel`、XDP-native は `bpf_xdp_load_bytes` を使います。
6. `bpf_ringbuf_submit` でスロットを consumer から見える状態にします。

設計上の要点が 2 つあります。

- reserve サイズはコンパイル時定数でなければ verifier が通りません。だから常に `int32(metadataSize + maxCapLen)` を即値で渡し、レジスタ由来の可変サイズは使いません。実データ長は metadata の `caplen` フィールドで伝えます。
- reserve+submit にしているのは memcpy を 1 回減らすためです。`bpf_ringbuf_output` は内部でデータバッファをスロットへ memcpy しますが、reserve したスロットへ直接書けばその一段を省けます。

> snaplen にあたる `maxCapLen` は kunai 側が決めます。`capture N` 句があればその長さを使い、`where` 節が参照するフィールドのオフセットから必要な最小プレフィックスを推論します。無指定なら 0 を返して host 側の `DefaultCapLen` である 1500B にフォールバックします。この処理は `pkg/kunai/codegen/capture.go` にあります。CLI の `--snaplen` で上書きもできます。

## on-wire 形式と RawSample レイアウト

ringbuf に積まれる 1 レコードである `RawSample` は次の固定レイアウトです。定義は `internal/capture/capture.go` にあります。program 側の `metadataSize` と一致することは `TestMetadataSizeMatchesCapture` でピン留めしてあります。

```
RawSample = [ metadata 28B ] [ packet bytes (caplen B) ] [ trailing slack ]
```

| offset | size | field        | 内容                                                  |
|:------:|:----:|:-------------|:------------------------------------------------------|
|   0    |  8   | kernel_ts_ns | `bpf_ktime_get_ns()` の値、CLOCK_MONOTONIC            |
|   8    |  4   | action       | 対象プログラムの戻り値。単独 entry と native は固定 |
|   12   |  1   | mode         | 0=entry/fentry, 1=exit/fexit, 2=xdp-native            |
|   13   |  1   | _pad         | 0                                                     |
|   14   |  2   | caplen       | 後続パケット領域のうち実際に有効なバイト数             |
|   16   |  4   | tag          | マッチした set エントリの value、set 未マッチや set 無しなら 0 |
|   20   |  8   | packet_id    | gated entry/exit の対応 ID。それ以外は 0 |

注意点は次のとおりです。

- 全マルチバイトフィールドはホストエンディアンです。BPF 側は `asm.StoreMem` でネイティブエンディアンに書くので、reader は `binary.NativeEndian` で読みます。
- スロットは常に `metadataSize + maxCapLen` バイト予約されますが、producer が書くのは `28 + caplen` バイトだけです。残りの slack は未初期化メモリですが、submit すると予約全体が consumer から見えます。reader は `caplen` を信じてそこまでだけを読みます。
- `tag` は set lookup がヒットしたときにマッチしたエントリの value が入ります。複数の set をまたぐときはソース順で最後にマッチした set の value になります。CLI の `--split-by-tag` はこの tag を使ってパケットを tag ごとに別々の pcap へ振り分けます。
- 単独の fexit と gated capture は対象プログラムの戻り値を観測できるので、exit 側で `where action == XDP_DROP` のような述語が書けます。gated capture は exit の判定後に取り置いた entry 画像を出すため、その entry record にも最終の戻り値が入ります。単独の fentry はまだ戻り値が決まっていないので action は無効です。

## ステージ③ per-CPU sharded ringbuf

ringbuf は 1 本ではなく、CPU ごとに 1 本立てる per-CPU shard 構成です。実装は `internal/program/sharded_ringbuf.go` にあります。

- outer は `ARRAY_OF_MAPS` で、サイズは CPU 数です。各エントリに inner の `RingBuf` を 1 本ずつ入れます。
- map は observer の affinity と独立に、kernel の possible CPU ID の最大値 + 1 個を作ります。疎な ID の穴と offline CPU も予約し、capture 中に online になった CPU の shard 欠落を防ぎます。各 inner のサイズは ringbuf 総容量をこの ID 範囲で割り、最低 64KiB を床として 2 の冪へ切り下げます。`--ringbuf-size` で指定する MiB を CPU 全体で等分する形です。
- BPF プロローグは `bpf_get_smp_processor_id()` で自分の inner を引いて reserve と submit を行います。

狙いはロックフリーな shard 所有です。producer はある CPU で動く XDP や tracing プログラム、consumer はユーザ空間でその CPU に pin された reader goroutine です。両者が同じ CPU の同じ shard だけを触るので、shard 間で mutex が要りません。同一 CPU が直前に書いたキャッシュラインをそのまま読むので、キャッシュの面でも有利です。

### なぜ map-in-map なのか

BPF には per-CPU 版の ringbuf というマップ型がありません。`BPF_MAP_TYPE_RINGBUF` は 1 本のリングを全 CPU で共有する型で、reserve は内部の spinlock を取ります。単一リングのままだと多数の CPU が同じロックと producer position のキャッシュラインを奪い合い、高 pps で競合が効いてきます。arg-echo のような低レート診断用途なら単一リングで足りるので、実際 `--arg-echo` は専用の単一 ringbuf を 1 本だけ使っています。

CPU ごとに独立した RingBuf を持たせるには、BPF プログラムが実行時に自分の CPU のマップを選べる仕組みが必要です。BPF プログラムが参照するマップは通常ロード時に命令へ固定されるので、実行時に選ぶには map-in-map を使うのが正攻法です。map-in-map は `ARRAY_OF_MAPS` を CPU 番号で lookup する構造です。これが outer `ARRAY_OF_MAPS` の存在理由です。

### outer の要素をいつ更新するか

outer の要素更新、すなわち `outer[i] = inner_i` の Put が起きるのはセットアップ時の 1 回だけです。`createShardedRingbuf` が inner を CPU 数ぶん並列に作成し、続けて outer の各エントリへ並列に Put します。以後、キャプチャ実行中に outer を更新することはありません。BPF 側はパケットごとに lookup するだけで、書き換えは行いません。attach 中に shard を付け替えたりサイズを変えたりする再構成もありません。マップはプロセス終了時に閉じられます。

Put が並列なのには理由があります。`ARRAY_OF_MAPS` のような fd を値に持つマップの要素更新は、カーネルが syscall の返却前に `synchronize_rcu()` で RCU grace period を 1 回待つ仕様です。無負荷なら一瞬ですが、XDP が高負荷で回っている最中は grace period が秒単位に伸びるため、逐次に CPU 数ぶん Put するとセットアップが分単位で止まります。並列に発行すれば待ちは実質 grace period 1 回分に潰れます。この経緯と機序は [attach-under-load-rcu-finding.md](attach-under-load-rcu-finding.md) にまとめてあります。

影響の向きは一方向です。`synchronize_rcu()` で眠るのは Put を発行した bpf-ninja のセットアップスレッドだけで、XDP のパケット処理を止めたり遅くしたりはしません。実測でも、セットアップがハングしている間、対象のデータパスは無損失で転送を続けていました。トラフィック負荷がセットアップを遅くすることはあっても、この更新がトラフィックへ負荷を与えることはありません。

## ステージ④ ユーザ空間 reader

reader は全 shard に 1 goroutine ずつ立てます。producer CPU が observer の許可集合にあれば同じ CPU に、それ以外は許可集合内へ分散します。pin に失敗した場合は警告と失敗数を記録し、継承した許可集合で読み続けます。`--no-cpu-affinity` を付けると pin を無効化できます。実装は 2 つあり、CLI フラグで切り替わります。

### default reader

この実装は `RunShards` で、`cilium/ebpf` の `ringbuf.Reader.ReadInto` を使ってレコードを 1 件ずつ読みます。1 件読んだら deadline を過去に倒してノンブロッキングにし、最大 256 件をバッチに溜めてから sink へ渡します。sink は pcap writer です。バッチで sink 呼び出し回数を償却するのが狙いです。

### fast reader

この実装は `RunShardsFast` で、`cilium/ebpf` の per-record API を介さず、ringbuf map を直接 mmap して consumer ページと producer ページを自前で読みます。コードは `internal/capture/fastrb` にあります。

- `--no-wakeup` と組み合わせると、producer 側の epoll wakeup を省けます。
- `--busy-poll` を付けると `epoll_wait` でブロックせずにスピンし、ringbuf を連続して drain します。ただし shard あたり 1 コアを使い切ります。
- `--rx-cores N` は、許可された CPU ID のうち N 以上へ reader を分散します。該当 CPU がなければ起動エラーです。全 producer shard を読むため、RX が想定外の CPU に来ても shard を読み捨てません。NIC queue 数だけでは RX affinity は決まらず、別途設定が必要です。

性能の経緯と数値は [tuning ガイド](./tuning.md) と、ベンチ方法論をまとめた [dsl-benchmark.md](./dsl-benchmark.md) を参照してください。

### タイムスタンプ

既定では metadata の `kernel_ts_ns` である CLOCK_MONOTONIC の値を、起動時に 1 回測った wall_clock と monotonic の差分オフセットで wall clock に変換します。これは per-packet の精度です。`--legacy-timestamp` を付けるとバッチ単位の `time.Now()` に切り替わり、256 件のバッチが 1 つのタイムスタンプを共有します。精度は落ちますが安価です。

> 所有権の契約として、`ParseRawSample` が返す `Packet.Data` は、default ではレコードバッファ、fast では mmap リングへのビューで、次のレコードを読むと上書きされます。そのまま 256 件ためてから書き出すと、バッチ内の全パケットが最後に読んだレコードのバイト列に化けてしまいます。これを避けるため、reader は shard ごとに使い回すアリーナへ各パケットの本体をコピーし、`Data` をそのアリーナの区画に張り替えてからバッチに積みます。アリーナはフラッシュのたびに先頭へ巻き戻して再利用するので、定常状態でのアロケーションはありません。sink 側は呼び出し中に `Data` を pcap へ書き出して消費しきる必要があり、バッチを跨いで `Data` を保持してはいけません。

## ステージ⑤ pcap-ng への書き出し

sink はバッチ内の各パケットを、pcap-ng の Enhanced Packet Block すなわち EPB として書き出します。実装は `internal/output` にあります。

- 既定の高速 writer である `FastNgWriter` は EPB を手書きで組み立て、`bufio.Writer` 経由で出力します。1 パケットあたり header と data と trailer の 3 回の `Write` を bufio が束ねます。実装は `fastpcapng.go` にあります。
- 出力先は stdout か `-w` で指定するファイルです。stdout に流して Wireshark や tshark にパイプできます。

別経路として raw-dump モードもあります。これは ParseRawSample を介さず、レコードのバイト列をそのまま自前のバイナリ形式でダンプする最速経路です。後から `bpf-ninja convert` で pcap-ng に変換します。観測オーバーヘッドを最小化したいベンチ用です。

## 関係するフラグのまとめ

| フラグ | 効くステージ | 役割 |
|:--|:--|:--|
| `--snaplen N` | ② | キャプチャ長 (maxCapLen) を上書き |
| `--ringbuf-size N` | ③ | ringbuf 総容量 (MiB)、CPU 数で等分 |
| `--no-wakeup` | ②③ | producer 側 wakeup を省く (fast reader 前提) |
| `--busy-poll` | ④ | epoll をブロックせずスピン drain |
| `--rx-cores N` | ④ | split-core モード (RX とコアを分離) |
| `--no-cpu-affinity` | ④ | reader goroutine の CPU pin を無効化 (診断用) |
| `--legacy-timestamp` | ④ | per-packet kernel ts ではなくバッチ単位の userspace ts |

## 関連ドキュメント

- [kunai overview](./kunai-overview-article.md) は kunai の全体像をまとめています。
- [kunai codegen deep-dive](./kunai-codegen-deepdive.md) はフィルタ命令列、つまりステージ①の生成を扱います。
- [性能チューニングガイド](./tuning.md) は fast reader や wakeup、split-core の効果を扱います。
- [ベンチ方法論](./dsl-benchmark.md) は測定セットアップを扱います。
- [高負荷中の attach がハングする機序と修正](./attach-under-load-rcu-finding.md) は outer 更新の RCU 待ちが高負荷時に顕在化した障害の記録です。

possible CPU ID 範囲は起動時に取得します。範囲内の online/offline 変更は shard を再作成せず扱えます。kernel の possible 範囲そのものが拡張される場合は capture を再起動してください。最小データ容量は `64KiB × (最大possible CPU ID + 1)` で、map管理領域とmmap領域は別途必要です。
