# Capture の対象と観測点

このページでは、packet を取得する場所 (観測点) と、対象にするプログラム (target) の選び方を説明します。
必要な環境と対応 hook は [README の Modes](../../../README.md#modes) を参照してください。
準備から停止までを一通り試すには [隔離 capture recipe](../examples/capture-recipes.md) を使ってください。
例にある `eth0`、program ID、関数名は説明用の値です。
実際の値は `--list-progs` や `--list-funcs` で確認してください。

## 観測点を選ぶ

| 指定 | 付く場所 | 使う場面 |
|---|---|---|
| `--mode entry` (既定) | 既存プログラムの入口 (fentry) | プログラムが受け取った直後の packet を確認する |
| `--mode exit` | 既存プログラムの出口 (fexit) | 戻り値 (`where action == ...`) や書き換え後の packet を確認する |
| `--mode entry EXPR --mode exit EXPR` | 入口と出口の両方 | 両方の条件に一致した packet だけを取得する |
| `--mode xdp` | bpf-ninja 自体が interface の XDP になる | XDP が付いていない interface で取得する |

entry と exit を使うには、BTF 付きの target プログラムが先に動いている必要があります。
hook の種類 (XDP、tc、cgroup-skb、netfilter) は target から自動で判定されます。
`--mode tc-entry` と `--mode tc-exit` は非推奨の別名です。
指定すると警告を表示し、`entry` および `exit` として動作します。

## target を指定する

| 指定 | 意味 |
|---|---|
| `-i IFACE` | interface に付いた XDP プログラム |
| `-p ID` | program ID。複数指定できます |
| `--cgroup PATH` | cgroup v2 に付いた cgroup-skb プログラム (ingress と egress) |
| `-i IFACE --prog-name NAME` | interface から到達できるプログラムを名前で選びます。複数指定できます |
| `--func NAME` | entry 関数の代わりに `__noinline` のサブ関数を対象にします。複数指定できます |

`-i`、`-p`、`--cgroup` はいずれか 1 つだけを指定します。

## 開始と停止

起動後に `capturing (...)...` と表示されてから packet を送ります。
Ctrl-C または `-c N` で停止すると、summary が表示されて最終的な pcap が出力されます。
条件に一致しない packet は count に含まれないため、一致しないことを確認する試験では手動で停止してください。
停止後の確認手順は [出力とキャプチャの完了](output.md#停止後に確認すること) を参照してください。

## `--mode xdp` で interface に直接 attach する

通常、bpf-ninja は既存の XDP プログラムに fentry/fexit で attach する観測ツールです。
一方 `--mode xdp` では、bpf-ninja 自体が XDP プログラムとして interface に attach されます。

```bash
# TCP/443 だけを取り、ほかは素通しする (XDP_PASS)
sudo bpf-ninja --mode xdp -i eth0 "eth/ipv4/tcp[dport==443]"

# UDP をすべて取る
sudo bpf-ninja --mode xdp -i eth0 "eth/ipv4/udp"

# tcpdump の構文は --cbpf で使う (enable_libpcap 付きの build が必要)
sudo bpf-ninja --cbpf --mode xdp -i eth0 "tcp port 443"
```

- 条件に一致した packet は per-CPU の ringbuf に書き込まれます。
- 戻り値は既定で `XDP_PASS` です。
  `--bench-drop` を指定すると、一致の有無にかかわらず、すべての packet に `XDP_DROP` を返します。これは隔離されたベンチマーク環境専用です。
- すでに XDP が付いている interface では起動しません。
  `error: interface eth0 already has XDP program (id=42, mode=driver); use --mode entry to observe it via fentry, or detach the existing program first` というエラーを出して停止します。
- `-i` の指定が必須です。
  `-p`、`--prog-name`、`--cgroup`、`--func`、`--arg-filter`、`--list-*` は併用できません。
- `--rx-hwts` (NIC の hardware timestamp) は `--mode xdp` でのみ使用できます。
  kfunc が使えない環境では警告を出し、software の時刻に戻ります。
- `--record` は使用できません。
- raw-dump の record metadata では、mode の値は 2 になります (entry は 0、exit は 1)。

`--mode xdp` では、DSL と `--cbpf` のどちらの filter もロードできます。
filter は packet 上で直接動作するため、可変 offset の読み出し時には packet 末尾との境界比較が行われます。
IPv4 と IPv6 の chain、IPv6 を親にした dispatch (`eth/ipv6/ipv6/tcp`、`eth/ipv4/ipv6/tcp`)、`ipv4{1,2}` や `ipv6{1,2}` の繰り返し、gre の optional word、alternation、quantifier、capture 句、where 句を使用できます。
IPv6 拡張ヘッダの値は stack に保持するため、`--mode xdp` は受け取った frame を書き換えずにそのまま通します。

## 入口と出口の両方に一致した packet だけを取る

`--mode entry` と `--mode exit` を両方指定すると、同じプログラムの入口と出口に同時に attach します。
両方の条件に一致した packet だけが出力されます。
この動作を gated capture と呼びます。

```bash
# decap 後に捨てられた packet を、decap 前と decap 後の両方の姿で取る
sudo bpf-ninja -i eth0 \
  --mode entry "eth/ipv4/udp[dport==6081]" \
  --mode exit  "eth/ipv4/tcp where action == XDP_DROP" \
  -w both.pcapng

# 同じ条件で decap 前の姿だけを取る
sudo bpf-ninja -i eth0 --mode entry "eth/ipv4/udp[dport==6081]" \
  --mode exit "eth where action == XDP_DROP" --emit entry
```

### 式の書き方

- 各 `--mode` の後ろに、引用符で囲んだ式を 1 つずつ指定します。
  式を 1 つも指定しない場合、両方とも無条件になります。
  式の数が `--mode` の数と一致しないとエラーになります。
- `--mode` が 1 つのときは、位置引数を空白でつないだものが式になります。
- 入口の式は、プログラムが受け取った時点の packet に対して評価されます。
- 出口の式は、プログラムの処理が終わった後の packet と判定 (`where action == ...`) に対して評価されます。
  decap や書き換えが行われた後の layout に合わせて記述してください。
  上の例では outer UDP が剥がれるため、出口では inner の Ethernet が先頭になります。

### `--emit`

| 値 | 出す record |
|---|---|
| `both` (既定) | 入口と出口の姿を 1 組で出します (同じ id と同じ判定が付きます) |
| `entry` | 入口の姿だけを出します |
| `exit` | 出口の姿だけを出します。入口では印だけを残すため、最も負荷が軽くなります |

- `--emit` は `--mode` を 2 つ指定したときだけ使用できます。
- `-c` は出力される record の数で数えます。`--emit both` では 1 packet が 2 record になるため、`-c 10` は 5 組分です。

### 制約

- 対象にできるのは 1 つの関数だけです。`--func` の複数指定や複数のプログラムとは組み合わせられません。
- `--mode xdp`、`--split-by-tag`、`--arg-echo`、`--record`、`--dump-asm` とは併用できません。
- 同じ `--mode` を 2 回指定することはできません。
- PREEMPT_RT の kernel では起動時に警告が出ます。ペアの記録が欠落することがあります。
- 入口の式を空にすると、すべての packet を一時保存するため警告が出ます。`--emit exit` では警告は出ません。
- tail call を使うプログラム (Cilium や Katran の inline decap など) では、7.0 から 7.2.5 の kernel が 2 本目の attach を拒否します。
  attach の失敗後に trampoline が壊れて machine が panic することがあるため、bpf-ninja は attach を試みずに説明を出して停止します (CVE-2026-92485、7.2.6 と 7.3-rc1 で修正済み)。
  kernel のバージョンを読み取れないときも同様に停止します。
  該当する kernel では `--mode` を 1 つずつ使うか、修正済みの kernel を使ってください。

### 取り置きと取りこぼし

- 入口での packet の姿は、出口の判定が出るまで CPU ごとの一時領域 (hold) に保持されます。
  出口で両方の条件がそろったときだけ ring に出力されます。
  `--emit exit` 以外では、入口の条件に一致した packet ごとにこのコピーが発生します。
- 対象プログラムが `bpf_clone_redirect` などで同じ関数に入り直しても、入れ子の深さごとに別の領域を使います。
  外側と内側の実行は、それぞれ組にして出力されます。
- 一時領域は CPU ごとに 10 段あり、kernel が許容する送信の入れ子上限を満たしています。
  それより深い実行は保持されず、`hold_depth_overflow` に計上されます。
- 別の attach が trampoline を書き換えて probe が飛ばされると、`hold_overwrite` または `hold_unpaired` に計上されます。
  深さの数え方がずれた場合は、次の実行で数え直して `hold_depth_resync` に計上します。
- これらが発生すると、終了時の `capture status` は `incomplete` になります。誤った組み合わせの record が出力されることはありません。
- ring が詰まると、入口の record だけが書き込まれ、出口の record を確保できないことがあります。
  対応する組がない入口の record は取りこぼしとして扱い、判定の証拠には使わないでください。
- kernel 内部では、保持した内容が同じ実行のものかを hook の packet identity で確認します。
  XDP では `xdp_buff->data_hard_start`、tc と cgroup-skb では `sk_buff` のアドレス、netfilter では `bpf_nf_ctx->skb` を使います。
  この値が kernel の外に出ることはありません。

### 出力の形式

- pcap-ng の interface は、exit mode と同じ判定ごとの interface (`xdp:DROP`、`xdp:PASS` など) に、入口の record 用の `xdp:entry` を加えたものです。
- 標準出力への stream と、CPU ごとの shard (`-w path.pcap` の `path.pcap.cpuN`) では、各 record に `epb_packetid` option が付きます。
  値は `CPU 番号 << 48 | その CPU で入口の条件に一致した通し番号` です。同じ実行の入口と出口の record には同じ値が入ります。
  kernel のアドレスは含まれません。
- raw-dump (`--raw-dump`) の record metadata は 32 byte で、offset 20 に packet id、offset 28 に元のパケット長が入ります (形式 V3)。
  0.26 から 0.32 が書いた V2 の dump (28 byte で元の長さを持たない) も `convert` で読めます。その元の長さは captured length と同じ値になります。
  V1 の dump は `convert` で読み込めません。
- 停止時に合算した `path.pcap`、`merge` した pcap-ng、`convert` で raw-dump から作成した pcap-ng には `epb_packetid` は入りません。
  入口と出口の対応づけが必要なときは、標準出力への stream、CPU ごとの shard、raw-dump のいずれかを使ってください。
  raw-dump の扱いは [offline 出力処理](../examples/offline-output.md) を参照してください。

## 複数のプログラムと関数に attach する

`-p` と `--func` はどちらも複数回指定できます。
各 `--func` は、指定したプログラムのうち、BTF とロード済みの `func_info` にその関数を持つものすべてに attach します。
`--func` を省略すると、各プログラムの entry 関数に attach します。

| 状況 | 動作 |
|---|---|
| 関数名が一部のプログラムの BTF にない | 警告を出さずにそのプログラムをスキップします |
| 関数名がどのプログラムの BTF にもない | エラーになります |
| 複数の関数名または複数のプログラムで、BTF FUNC はあるが `func_info` にない対象や外部宣言がある | 理由付きの警告を出してスキップし、件数を stderr に出力します |
| プログラム 1 つと関数名 1 つの指定で、その関数が使えない | 詳しい説明を表示して失敗します |
| すべての対象をスキップした | 切り分け資料へのリンクを表示して失敗します |

問題の切り分けは [Subprog エラーの調べ方](../troubleshooting.md#fentryfexit-の-subprog-エラーを調べる) を参照してください。

- すべての attach 点は 1 本の共有 ringbuf に書き込むため、出力は 1 つの pcap に時刻順で記録されます。
- `--arg-filter` は関数ごとに BTF を引いて解決します。同じ param 名が関数によって別の位置にあっても正しく動作します。
  指定した param を持たない関数が混ざるとエラーになります。
- hook の種類が違う target (XDP と tc など) は混在できません。hook ごとに bpf-ninja を起動してください。

たとえばモバイルコアの UPF では、上り (UL) と下り (DL) の capture point が別のプログラムにあり、多段の dispatcher (cpu_dispatch → CPUMAP → 方向別ハンドラ) を通ります。
`__noinline` のサブ関数は呼び出し元のプログラムごとにコピーされるため、DL の関数は IPv4 ハンドラ (id 1610) と IPv6 ハンドラ (id 1611) の両方に存在します。
この場合も関数名 1 つで両方に attach でき、UL と合わせて 1 回の起動で済みます。

```bash
# dispatcher から末端の program ID までを洗い出す
sudo bpf-ninja -i ens2f0 --list-progs

# UL と DL (v4 と v6) に 1 回で付ける。upf_capture_point_dl は 1610 と 1611 に、
# upf_capture_point_ul は 1614 だけに一致する
sudo bpf-ninja -p 1610 -p 1611 -p 1614 \
  --func upf_capture_point_ul --func upf_capture_point_dl \
  --arg-filter "imsi=999990000000001" -w all.pcap
```

### `--list-progs` で到達できるプログラムを調べる

`--list-progs` は、起点のプログラムから到達できるプログラムをたどって一覧表示します。
起点は `-i` の XDP、`-p` の ID、または `--cgroup` の cgroup-skb プログラムです。
たどる経路は次の 3 種類です。

- freplace は、関数を置き換えている attach 済みの EXT プログラムです。
- tail call は、`bpf_tail_call` が使う `PROG_ARRAY` の entry が指す先です。
- redirect は、`CPUMAP`、`DEVMAP`、`DEVMAP_HASH` の entry に付いた XDP プログラムで、`bpf_redirect_map()` の飛び先です。

到達した先も同じようにたどるため、多段の構成でも末端のプログラム ID まで表示されます。
`--list-maps` を追加すると、関数ごとの呼び出しと map の使い方も表示します。
詳しい使い方は [walkthrough の map 一覧の節](../../en/inject-walkthrough.md#1-list-the-map-calls) を参照してください。

### ID の代わりに名前で選ぶ (`--prog-name`)

```bash
sudo bpf-ninja -i ens2f0 --prog-name upf_dl_v4 --prog-name upf_dl_v6 \
  --func upf_capture_point_dl --arg-filter "imsi=999990000000001" -w dl.pcap
```

- `--prog-name` は `-i` の到達ツリーから名前を解決します。`-i` の指定が必須です。
- `--mode xdp` では使用できません。tc のプログラムは `-p` で指定してください。
- kernel のプログラム名は 15 文字で切り詰められるため、長い名前は前方一致で解決します。
- 同じ名前に複数のプログラムが一致すると、特定できないためエラーになります。そのときは `-p <id>` を使ってください。

### 一覧を JSON で得る (`--json`)

`--json` を付けると、`--list-progs`、`--list-funcs`、`--list-params` の結果を JSON 形式で stdout に出力します。
`--list-progs` と `--list-funcs` を同時に渡すと、到達ツリーの各プログラムに BTF 関数の一覧が付きます。
entry と exit の capture で、これらの一覧なしに `--json` を指定するとエラーになります。

```bash
# 到達ツリーを JSON で
sudo bpf-ninja -i ens2f0 --list-progs --json | jq '.[].reachable[].name'

# 到達ツリーと各プログラムの BTF 関数を JSON で
sudo bpf-ninja -i ens2f0 --list-progs --list-funcs --json | jq '.[].reachable[] | {name, funcs}'
```

## 関数引数の値を見る (`--arg-echo`)

`--arg-echo` は、`--func` で選んだ関数がどのような引数で呼ばれているかを表示します。
packet の取得は行いません。
`--arg-filter "imsi=..."` が一致しないときに、IMSI が 10 進数か TBCD かなどを確かめるのに使えます。

```bash
# 絞り込みに使える引数を確認する
sudo bpf-ninja -p 1661 --func upf_capture_point_ul --list-params
#   imsi  [8 bytes, unsigned, arg index 1]
#   teid  [4 bytes, unsigned, arg index 2]

# 1 回だけ表示して終了する
sudo bpf-ninja -p 1661 --func upf_capture_point_ul --arg-echo -c 1
#   upf_capture_point_ul: imsi=999990000000001 (0x38d7c50ba9c01) teid=12345 (0x3039)
```

- `--func` の指定、または絞り込める引数を持つ entry 関数が必要です。
- 既定では、`--list-params` が挙げる整数引数を 10 進数と 16 進数で表示します。
  位置引数に `'q->imsi'` や `'value[0]'` のような式を書くと、その値を表示します。
- `--arg-filter` と組み合わせると、条件に一致した呼び出しだけを表示します。
- 同じ値の組が連続すると、1 行にまとめて `(xN)` と表示します。
- `-c N` で N 件表示して終了します。指定しないと Ctrl-C で止めるまで続きます。
- 対象にできるのは (プログラム, 関数) の 1 組だけです。
- `--set` と `--arg-filter @NAME` は使用できません。指定できる `--mode` も 1 つだけです。

## 判断材料を packet と一緒に記録する (`--record`)

inject した hook で取得するとき、その hook がどのような値で呼ばれたかを各 packet の pcapng コメントに記録します。

| 値 | 記録する内容 |
|---|---|
| `filter` (既定) | `--arg-filter` と `--set` のキーが読む引数とメンバー |
| `entry` | `site`、`status`、キー、値のうち hook にあるもの。キーと値はそれぞれ最大 `--record-max` バイトです。generic と dispatch の hook では `site` と `info` だけです |
| `none` | 記録しません。通常の pcap の形のままになります |

### どこで記録するか

- 既定では、`inject-run` が生成した hook だけで記録します。
  生成された hook には BTF の decl tag `bpf-ninja:hook` が付いているため、引数名が同じだけの通常の関数は通常の形のままになります。
- `--record filter` または `--record entry` を明示すると、すべての `--func` の対象で記録します。
- `-v` を付けると、記録する対象を表示します。
- gated capture、`--raw-dump`、`--arg-echo`、`--mode xdp`、`--dump-asm` では使用できません。
  明示するとエラーになり、既定値は自動で無効になります。
- 記録する対象は 255 個までです。これを超えると、明示した `--record` はエラーになり、既定値は無効になります。

### `filter` の記録

- 各フィールドは 1 回だけ読み取り、その値ですべての条件を判定して記録します。記録された値は必ず条件を満たしています。
- 読み取るフィールドがなければ記録せず、通常の pcap の形のままになります。
- LPM trie のキー構造体以外の `bpf_*` 構造体に含まれるメンバー (`struct bpf_sock_tuple` の `tuple->ipv4.dport` など) は、絞り込みには使えますが記録されません。
  既定ではそのフィールドを記録対象から外し、`-v` で名前を表示します。`--record filter` を明示した場合はエラーになります。

### `entry` の記録

- キーと値はマップの BTF を使って復号します。無名の構造体や共用体のメンバーは `--arg-filter` と同じ名前で出力します。
- 配列と名前付きの共用体は 16 進数で出力します。
- マップに BTF がないときは、generic hook と dispatch hook を除き、`key=` と `value=` に生のバイト列を 16 進数で出力します。
- `--record-max N` (既定 256、0 から 4096) は、キーと値それぞれの記録バイト数の上限です。
  `--record entry` のときだけ指定できます。
- 値渡しの整数は、全体を記録するか、まったく記録しないかのどちらかになります。
- ポインター、`bpf_*` 構造体 (`bpf_timer`、ロック、kptr を持つ構造体など)、およびそれらを含む配列や共用体は記録されません。
  uapi の LPM trie キー構造体である `bpf_lpm_trie_key`、`bpf_lpm_trie_key_hdr`、`bpf_lpm_trie_key_u8` は記録されます。
  プログラムが通常の整数フィールドに入れたアドレスは、整数として記録されます。
- untrusted な per-map hook の `const void *` のキーと値には、`inject-run` がマップから `bpf-ninja:key_size` と `bpf-ninja:value_size` の decl tag を付けます。
  `entry` はこれを読んで生のバイト列を 16 進数で記録します。
  タグが付くのは、全バイトが単純なデータであるか、その側にマップの BTF がないときだけです。ポインターや `bpf_*` フィールドを含むキーや値は記録されません。
- generic hook と dispatch hook は複数のマップを扱うため、サイズのタグがありません。
  `entry` は `site` (`info` の下位 32 ビット) と `info` 全体だけを `site=N info=0x...` として記録します。

### コメントの書式

- 空白区切りの `名前=値` の並びです。
- 名前は `--arg-filter` と同じ書き方です (`value->action`、`key->hdr.prefixlen`、`value[0]`)。
- 整数は 10 進数で出力します。符号付き整数は符号拡張されます。
- `status` は `(u32)ret | flags << 32` であるため、`--record entry` では `status=0x00000002fffffffe` のように `0x%016x` で出力します。`info` も `0x%016x` で出力します。どちらの値もそのまま `--arg-filter` に渡せます。`--record filter` では `status` と `info` もほかの整数と同じ 10 進数です。
- `status` 全体を比較するとフラグも比較されるため、`status==0` ではフラグ付きの成功を選べません。成功だけを選ぶには `:any` の操作で `status.ret==0` を使います ([ヘルパーの結果で選ぶ](../arg-member-filter.md#ヘルパーの結果で選ぶ))。
- 読み取りに失敗したフィールドは `名前=?` になります。
- NULL 判定の対象は `value=null` または `value!=null` になります。
- `--record-max` で切り詰められた値は `value_bytes=4/8` (8 バイト中 4 バイトを記録) と出力されます。

### pcapng の形

- (プログラム, 関数) の組ごとに 1 つの pcapng interface を作ります。
  interface 名は関数名です。同じ関数名が複数のプログラムにあるときは `func@progid` になります。
- `epb_packetid` は付きません。
- 判定ごとの interface がないため、`--mode exit` では各コメントの先頭に関数の戻り値を `return=0x%08x` として出力します。
- コメントの最大長が `return=` を含めて pcapng の option 1 つ分 (65535 バイト) に収まらない場合、明示した `--record` はエラーになります。
  `entry` なら `--record-max` を下げ、`filter` なら条件のフィールドを減らしてください。既定値の場合は自動で無効になります。

実際の出力例は [walkthrough の記録の節](../../en/inject-walkthrough.md#record-the-decision-state-with-each-packet) を参照してください。

## reload 後のプログラムを追う

loader が datapath を reload すると新しいプログラムがロードされますが、capture の observer は古いプログラムに付いたままです。
そこで、`inject-run` が生成した hook (`bpf-ninja:hook` の decl tag が付いた関数) への capture は、開始後にロードされたプログラムを追う。

- 開始時には、利用者が指定したプログラムだけに observer を attach する。
  その時点ですでに存在し、同じ hook を持つほかのプログラムには attach せず、gap も報告しない。
  開始後は、同じ hook を持つすべての新しいプログラムを追い、`inject-run` のセッションや interface では区別しない。
- 新しいプログラムは 2 つの方法で見つけます。
  - `inject-run` から通知を受ける。capture は、開始時とその後 2 秒ごとに、同じ network namespace にあるすべての `inject-run` に接続する。`inject-run` は hook の追加に成功したプログラムを capture へ通知し、capture が attach を終えるまで loader を止める。このプログラムは、observer が付く前には動かない。
    `--fail-closed` を付けない場合、変換に失敗して元のプログラムへ戻したロードには生成 hook がなく、通知も行われない。一致したすべてのロードへ hook を加えるかロードを拒否する必要がある場合は、`--fail-closed` を付ける。
    `inject-run` が待つのは、1 回のロードにつき全 capture の合計で 1 秒までである。1 秒を過ぎるとロードを先に進め、capture はその attach を遅れとして報告する。
    この待機は `inject-run` の単一の tracing thread 上で直列に実行されるため、target のほかの thread とそのロードも、保持中のロードの後ろで待つ。複数のロードが続くと、ロードごとの待機時間が累積する。
    timeout の後は接続を閉じ、capture は 2 秒ごとの走査で再接続します。
    再接続後の次のロードでは、その capture を再び 1 秒まで待ちます。
  - 20 ms ごとの program ID の監視です。別の network namespace にある `inject-run` や、32 個の socket がすべて使われていた `inject-run` のプログラムは、この方法で見つけます。
    開始時に接続できる `inject-run` がなければ、capture は `following N generated hook(s) by polling: no inject-run is reachable in this network namespace, ...` を出力します。
- 新しいプログラムの record は、その hook 名を持つ最初の `-p` target と同じ pcapng interface、counter、ring に入ります。
  `--arg-filter`、`--set`、`--record` は新しいプログラムの BTF に対して解決し直します。
- 対象は `--mode` が 1 つの capture です。入口と出口の両方に一致させる capture と、hook と同じ名前を持つだけの関数は追いません。
- `--no-follow` を付けると、開始時に指定したプログラムだけに観測範囲を制限します。

follower を attach できるのは、プログラム上の tracing link がすべて同じ capture の所有物である場合だけである。
link の一覧を完全に読み取れない場合は、別の observer があるものとして扱う。
capture は link を読む前に `/run/bpf-ninja/follow.lock` の排他 advisory lock を取り、そのプログラムに対する同じ capture の attach がすべて終わるまで保持する。
following には書き込み可能な `/run/bpf-ninja` directory が必要である。
lock の待機上限は 1 秒であり、取得できなければ何も attach せず、`observed_by_other` の gap を報告する。
異なる mount namespace の capture はこの lock を共有しない。
別のツールは advisory lock に従わない場合があるが、すでに付いている tracing link は follower を拒否する理由になる。

同じプログラムの hook を追う 2 つの capture は、同じ hook でも異なる hook でも、reload 後の新しいプログラムでは互いに排他となる。
先に到着した capture だけが attach し、もう一方は `observed_by_other` を報告して `incomplete` で終わる。
先着した capture が終了しても、後着の capture はそのプログラムを引き継がない。
1 つのプログラムの全 hook は、1 つの capture でまとめて追う。

ID の監視では loader を止められないため、この方法で見つけたプログラムは observer が付く前に動くことがあります。
2 回の監視の間にロードと解放が終わった短命なプログラムも見つけられず、この場合を観測できるのは supervisor がロードを保持したときだけである。
capture は、そのようなプログラムと観測できないプログラムを stderr に 1 行ずつ報告し、終了時の `capture status` は `incomplete` になります。

```
warning: FOLLOW GAP: prog=412 func=ninja_sessions reason=late unobserved_ms=23
```

| `reason` | 意味 |
|---|---|
| `late` | ロードから `unobserved_ms` ミリ秒後に observer が付き、その間 loader は止まっていませんでした。ID の監視で見つけた場合と、`inject-run` が待つのをやめた場合です。その間の hook の呼び出しは capture に入りません。 |
| `attach_failed` | プログラムを読み取れない、observer をロードまたは attach できない、または follower lock を準備できなかった。直前の行にエラーが出る。読み取れないプログラムは、後続 ID の走査を止めずに再試行し、capture の終了時にも読み取れなければ 1 回だけ報告する。このプログラムは観測されない。 |
| `filter_unresolved` | `--arg-filter` や `--set` のキーが指す引数やメンバーが、新しいプログラムの hook にありません。このプログラムは観測されません。 |
| `layout_changed` | 新しいプログラムの hook の `--record` の内容が、合流先の interface を持つ最初の target と異なる形に復号されます。このプログラムは観測されません。 |
| `observed_by_other` | 別の capture またはツールの tracing link がある、link の一覧を完全に読み取れない、または follower lock を 1 秒以内に取得できなかった。この capture はプログラムへ何も attach しない。 |

観測されないプログラムの `unobserved_ms` は、ロードから報告までの時間になる。ロード時刻も読み取れない場合は、最初の読み取り失敗から報告までの時間になる。
gap があっても capture と loader は止まらず、終了コードは 0 のままです。
observer を attach できなくても、`--fail-closed` の有無にかかわらずロードは拒否されません。
開始時の attach がすべて成功し、後からロードされたプログラムがすべて loader の停止中に attach できた capture は、`complete` かつ `follow_gaps=0` で終わる。
hook を追う capture の `capture status` の行には、末尾に `follow_attached`、`follow_held`、`follow_gaps`、`follow_gap_ms` が付く ([Capture completion](../../capture-lifecycle.md))。
`follow_attached` は現在 attach されている follower observer の数であり、reload に伴う増加を確認できる。

observer は target program をロードされたままにする。
そのため、target が置き換えたプログラムを含め、capture が観測したすべてのプログラムは capture の終了まで残る。
それらのプログラムだけが参照する map も残る。
多数の reload をまたぐ長時間の capture は再起動し、古い observer を detach してプログラムと map を解放できるようにする必要がある。
follow が有効な filter 記録では follower 用の snapshot key を 1,024 個使える。`--no-follow` ではこの領域を予約しない。
key 1 個の per-CPU map value は `8 × 記録する field 数 × possible CPU 数` byte であり、これに kernel の map 管理領域が加わる。
field 数が上限の 32 個なら follower 用領域は possible CPU 当たり 256 KiB であり、16 CPU では 4 MiB、192 CPU では 48 MiB になる。field が 1 個なら possible CPU 当たり 8 KiB になる。
追跡するプログラムが増えて key を使い切ると、次の attach は失敗し、`attach_failed` の gap が報告され、status は `incomplete` になる。

## 自作の capture point で `--arg-filter` が当たらないとき

`--func` で狙う capture point を自作するときは、引数を関数の本体で使う必要があります。
関数本体が空だと、コンパイラは使わない引数をレジスタ (r1 から r5) から落とすことがあります。
BTF の関数シグネチャは残るため、`--list-params` は正しく表示され、attach も capture も成功します。
しかし fentry/fexit の trampoline が保存するのはレジスタの中身であるため、bpf-ninja は呼び出し元が残した無関係な値を読み取ってしまいます。

このときの症状は次のとおりです。

- filter なしの capture は正常に動きます。`--list-params` も正しく表示されます。
- `--arg-filter "imsi=<真値>"` や `--arg-filter @SET` の完全一致が 1 件も当たりません。
- 範囲比較 (`imsi>=...`) は、桁だけ合う値で一致したりしなかったりします。
  目的の値を計算している途中の断片がレジスタに残っているためです。

この問題が疑わしいときは、まず `--arg-echo` で trampoline が保存した値を確認してください。
datapath 側のデバッグ出力と食い違っていれば、引数がレジスタから落ちています。

対策は、対象プログラム側で引数をレジスタに固定することです。
リポジトリの `include/keep_args.h` にある `KEEP_ARGS()` を関数本体の先頭に置いてください。

```c
#include "keep_args.h"

__attribute__((noinline))
int upf_capture_point_ul(struct xdp_md *ctx, __u64 imsi, __u32 teid) {
    KEEP_ARGS(ctx, imsi, teid);
    return 0;
}
```

`KEEP_ARGS` は各引数をレジスタ入力の空の asm に通すだけで、命令は増えません。
libbpf の `bpf_helpers.h` がある環境では、同じ働きをする `barrier_var()` を引数ごとに並べても構いません。

[DSL 利用ガイドに戻る](../dsl-usage.md)
