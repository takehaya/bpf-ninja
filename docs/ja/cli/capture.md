# Capture の対象と観測点

対象 program の動作前を見るなら entry、戻り値も見るなら exit、既存 XDP のない専用 interface で取得するなら xdp を選びます。
Linux、kernel BTF、必要な権限を確認し、entry/exit では BTF 付き target を先に用意してください。
[対応 hook と条件](../../../README.md#modes)を確認し、例中の interface、ID、関数名は実際に探索した値に置き換えます。
以下の `eth0` や program ID は説明用です。

準備から停止までの手順は [隔離 capture recipe](../examples/capture-recipes.md)を参照してください。
起動完了を示す `capturing (...)...` が出てからパケットを送信します。
Ctrl-C または count による終了後、summary と最終 pcap を確認してください。
不一致ケースは count が増えないため明示停止します。

## `--mode xdp` で native XDP として直接 attach する

通常の bpf-ninja は、既存の XDP プログラムに fentry/fexit で trampoline attach する観測ツールであり、他人の XDP を覗くモードです。一方 `--mode xdp` を付けると、bpf-ninja 自身が XDP として interface に直接 attach します。interface に何も XDP が attach されていないが filter したい場合に便利です。

```bash
# DSL で TCP/443 だけ capture, それ以外は素通し (XDP_PASS)
sudo bpf-ninja --mode xdp -i eth0 "eth/ipv4/tcp[dport==443]"

# DSL filter (UDP は全部 capture)
sudo bpf-ninja --mode xdp -i eth0 "eth/ipv4/udp"

# 旧 pcap syntax を使いたい時は --cbpf 必須 (legacy)
sudo bpf-ninja --cbpf --mode xdp -i eth0 "tcp port 443"

# 既存 XDP がある interface では fail (production XDP を意図せず壊さない設計)
sudo bpf-ninja --mode xdp -i eth0 "eth/ipv4/tcp[dport==443]"
# → error: interface eth0 already has XDP program (id=42, mode=driver);
#          use --mode entry to observe it via fentry, or detach the existing program first
```

挙動は次のとおりです。

- マッチしたパケットは per-CPU ringbuf に記録されます。
- 既定では `XDP_PASS` を返します。`--bench-drop` は隔離したベンチ用途でのみ使う opt-in です。
- mode metadata 値は xdp-native を表す 2 です。既存は entry=0、exit=1 です。

DSL / tcpdump の両方とも `--mode xdp` で load できます。native XDP では filter が packet pointer の上で直接動くので、kunai codegen は可変 offset の読みに packet 末尾との比較を付けます。verifier を通ることを確認している形は `internal/program/program_xdp_test.go` の `xdpNativeDSLExprs` にあり、IPv4 と IPv6 の chain、IPv6 を親にした dispatch (`eth/ipv6/ipv6/tcp`、`eth/ipv4/ipv6/tcp`)、`ipv4{1,2}` や `ipv6{1,2}` の繰り返し、gre の optional word、alternation、各種 quantifier、capture、where を含みます。IPv6 拡張ヘッダの write-back は packet を書き換えず stack slot に値を持つので、`--mode xdp` が通す frame は受け取ったままです。

## 入口と出口の両方に一致した packet だけを取る (`--mode` を 2 回)

`--mode` は繰り返せる。`--mode entry` と `--mode exit` を両方書くと、同じプログラムの入口 (fentry) と出口 (fexit) に同時に付き、**両方の条件に一致した packet だけ**を出す。式は `--mode` ごとに 1 つ (引用符で囲んで) 続ける。
入口の条件はプログラムが受け取ったままの packet に対して、出口の条件はプログラムが返した後の packet (decap や書き換えの後) と判定 (`where action == ...`) に対して評価する。

```bash
# decap 後に捨てられた packet を、decap 前の姿 (outer header 付き) と decap 後の姿の両方で
sudo bpf-ninja -i eth0 \
  --mode entry "eth/ipv4/udp[dport==6081]" \
  --mode exit  "eth/ipv4/tcp where action == XDP_DROP" \
  -w both.pcapng

# 同じ条件で、decap 前の姿だけ
sudo bpf-ninja -i eth0 --mode entry "eth/ipv4/udp[dport==6081]" --mode exit "eth where action == XDP_DROP" --emit entry
```

- `--mode` が 1 つなら従来どおり (位置引数を空白でつないだものが式)。2 つなら式は `--mode` と同じ数だけ (それぞれ 1 引数)、または 0 個 (両方とも無条件)。
- 入口の姿は出口の判定が出るまで CPU ごとの一時領域 (hold) に取り置き、出口で両方の条件が揃ったときだけ ring に出す。入口の条件に一致した packet にはこの取り置きのコピーが掛かる (`--emit exit` を除く)。入口の条件を空にすると全 packet を取り置くので警告が出る。
- `--emit both` (既定) は入口の姿と出口の姿を 2 record (同じ id、同じ判定付き)、`--emit entry` は入口の姿だけ、`--emit exit` は出口の姿だけ (取り置きは印だけで一番安い)。`--emit` は `--mode` が 2 つのときだけ書ける。迷ったら `both`。
- 対象は 1 つの関数に限る (`--func` の複数指定や複数プログラムとの併用は不可)。`--split-by-tag` と `--arg-echo` は併用できない。PREEMPT_RT の kernel は対象外 (起動時に警告が出る)。
- 対象が `bpf_clone_redirect` などで同じ関数に同期的に入り直しても、取り置きは入れ子の深さごとに別の領域を使うので、外側と内側の実行をそれぞれ対にして出す。領域は CPU ごとに 10 段で、kernel が許す送信の入れ子の上限に足りる。それより深い実行は取り置かずに `hold_depth_overflow` として数える。別の attach が trampoline を書き換えたせいで probe が飛ばされたときは、`hold_overwrite` か `hold_unpaired` として数え、深さの数え方がずれたら次の実行で数え直して `hold_depth_resync` に数える。どの場合も終了時の `capture status` は `incomplete` になり、誤った組み合わせの record は出ない。
- 対象が tail call をする program (Cilium や Katran の inline decap) の場合、CVE-2026-92485 に当たる kernel (7.0 から 7.2.6 / 7.3-rc1 の修正まで) は 2 本目の attach を拒否する。失敗した attach の後片付けで trampoline が壊れ、machine が panic することがあるので、bpf-ninja は試さずに説明付きで止まる。その kernel では `--mode` を 1 つずつ取るか、修正の入った kernel を使う。
- `-c` は record 数で数える。`--emit both` なら 1 packet で 2 record なので、`-c 10` は 5 組。
- ring が詰まると、入口 record だけ書けて出口 record の確保に失敗することがある (出口側の reserve が後)。対の無い入口 record は取りこぼしとして扱い、判定の証拠にしない。
- 出口の式は「出口で見える layout」に対して書く。上の例で対象が outer UDP を剥がすなら、出口では inner の Ethernet が先頭に来ているので `eth/ipv4/tcp` と書く。同じ packet でも入口と出口で式が変わるのは、実際に header が変わっているからである。
- pcap-ng の layout は exit mode と同じ verdict ごとの interface (`xdp:DROP`, `xdp:PASS`, ...) に、入口 record 用の `xdp:entry` を足したもの。
- すべての record に `epb_packetid` option (pcap-ng 標準の「同じ packet を別の interface で見た印」) が入る。既定の値は「CPU 番号 << 48 | その CPU で入口の条件に一致した通し番号」で、同じ実行の入口と出口の record が同じ値を持つ。kernel のアドレスは含まない。
- kernel 内では、取り置いた内容が同じ実行のものかを hook の packet identity (XDP なら `xdp_buff->data_hard_start`、tc / cgroup-skb なら `sk_buff` のアドレス、netfilter なら `bpf_nf_ctx->skb`) で確認する。この値は kernel の外には出ない。
- raw-dump (`--raw-dump`) の record metadata は 28 byte になり、offset 20 に packet id が入る (形式 V2。V1 の dump は `convert` で読めない)。
- この gated capture で `merge` した pcap-ng と `convert` で raw-dump から起こした pcap-ng には `epb_packetid` が入らない (どちらも id を持たない書き出し経路を通る)。対応づけが要るときは shard ごとの pcap-ng か raw-dump そのものを使う。

## 複数の (プログラム, 関数) に同時アタッチする

`-p` と `--func` はどちらも繰り返し指定できる。
各 `--func` は、指定した全 program のうち BTF とロード済み `func_info` にその関数を持つものすべてにアタッチする。
異なる関数名の複数指定や複数 program の指定では、BTF FUNC があっても `func_info` にない対象や外部宣言を短い理由付きの警告でスキップし、件数を stderr に出す。
単一 program で関数名が一つなら、同名を繰り返しても欠落時は詳しい説明付きで失敗する。
全対象をスキップした場合は、切り分け資料へのリンクを一度示して失敗する。
一部の program の BTF にない関数名は従来どおり警告なしでスキップし、全 program にない関数名はエラーになる。
`--func` を省略した場合は各 program の entry 関数が対象である。
[Subprog エラーの切り分け](../troubleshooting.md#fentryfexit-の-subprog-エラーを調べる)を参照する。

モバイルコアの UPF を例にすると、上り (UL) と下り (DL) の capture point が別プログラムに分かれ、さらに多段 dispatcher (cpu_dispatch → CPUMAP → 方向別ハンドラ) を通る。ここで `--func upf_capture_point_dl` が複数プログラムに当たる理由は、noinline サブ関数が呼び出し元プログラムごとに 1 コピーずつコンパイルされるからである。DL の実体が IPv4 ハンドラ (id 1610) と IPv6 ハンドラ (id 1611) の両方にあれば、関数名 1 つで両方へ張れる。UL + DL v4 + DL v6 の全網羅は従来3回の起動が必要だったが、1回で済む。

### `--list-progs` で到達可能プログラムを洗い出す

`--list-progs` は、起点プログラムから到達できるプログラムを推移的に辿って一覧する。起点は `-i` の XDP か `-p` の ID である。辿るエッジは次の 3 種類がある。

- freplace は、関数を置換している attach 済み EXT プログラムである。
- tail call は、`bpf_tail_call` が使う `PROG_ARRAY` のエントリ先である。
- redirect は、`CPUMAP` / `DEVMAP` / `DEVMAP_HASH` のエントリに attach された XDP プログラム、すなわち `bpf_redirect_map()` の飛び先である。

さらにその先も同様に辿るので、`cpu_dispatch → CPUMAP[0..N] → 方向別ハンドラ` から別の redirect へ続くような多段構成でも、末端の実プログラム ID までまとめて出る。

```bash
# --list-progs で dispatcher から末端の prog ID を推移的に洗い出し
sudo bpf-ninja -i ens2f0 --list-progs

# UL + DL (v4/v6 両実体) を1回でアタッチ。--func upf_capture_point_dl は
# 1610/1611 の両方に、_ul は 1614 だけにマッチする
sudo bpf-ninja -p 1610 -p 1611 -p 1614 \
  --func upf_capture_point_ul --func upf_capture_point_dl \
  --arg-filter "imsi=999990000000001" -w all.pcap
```

### ID の代わりに名前で選ぶ (`--prog-name`)

`--list-progs` の出力から prog ID を控えてコピペするのが面倒なときは、`--prog-name` で名前から選べる。`-i` の到達ツリーに対して名前解決するので、ID を調べずに済む。func 側は従来どおり `--func` を使う。

```bash
# ID の代わりに名前で選ぶ (-i の到達ツリーから解決)
sudo bpf-ninja -i ens2f0 --prog-name upf_dl_v4 --prog-name upf_dl_v6 \
  --func upf_capture_point_dl --arg-filter "imsi=999990000000001" -w dl.pcap
```

- カーネル上のプログラム名は 15 文字までに切り詰められるので、長い名前は前方一致で解決する。同じ切り詰め名のプログラムが複数あると曖昧としてエラーになるので、その場合は `-p <id>` を使う。
- `--prog-name` は `-i` 専用である。`--mode xdp` や tc 系では使えない。

### list 出力を JSON で得る (`--json`)

`--json` を付けると、`--list-progs` / `--list-funcs` / `--list-params` の結果をテキストではなく JSON で stdout に出せる。jq などに渡して自動処理したいときに便利である。`--list-progs` と `--list-funcs` を同時に渡すと、到達ツリーの各プログラムにその BTF 関数一覧もぶら下がる。

```bash
# 到達ツリーを JSON で
sudo bpf-ninja -i ens2f0 --list-progs --json | jq '.[].reachable[].name'

# 到達ツリー + 各プログラムの BTF 関数を JSON で一括取得
sudo bpf-ninja -i ens2f0 --list-progs --list-funcs --json | jq '.[].reachable[] | {name, funcs}'
```

- 全アタッチポイントが 1本の共有 ringbuf に emit するので、出力は通常どおり 1 つの pcap に時刻順で入る (`-w` なら終了時マージ、stdout なら直列化ストリーム)。
- `--arg-filter` は関数ごとに BTF を引いて検証し、解決する。同じ param 名が関数によって別の引数位置にあっても正しく効く。指定した param を持たない関数が混ざるとエラーになる。
- XDP と tc のターゲット混在は不可 (別々に起動する)。`--arg-echo` は単一 (プログラム, 関数) のみ。

## 関数引数の値を覗く (`--arg-echo`)

`--func` で狙ったサブ関数の整数引数が、実際にどんな値で呼ばれているかを見る診断モードです。`--arg-filter "imsi=..."` が当たらないとき、そもそも引数にどんな値が乗っているかを確認するのに使います。たとえば IMSI が 10 進なのか TBCD なのかを見分けられます。パケットキャプチャはせず、引数だけを専用 ringbuf に流して表示します。

```bash
# 対象関数の絞り込み可能な整数引数を確認
sudo bpf-ninja -p 1661 --func upf_capture_point_ul --list-params
#   imsi  [8 bytes, unsigned, arg index 1]
#   teid  [4 bytes, unsigned, arg index 2]

# 1 回だけ観測して終了 (-c 1)
sudo bpf-ninja -p 1661 --func upf_capture_point_ul --arg-echo -c 1
#   upf_capture_point_ul: imsi=999990000000001 (0x38d7c50ba9c01) teid=12345 (0x3039)
```

- `--func`、または整数引数を持つ EXT entry が必要です。表示対象は `--list-params` が挙げる整数引数で、10 進と 16 進を併記します。
- `--arg-filter` と併用すると、その述語にマッチした呼び出しだけを表示します。値の当たりを付けてから絞り込むという使い方ができます。
- 連続して同じ引数タプルが来た場合は 1 行に畳んで `(xN)` と表示します。`-c N` を付けると N 件表示したところで終了し、無指定なら Ctrl-C まで続きます。
- リーダは capture path と同じ in-tree の `fastrb` (mmap + epoll) を使います。

## capture point の書き方 (`--arg-filter` が当たらないとき)

`--func` で狙う capture point を自作するときは、引数を関数本体で「使って」おく必要があります。本体が空の capture point だと、コンパイラは未使用の引数を呼び出し規約 (r1..r5) から落とすことがあります。BTF の関数シグネチャはそのまま残るため `--list-params` は正しく表示され、アタッチもキャプチャも成功します。しかし fentry/fexit の trampoline が保存するのはレジスタの実体なので、bpf-ninja が読むのは呼び出し元が残した無関係な値になります。

この状態の症状は次のように見えます。

- フィルタ無しのキャプチャは動く。`--list-params` も正しい。
- `--arg-filter "imsi=<真値>"` や `--arg-filter @SET` の完全一致が 1 件も当たらない。
- 範囲比較 (`imsi>=...`) だと桁だけ合う値でマッチしたりしなかったりする。呼び出し元のレジスタに残っていたのが目的の値の計算途中の断片だと、こういう「惜しい」挙動になります。

疑わしいときは、まず `--arg-echo` で trampoline が実際に保存した値を見てください。datapath 側のデバッグ出力と食い違っていれば、引数が ABI から落ちています。

対策は、対象プログラム側で引数を ABI に固定することです。リポジトリ同梱の `include/keep_args.h` の `KEEP_ARGS()` を関数本体の先頭に置きます。

```c
#include "keep_args.h"

__attribute__((noinline))
int upf_capture_point_ul(struct xdp_md *ctx, __u64 imsi, __u32 teid) {
    KEEP_ARGS(ctx, imsi, teid);
    return 0;
}
```

`KEEP_ARGS` は各引数をレジスタ入力の空 asm に通すだけで、命令は 1 つも増えません。libbpf の `bpf_helpers.h` が入っている環境なら、同等の `barrier_var()` を引数ごとに並べても同じです。




## hook ごとの interface と共有 ID

一つの XDP または tc (SchedCLS) プログラムの複数 hook を識別する場合は、[`--hook-pcapng`](hook-pcapng.md) を指定する。
hook 名を interface 名にし、同じ実行の全 hook record に共通の packet id を付ける。
この形式では停止後の shard 合算でも ID と interface description を保持する。

[DSL 利用ガイドに戻る](../dsl-usage.md)
