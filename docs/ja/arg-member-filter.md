# ポインター引数のメンバーを調べて絞り込む

BPF 関数に渡された構造体や共用体の中に、絞り込みに使いたい値がある場合は `--arg-filter` を使えます。
たとえば UPF の分類関数が受け取る query に IMSI や PDR ID が入っていれば、その値でキャプチャ対象を選べます。
先に `--arg-echo` で実際の値を確認してから、フィルターを設定する流れが基本です。
どちらも `--mode entry` と `--mode exit` で使えます。
引数フィルターは entry と exit の両方で条件を満たす gated キャプチャでも使えます。

対象は、関数や型の情報を持つ BTF とともにロード済みの BPF プログラムです。
`-p <ID>` でプログラムを、`--func classify` でコンパイル後も残っているサブ関数を指定します。
先頭のコンテキスト引数はパラメーター一覧に含まれません。
EXT の置換関数など、対応する引数を持つエントリ関数では `--func` を省略できます。
エントリ関数にコンテキスト引数しかない場合は、`--func` でサブ関数を選びます。
アタッチの前提は [README](../../README.md#attaching-to-subfunctions-entryexit-only) を参照してください。

メンバーのフィルターと echo、スカラーポインターの `[0]` 読み取り、ポインターの NULL 比較、メンバーからのセットキー生成には `bpf_get_func_arg` ヘルパーが必要です（upstream Linux 5.17 以降）。
これらの機能の実測範囲はテストマトリクスの 6.1 以降であり、ディストリビューションのバックポート状況によって異なります。
共通の前提である 5.8 以降という条件だけでは、このヘルパーは使えません。

static XDP、tc、cgroup-skb、netfilter のキャプチャでは、直接読み取りのプローブが scalar コンテキストとして拒否された場合に、失敗を処理できるヘルパーでコンテキストを読み取ります。
直接読み取りが通る static 関数は、そのまま直接読み取ります。
この経路を使う前に、bpf-ninja は対象の変換後の命令列を調べ、すべての呼び出しが第 1 引数にプログラムのコンテキストを渡していることを確かめます。
失敗を処理できる読み取りは、どのポインターでもコンテキストとして受け付けてしまうためです。
`inject-run` が `bpf-ninja:hook` タグを付けたフックでは、この検査を省きます。
第 1 引数は保存済みのプログラムコンテキストであり、その整合性は注入時に決めたスタックの床に依存します。
このタグは生成した関数であるというローダー側の表明であり、別のローダーが付けたタグを bpf-ninja は検証しません。
直接呼び出しの連鎖にある各関数が BTF のコンテキスト引数を持ち、対象関数の第 1 引数まで同じコンテキストを渡す場合を確かめます。
コンテキストは各呼び出し位置でレジスターか 8 byte のスタック退避に残っている必要があります。
コンテキストを渡さない呼び出し元、コンテキスト引数のない関数、対象関数の関数ポインターとしての使用、間接ジャンプ、呼び出し先が上書きしうるコンテキストの退避、ヘルパーか kfunc に渡したスタックバッファに重なるか、それより上にあり、再読み込みまでに呼び出しかスタック以外を指すポインター経由の書き込みがあるコンテキストの退避、スタックポインターと関数ポインターでありうる値の両方を受け取るヘルパーか kfunc の呼び出し（フレームに書き込みうるコールバック）より前のコンテキストの退避、r11（Linux 7.2 以降が 6 番目以降の引数に使うレジスター）を介して格納されるスタック引数、x86-64 以外のホストでヘルパー ID を隠した変換後の命令列（CAP_SYSLOG を与え、`kernel.kptr_restrict` を 2 未満に保てば避けられます）、32,767 命令を超えるプログラムは拒否します。
その場合は呼び出し元か global 関数でキャプチャしてください。
複数 target のキャプチャでは、拒否された target を警告付きでスキップし、他の target への attach は残します。一つも attach できなければ失敗します。
エントリが呼ぶ関数を後から extension で置き換える場合は考慮しません。それにはプログラム自体を置き換えるのと同じ権限が要るためです。
static tc と cgroup-skb では、カーネル BTF から求めた `sk_buff` のオフセットを使い、`data`、`len`、`data_len` を `bpf_probe_read_kernel` で読みます。static netfilter では、先に `bpf_nf_ctx.skb` を同じく BTF のオフセットで `bpf_probe_read_kernel` で読み、その `sk_buff` から同じ 3 つを読みます。
キャプチャする範囲は線形ヘッドの `len - data_len` bytes に限り、fragment は含めません。
読み取りに失敗した場合はキャプチャしません。
tc では、この経路でフィルターに `--tc-vlan-reinsert` を付けると、`--tc-vlan-reinsert is not supported at static tc function "NAME"` として拒否します。cgroup_skb と netfilter では、このフラグは効果がありません。

これらの経路の exit と gated キャプチャには、action の取得用に `bpf_get_func_ret` も必要です（upstream Linux 5.17 以降）。
カーネルが BTF プロトタイプを破棄している可能性があるため、引数数から戻り値の位置を推測しません。

## 式を書く前にメンバーを調べる

まず関数と引数の一覧を確認します。
`--list-params` に `--members` を追加すると、構造体または共用体へのポインター引数ごとに、参照先のメンバーがツリー表示されます。
対応するスカラーポインターには `[0]` の式も表示されます。配列へのポインターは先頭要素で表示されます。

```sh
sudo bpf-ninja -p <ID> --list-funcs
sudo bpf-ninja -p <ID> --func classify --list-params
sudo bpf-ninja -p <ID> --func classify --list-params --members
```

query の中に target を埋め込んだ構造体なら、次のように表示されます。
型名やオフセットは対象プログラムの BTF によって変わります。

```text
Filterable parameters for classify (id=42):
  q: struct query * (arg index 1)
    q->imsi  u64  off 0  size 8  unsigned  filterable
    q->target  struct target  off 8  size 4  (not filterable: final member must be an integer or enum, got struct (select one of its members))
      q->target.pdr_id  __u32  off 8  size 4  unsigned  filterable
    q->flags  __u32:3  off 12  size 4  unsigned  (not filterable: bitfield member "flags" is not supported)
```

各メンバー行の先頭が、そのまま入力できる式です。
`off` は元のポインター `q` からのバイトオフセットで、親の行からの相対位置ではありません。
`size` は BTF 上の型の格納サイズをバイト単位で示します。
ビットフィールドでは型名の後の `:3` がビット幅を表し、`size` は引き続き型の格納サイズを示します。
バイト境界にないメンバーには、端数のビットオフセットも表示されます。
`__u32` などの typedef 名は維持され、整数と列挙型には符号の有無が表示されます。
構造体や共用体そのものはフィルターに使えませんが、その子の整数メンバーは使える場合があります。

`filterable` は、フィルターと echo が使うものと同じ解決処理を通ったことを示します。
実行時にポインターを読めることや、どの呼び出しでも意味のある値が入っていることまでは保証しません。
無名の構造体や共用体のメンバーは、外側のスコープに公開された名前で表示されます。
式に無名部分の名前を補う必要はありません。
同じ名前が複数のメンバーに対応する場合は、各行に `ambiguous` と表示され、式としては使えません。
それぞれの型とオフセットは表示されるため、名前が衝突している箇所を確認できます。

表示の深さはデフォルトで 3 段です。
`q->target.pdr_id` は 2 段目に当たり、無名のコンテナーは段数に数えません。
最初は `--members-depth 1` で全体を見渡し、必要に応じて最大 32 まで増やせます。

```sh
sudo bpf-ninja -p <ID> --func classify --list-params --members --members-depth 5
```

省略した枝には理由が表示されます。
循環する型を検出した場合、無名メンバーの入れ子が 32 段を超えた場合、または引数ごとの表示が 4096 行に達した場合にも探索を止めます。
`--members-depth` は一覧表示の設定であり、フィルター式を解決する規則は変えません。
`--members` には `--list-params` が、`--members-depth` にはその両方が必要です。
`--list-funcs`、`--list-progs`、`--dump-asm` とは併用できません。
テキストは通常の引数一覧と同じく標準エラー出力に書き込まれます。

## JSON をスクリプトで扱う

`--json` を付けると、同じ内容が標準出力に JSON で出力されます。
次の例では、利用可能な式だけを `jq` で取り出しています。

```sh
sudo bpf-ninja -p <ID> --func classify --list-params --members --json > params.json
jq '.. | objects | select(.filterable? == true) | .expression' params.json
```

既存の最上位の配列、`func`、`id`、引数の各フィールドは変わりません。
生成されたフックの `status` の項目には常に `fields` 配列があり、引数と同じ形で `status.ret` と `status.flags` を持ちます。どちらも 1 つの引数の一部です。
`--members` を付けた場合だけ、ポインター引数に `type` と `members` 配列が追加されます。
参照先にメンバーがなければ空配列になります。
個々のメンバーは次の形式です。

```json
{
  "expression": "q->target.pdr_id",
  "type": "__u32",
  "offset": 8,
  "size": 4,
  "signed": false,
  "filterable": true
}
```

入れ子の構造体や共用体には、さらに `members` 配列が付きます。
使えない式には `reason` が付き、整数と列挙型の `signed` は false の場合も出力されます。
`bitfield_size` はビット幅、`bit_offset` はバイト単位の `offset` に加算する 1〜7 ビットの端数です。
これらはゼロの場合に省略されます。
BTF から格納サイズを求められない型の `size` は null になります。
引数またはメンバーの `members_truncated` は、その下の表示を省略した理由です。
`--members` を付けない場合の JSON 形式は従来どおりです。

## 式と比較演算子を使う

引数のポインターを `->` で 1 回だけたどり、埋め込まれた構造体や共用体には `.` で進みます。
シェルが `>` をリダイレクトとして解釈しないよう、式全体を引用符で囲んでください。
引数フィルターはパケット用 DSL とは別の構文です。

| 式 | 条件 |
|---|---|
| `q->imsi=262010000000001` | 指定した数値と等しい（`==` も同じ意味です） |
| `q->target.pdr_id!=3` | 3 と等しくない |
| `q->target.pdr_id>=3` | 3 以上 |
| `q->target.pdr_id<=9` | 9 以下 |
| `q->target.pdr_id=3..9` | 3 以上 9 以下 |

数値は 10 進数か `0x` 付きの 16 進数で指定します。
符号付きのメンバーには、負の 10 進数も使えます。
列挙型には列挙子の名前ではなく数値を指定し、型の幅と符号に収まる値を使います。
`--arg-filter` を繰り返すと、すべての条件を満たす呼び出しが対象になります。
同じ演算子を通常の整数引数にも使えます。
厳密な大小比較の `<` と `>`、変数の添字、2 回目の `->` には対応していません。

Echo では比較演算子を付けず、メンバー式を位置引数として渡します。

```sh
sudo bpf-ninja -p <ID> --func classify --arg-echo -c 10 'q->imsi' 'q->target.pdr_id'
```

式を指定しない `--arg-echo` は整数引数だけを表示し、ポインターの参照先を自動では展開しません。
Echo の対象は 1 つの関数と 1 つのモードに限られます。
通常の `--arg-filter` 式を組み合わせ、条件を満たした呼び出しだけを表示することもできます。

## 配列の要素を選ぶ

固定長の配列メンバーには、経路のどこでも定数の添字を付けられます。
入れ子の配列には次元ごとに添字を付けます。

```sh
sudo bpf-ninja -p <ID> --func lookup_hook --arg-filter 'value->rules[0].action==2'
sudo bpf-ninja -p <ID> --func lookup_hook --arg-filter 'value->counts[3]==1'
sudo bpf-ninja -p <ID> --func lookup_hook --arg-filter 'value->grid[1][2]>=7'
sudo bpf-ninja -p <ID> --func lookup_hook --arg-echo 'value->rules[1].action'
```

オフセットは BTF から求めます。添字と要素サイズの積をメンバーのオフセットに足します。
`value` が配列へのポインターのとき（値の型が `__u32[4]` や `struct rule[4]` のマップのフックなど）は、`[0]` から始めて `value[0][2]` や `value[0][1].action` と書きます。
添字は 10 進数の定数で、先頭に 0 を付けません。
負の添字、変数の添字、配列の長さ以上の添字、配列以外への添字、長さ 0 の配列への添字は、フィルターを解決する時点で拒否します。
`--list-params --members` は配列を先頭要素で `value->rules[0].action`、`value->counts[0]`、`value[0][0]` のように表示します。ほかの要素は `0` を置き換えて指定します。
セットのキーと `--record filter` も同じ式を受け付け、コメントには `value->rules[0].action=2` のように要素の名前が出ます。

## ヘルパーの結果で選ぶ

update、delete、push、pop、peek のフックの引数 `status` は `(u32)ret | flags << 32` です。
そのため全体を比較するとフラグも比較されます。`BPF_NOEXIST` の update が成功すると status は `0x0000000100000000` になり、`status==0` では選べません。
これらのフックでは、`status.ret` が下位 32 ビットを符号付き整数として、`status.flags` が上位 32 ビットを符号なし整数として表します。

```sh
sudo bpf-ninja -p <ID> --func ninja_sessions_update --arg-filter 'status.ret==0'
sudo bpf-ninja -p <ID> --func ninja_sessions_update --arg-filter 'status.ret==-17'
sudo bpf-ninja -p <ID> --func ninja_sessions_update --arg-filter 'status.flags==1'
sudo bpf-ninja -p <ID> --func ninja_sessions_update --arg-echo 'status.ret' 'status.flags'
```

フックが成功した呼び出しを受け取るのは `update:any` のような `:any` の操作だけです。`update` だけでは失敗時にしか呼ばれないため、`status.ret==0` には `:any` が必要です（[操作の表](../en/inject-run.md#choose-the-maps-and-operations-to-observe)）。
シフトと符号拡張はプローブが比較の前に行います。
`status` だけを書くと全体を表します。
`--list-params` は `status` の下にこの 2 つを表示します。
どちらも `inject-run` が生成したフックにだけあり、ほかの関数の引数に `status.ret` を指定すると、引数名によらず拒否します。

## ネットワークバイトオーダーの値を比較する

ネットワークバイトオーダーで格納された引数やメンバーには、`be16(...)`、`be32(...)`、`be64(...)` を使います。

```sh
sudo bpf-ninja -p <ID> --func lookup_hook --arg-filter 'key->dport==be16(443)'
sudo bpf-ninja -p <ID> --func lookup_hook --arg-filter 'key->addr!=be32(0x0a000001)'
```

括弧内の符号なし整数をネットワークバイトオーダーに変換してから比較します。
幅は BTF の引数やメンバーと一致する必要があり、16 ビットのポートに `be32(443)` を指定するとエラーになります。
符号付きの末端では、格納されたビット列を符号拡張して比較します。
対応する演算子は `=`、`==`、`!=` だけです。
バイトオーダーの変換では数値の大小関係が保たれないため、`be16(1000)..be16(2000)` や `1000..be16(2000)` の範囲、`beNN` を含む `>=` と `<=` は拒否します。
通常の数値は、メモリーからネイティブの整数として読み取った値を表します。

## NULL を調べてスカラーポインターを読む

ポインター引数そのものには `value=null`、`value==null`、`value!=null` を指定できます。
構造体、共用体、スカラー、`const void *` のポインターに対応し、参照先は読みません。
`value->action!=2` を含むメンバー比較では、NULL や読み取り失敗は常に不一致になります。
読み取れなかった値をゼロとして扱うことはありません。
NULL の比較対象はポインター引数なので、`value->action==null` はエラーになります。

`const __u32 *value` や `const __u64 *value` には `value[0]` を使います。

```sh
sudo bpf-ninja -p <ID> --func ninja_seen_peek --list-params --members
sudo bpf-ninja -p <ID> --func ninja_seen_peek --arg-filter 'value[0]==64'
sudo bpf-ninja -p <ID> --func ninja_seen_peek --arg-echo 'value[0]'
```

一覧にも型、サイズ、符号とともに `value[0]` が表示されます。
対応するのは整数または列挙型へのポインターの添字 0 だけで、構造体全体や型が不明な `void` の参照先は読めません。
対象フックの BTF にスカラー型が残っている必要があります。
マップを BTF なしでロードすると、フックの参照先が型不明のバイト列構造体になり、`[0]` を使えない場合があります。
queue の BTF と typed lookup のミス時の引数については、[walkthrough](../en/inject-walkthrough.md#6-capture-the-packets-at-a-hook) を参照してください。

## メンバーからセットのキーを組み立てる

セットのキーへの明示的な対応付けにも、メンバー式やスカラーの参照先を使えます。

```sh
sudo bpf-ninja -p <ID> --func lookup_hook \
  --set 'ports=/sys/fs/bpf/ports,key(dport=arg:key->dport)' \
  --arg-filter '@ports'
```

すべてのキーフィールドに値を対応付ける必要があり、対応先より幅の広い値は拒否します。
幅の狭い符号付きの値は、幅の広いフィールドに符号拡張して格納します。
読み取り元が NULL または読み取り不能なら、そのセットには一致しません。
複数のセット参照と通常の引数比較は AND 条件になり、タグや実行中のエントリー更新は整数引数の場合と同じように使えます。
メンバーのバイト列はネイティブの整数表現としてキーに入るため、セットにも対応するキーを登録してください。
`beNN` は比較値の構文であり、セットの対応付けに変換を追加するものではありません。

`key(...)` を省略すると、まずフィールドと同名の整数引数を使います。
なければポインター引数から同名のメンバーを探し、一意に決まる場合に使います。
たとえばセットの `dport` は `key->dport` に自動で対応付けられます。
フィールドと同名のスカラーポインターは `[0]` の値を使います。
候補が複数あればエラーになるため、明示的に対応付けてください。
入れ子のメンバーには明示的なパスが必要で、`@NAME` は常にセット自体の名前を表します。

## 値をパケットと一緒に記録する

生成されたフックでキャプチャすると、これらのフィルターとセットのキーが読む値を、各パケットの pcapng コメントとして書き込みます。
たとえば `value->action=2 key->dport=443` のようになります。
`--record entry` を指定すると、`site`、`status`、キー、値のうちフックにあるものを書き込みます。キーと値はそれぞれ最大 `--record-max` バイト（既定は 256）です。generic と dispatch のフックでは `site` と `info` だけを書き込みます。`--record none` で無効にできます。
詳しくは[ウォークスルー](../en/inject-walkthrough.md#record-the-decision-state-with-each-packet)を参照してください。
`filter` は各フィールドを 1 回読み、その読み取り値ですべての条件を判定して記録するため、記録値はその条件を満たします。`entry` はフックでキーと値を読むため、フィルターが見ていないフィールドは別の CPU による変更と食い違う場合があります。
LPM trie のキー構造体以外の `bpf_*` 構造体の中のメンバー (`struct bpf_sock_tuple` の `tuple->ipv4.dport` など) に対するフィルターやセットのキーは、通常どおり絞り込みに使えますが記録しません。既定ではコメントから外して `-v` でその名前を表示し、`--record filter` を明示した場合は拒否します。

## BTF から読み取り位置を決める

bpf-ninja は対象プログラムの BTF から、選択した関数のプロトタイプを探します。
引数の位置を特定し、typedef や修飾子を外してポインターの参照先を調べ、メンバーを名前でたどります。
無名メンバーの子は外側のスコープで解決します。
オフセットは元の参照先から累積し、最後の整数または列挙型から幅と符号を決定します。
C のレイアウトを推測したり、同名のカーネル型を代用したりする処理ではありません。

生成した entry/exit プローブは引数のポインターを取得し、null でないことを確認してからオフセットを加算します。
値の読み取りにはカーネルの `bpf_probe_read_kernel` ヘルパーを使います。
1、2、4、8 バイトのいずれかを読み、符号付きなら符号拡張、符号なしならゼロ拡張して比較や echo に使います。
メンバーの読み取り用に別のプローブを追加することはありません。
引数を取得できない、ポインターが null、カーネル読み取りに失敗した、のいずれかなら、その呼び出しは引数フィルターを通りません。
Echo の読み取りに失敗した場合は、ゼロを表示するのではなくレコード全体を破棄します。
この処理は対象プログラムの戻り値を変更せず、対象のパケットもドロップしません。

使える末端の型は、バイト境界にある 1、2、4、8 バイトの整数か列挙型です。
選択した経路にビットフィールドが含まれていても使えません。
配列全体、構造体や共用体全体、ポインター値も対象外です。配列の要素はほかのメンバーと同じように扱います。
ポインターメンバーは表示されますが、同じ構造体へのポインターも含めて参照先には進みません。
共用体の一覧はレイアウトを示すもので、呼び出し側が現在どのメンバーを使っているかは判定しません。
無名メンバー由来の名前が曖昧な場合や、累積オフセットが対応範囲を超えた場合も拒否します。
`--arg-echo` 自体はセットに対応していません。

## IMSI を確認してからキャプチャする

UPF にあるような分類関数を、次の単純化した宣言で考えます。

```c
struct target { __u32 pdr_id; };
struct query {
    __u64 imsi;
    struct target target;
    __u32 flags : 3;
};

__attribute__((noinline))
int classify(struct xdp_md *ctx, struct query *q);
```

まず一覧で `q->imsi` を確認し、フィルターを置く位置と同じモードで echo を試します。
観測値が期待した IMSI であることを確認できたら、キャプチャ条件を指定します。

```sh
sudo bpf-ninja -p <ID> --func classify --list-params --members
sudo bpf-ninja -p <ID> --func classify --mode entry --arg-echo -c 10 'q->imsi'
sudo bpf-ninja -p <ID> --func classify --mode entry \
  --arg-filter 'q->imsi=262010000000001' -w subscriber.pcap
```

Entry で見える `q->imsi` は、呼び出し元がその時点までにオブジェクトへ格納した値です。
query を使い回していれば前のパケットの IMSI が残っていることがあり、実行経路によっては一度も値を設定しない場合もあります。
メンバーに `filterable` と表示されても、呼び出し元が毎回そこへ値を設定するとは限りません。
Echo の結果を実際のトラフィックと呼び出し側の代入処理に照らして確認してください。
Echo が何も出さない場合も、IMSI がゼロとは限らず、関数が呼ばれていない場合や読み取りに失敗している場合があります。

`classify` の内部で `imsi` を書き込むなら、`--mode exit` か、初期化後に呼ばれる別の関数を選びます。
位置を変えたら、そこで再び echo を確認してから絞り込みます。

```sh
sudo bpf-ninja -p <ID> --func classify --mode exit --arg-echo -c 10 'q->imsi'
sudo bpf-ninja -p <ID> --func classify --mode exit \
  --arg-filter 'q->imsi=262010000000001' -w subscriber-exit.pcap
```

Exit では終了時のオブジェクトを読みます。
Entry 時点のスナップショットではありません。
Gated キャプチャでは exit で引数比較とセットのキーを再評価し、両方の時点で一致する必要があります。
その間に関数本体や別の CPU が値を変更すると、キャプチャされないことがあります。
その時点でもポインターが読めることと、調べたい経路でメンバーが初期化されていることを確認します。

これとは別に、コンパイラーが未使用の引数を落とす問題があります。
`clang -O2` は、BTF に引数を残したまま、実際の呼び出し規約から未使用引数を取り除くことがあります。
その場合、一覧が正しく見えても、プローブはレジスターに残った古い値を読みます。
観測用の引数が未使用になる場合は [`keep_args.h`](../../include/keep_args.h) をインクルードし、関数本体に `KEEP_ARGS(ctx, q);` を置いてください。
命令を追加せずに引数を保持できますが、`q->imsi` を初期化する効果はありません。
`--list-funcs` で関数が `present` と表示されることを確認し、最終的な観測値は echo で確かめます。

[English version](../en/arg-member-filter.md)
