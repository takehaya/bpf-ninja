# ポインター引数のメンバーを調べて絞り込む

BPF 関数に渡された構造体や共用体の中に、絞り込みに使いたい値がある場合は `--arg-filter` を使えます。
たとえば UPF の分類関数が受け取る query に IMSI や PDR ID が入っていれば、その値でキャプチャ対象を選べます。
先に `--arg-echo` で実際の値を確認してから、フィルターを設定する流れが基本です。
どちらも `--mode entry` と `--mode exit` で使えます。

対象は、関数や型の情報を持つ BTF とともにロード済みの BPF プログラムです。
`-p <ID>` でプログラムを、`--func classify` でコンパイル後も残っているサブ関数を指定します。
先頭のコンテキスト引数はパラメーター一覧に含まれません。
EXT の置換関数など、対応する引数を持つエントリ関数では `--func` を省略できます。
エントリ関数にコンテキスト引数しかない場合は、`--func` でサブ関数を選びます。
アタッチの前提は [README](../../README.md#attaching-to-subfunctions-entryexit-only) を参照してください。

## 式を書く前にメンバーを調べる

まず関数と引数の一覧を確認します。
`--list-params` に `--members` を追加すると、構造体または共用体へのポインター引数ごとに、参照先のメンバーがツリー表示されます。

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
    q->target  struct target  off 8  size 4  (not filterable: final member must be an integer or enum, got *btf.Struct)
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
| `q->imsi=262010000000001` | 指定した数値と等しい |
| `q->target.pdr_id>=3` | 3 以上 |
| `q->target.pdr_id<=9` | 9 以下 |
| `q->target.pdr_id=3..9` | 3 以上 9 以下 |

数値は 10 進数か `0x` 付きの 16 進数で指定します。
符号付きのメンバーには、負の 10 進数も使えます。
列挙型には列挙子の名前ではなく数値を指定し、型の幅と符号に収まる値を使います。
`--arg-filter` を繰り返すと、すべての条件を満たす呼び出しが対象になります。
`!=`、厳密な大小比較の `<` と `>`、配列の添字、2 回目の `->` には対応していません。

Echo では比較演算子を付けず、メンバー式を位置引数として渡します。

```sh
sudo bpf-ninja -p <ID> --func classify --arg-echo -c 10 'q->imsi' 'q->target.pdr_id'
```

式を指定しない `--arg-echo` は整数引数だけを表示し、ポインターの参照先を自動では展開しません。
Echo の対象は 1 つの関数と 1 つのモードに限られます。
通常の `--arg-filter` 式を組み合わせ、条件を満たした呼び出しだけを表示することもできます。

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
配列、構造体や共用体全体、ポインター値も対象外です。
ポインターメンバーは表示されますが、同じ構造体へのポインターも含めて参照先には進みません。
共用体の一覧はレイアウトを示すもので、呼び出し側が現在どのメンバーを使っているかは判定しません。
無名メンバー由来の名前が曖昧な場合や、累積オフセットが対応範囲を超えた場合も拒否します。
セット参照の `@NAME` と `key(field=arg:param)` の対応付けにはメンバー式を使えず、`--arg-echo` 自体もセットに対応していません。

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
その時点でもポインターが読めることと、調べたい経路でメンバーが初期化されていることを確認します。

これとは別に、コンパイラーが未使用の引数を落とす問題があります。
`clang -O2` は、BTF に引数を残したまま、実際の呼び出し規約から未使用引数を取り除くことがあります。
その場合、一覧が正しく見えても、プローブはレジスターに残った古い値を読みます。
観測用の引数が未使用になる場合は [`keep_args.h`](../../include/keep_args.h) をインクルードし、関数本体に `KEEP_ARGS(ctx, q);` を置いてください。
命令を追加せずに引数を保持できますが、`q->imsi` を初期化する効果はありません。
`--list-funcs` に関数が残っていることを確認し、最終的な観測値は echo で確かめます。

[English version](../en/arg-member-filter.md)
