# TCP 多 option フィルタの codegen (bit accumulator + forget)

`eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7`
や `eth/ipv4/tcp[mss.value == 1460, ws.shift == 7]` のように、同じ TLV リスト
(TCP options) から複数の option を問い合わせるフィルタをどう eBPF に落とすかを扱う。Mechanism 7
(TLV options walk、`dsl-internals.md` §6.5) の上に乗る codegen 技法である。

結論だけ先に言うと、複数 option を 1 個の bit accumulator に畳んで 1 本の
bpf_loop で評価する。素直に書くと verifier に弾かれるので、ループ内で
cursor と accumulator を毎周忘れさせる、すなわち forget することで収束させている。

## 1. 何が難しいか

TCP options は可変長 TLV (kind / length / payload の並び) なので、parser machine
の self-loop すなわち `bpf_loop` で歩く。素直な実装は次のようになる。

- query した option ごとに、その option のパケット内オフセットを専用 stack
  slot に記録する。
- ループ後に、各 slot からオフセットを引いてフィールドを読み、比較する。

これは option が 1 種類なら通るが、2 種類以上を query すると verifier が
1M 命令予算 (`processed 1000001 insns`) を超えて reject する。記録 slot が
N 個になると、verifier がどの slot にどの値が入っているかの組合せを追い、
さらに後述の cursor 非収束も重なって状態が爆発するからである。

## 2. 解決の骨子となる bit accumulator

N 個の位置を記録するのをやめて、評価結果の bit を 1 個の slot に畳む。

- ループの中で各 option をその場 (live cursor) で評価する。
- `option.field == const` が成り立ったら、その atom に割り当てた bit を
  accumulator slot に OR する。
- ループ後の `where` 判定は `(acc & mask) == mask` の 1 個だけになる
  (mask = 全 atom の bit の OR)。option が 1 個でも欠けると bit が 0 のまま
  なので AND が成立しない。

記録する distinct slot が 1 個に減るので、N-slot 由来の爆発が消える。

用語を整理する。atom とは `<option>.<field> == <const>` の等式 1 個を指す。`MSS.value == 1460`
で 1 atom、`MSS.length == 4` を足すと 2 atom となる (同じ MSS でもフィールドが違えば
別 atom)。

## 3. なぜループが収束しないか、そして forget

accumulator にしても、それだけでは通らない。`bpf_loop` は、今回のループ先頭
状態が前回に含まれる (RANGE_WITHIN) と判定できたとき探索を打ち切る (収束)。
ところが先頭で生きている可変スカラが収束を妨げる。

- cursor すなわち options 領域内のバイトオフセットは、毎周ランタイム長ぶん前進する
  ので、verifier が追う範囲の下限 (smin) がじわじわ上がり、前回の状態に含まれ
  ない。収束せず callback を状態ごとに再探索する。
- accumulator は、ループの中で bit を OR していくので、verifier はその bit の
  組合せ履歴を精密に追う。option が D 種類あると 2^D 通りに枝分かれする。

どちらも forget で畳む。次に示すのは XOR を使った恒等変換である。

```
forget(x, width):
    salt = read(scratch[0], width)   # verifier 的に width bit ぶん不定の値
    x ^= salt
    x ^= salt                        # x ^ s ^ s == x (ランタイム値は不変)
```

ランタイムでは `x` は変わらない (同じ salt で 2 回 XOR)。だが verifier は
`s ^ s == 0` を畳まないので、`x` の bit が unknown になり範囲履歴が消える。
次のループ先頭で `x` は毎周まったく同じ不定状態になり、収束する。

salt の幅 (`width`) は、変わりうる bit を全部カバーする幅にする。

- cursor (0..511、9 bit) は `byte` で足りる。
- accumulator (atom 数ぶんの bit フラグ) は `u64` が必須になる。`byte` だと低 8 bit
  しか忘れず、9 個目以降の bit が履歴を持って 2^(N-8) に枝分かれする。これが
  実際にあった ~8 atom で頭打ちという現象の正体だった。

## 4. 最終形 (疑似コード)

```
compile(where = AND of "opt.field == const"):
    atoms = [(MSS, value, 1460, bit0), (WS, shift, 7, bit1), ...]
    mask  = (1<<bit0) | (1<<bit1) | ...

    acc = 0
    cursor = options_start

    bpf_loop(MAX_DEPTH):                       # 1 本のループで全 option を評価
        cursor = forget(cursor, byte)          # 毎周 cursor を収束
        kind = packet[cursor]
        for atom in atoms:                     # 全 atom をインライン評価
            if kind == atom.option_kind:
                acc &= ~(1 << atom.bit)        # 同じ option が再び現れたら最後のものが決める
                if packet[cursor + atom.field_off] == atom.cmpval:
                    acc |= (1 << atom.bit)
        acc = forget(acc, u64)                 # 毎周 acc を収束 (1 ループ化の鍵)
        cursor += option_length(packet, cursor)

    if never:                                  # field に収まらない定数の葉があった
        mask |= NEVER_BIT                      # 誰も立てない bit を要求して必ず reject
    if (acc & mask) != mask:                   # 全 option が一致したときだけ通す
        reject
    if not where(rest):                        # 畳まなかった where の項
        reject                                 # (不在の layer の atom は false, D-003)
```

ループが運ぶ可変スカラ (cursor と acc) を両方とも forget するのが要点である。
両方畳めば先頭状態が毎周同じになり、option を何個積んでも 1 反復ぶんに収束
する。cursor だけ忘れて acc を忘れないと、acc が 2^D に枝分かれして詰まる。

## 5. 分岐数ガードの免除

codegen には別途、callback の分岐命令数を静的に数える tripwire がある
(`callback_lint.go`、閾値 64)。分岐 × MAX_DEPTH で scalar-ID が膨張する
クラスの回帰を compile 時に捕まえるためのものである。

全 option の dispatch を 1 callback に詰めると、option が 5 種類くらいで 64 を
超える。だが forget で収束する accumulator callback では × MAX_DEPTH の膨張が
起きないので、このガードの前提が当てはまらない。よって accumulator のとき
だけガードを免除している (`emitMultiStateCallback`)。代わりに、その load は
カーネル matrix のテストで直接証明している (下記)。

## 6. 制限とパラメータ

- `accMaxAtoms = 16` (`acc.go`) は accumulator が畳む atom 数の上限である。技術的な壁
  ではなく policy 値になっている。TCP が構成可能な atom は最大 14 (全 option の全フィールド)
  なので、実質として TCP で書けるものは全部通る。同じ field の `==` を繰り返すと
  上限を超えることがあり、そのときは等式の数を示して拒否する。
- ハード上限は約 31 になる。`where` 後の `(acc & mask) == mask` を 32bit 即値で組んで
  いるためである (`emitAccMaskCheck`)。32 個以上の bit にしたければ mask をレジスタに
  積む変更が要る。
- 起動条件は次のとおり。length-byte の TLV walk を持ち、distinct な option を
  2 種類以上読む layer がちょうど 1 つあること (`accCandidates`)。そうした layer が
  2 つ以上あると、それぞれの名前と位置を挙げて拒否する。同梱の語彙で該当するのは
  TCP だけなので、2 つになるのは alternation に tcp を 2 回書いたときに限られる。
  alternation は親の dispatch が一致した最初の member を採用して残りを試さないので、
  2 つ目以降の tcp は match しない。拒否の理由は、resolver の warning と同じ説明
  (`ir.AlternationShadowText`) で、option を 1 種類しか読まない先頭の tcp も含めて
  同じ protocol の member をすべて挙げ、1 つだけ残すよう勧める。warning が勧める
  `where` の `or` は、ここでは使えない。`or` の下で option を読む項は walk が畳めない
  ためである。
  そのうえで、その layer の option の読み出しがすべて `<option>.<field> == <const>`
  であること (`buildAccPlan`)。読み出しは bracket の predicate (`predToAtom`) でも、
  `where` の一番外側の AND の項 (`eqLeafToAtom`) でもよい。畳んだ bracket の
  predicate は `accPlan.folded` に入り、`splitPredicates` が飛ばす。
  同じ layer の `<layer>.options.valid` は `emitAccMaskCheck` が mask の後で確かめる。
  `where` の残りの項 (option を読まない atom、別 layer の `options.valid`、
  `or` や `not` を含む部分木) は `accPlan.rest` にまとめ、mask check の後に通常の
  where 条件として出す。不在になりうる layer の項には通常どおり不在のガードが付く。
  `rest`、capture の条件、capture の field のどれかが対象 layer の option を読むと、
  位置の slot が要るので plan を作らない。`!=`、大小比較、`in`、`.exists` などで
  option を読む bracket の predicate があるときも同じである。
  bracket の predicate は layer が不在なら評価されない (D-003) のに、chain の後の
  mask check は畳んだ条件を偽として扱う。このため、layer が不在になりうる (min が 0
  か、alternation の member) うえに `where` に同じ layer の atom が無いときは、mask
  check を chain の後ではなく layer の walk の直後 (done landing) に置く
  (`accPlan.inLayer`)。layer が無い経路はこの check を通らない。`where` に同じ layer
  の atom があれば、layer の不在で verdict が偽になるので chain の後で check する。
  layer が必ず存在する場合 (`accLayerAlwaysPresent`) も chain の後で check する。
  繰り返す layer は instance ごとに accumulator を戻す必要があるので拒否する。
  同じ option が 2 回以上現れたときは、仕様 (`latestView`) と位置 slot の経路に
  合わせて最後のものの値で判定する。kind が一致した時点で atom の bit を消してから
  比較し直す。
  定数は field の幅に収まる値を比較する。`int<128>(n)` で field に収まらない値を
  書いた葉は、どの packet でも false になるので、plan を `never` にして mask check が
  必ず reject する。32 bit field の上位 bit が立った定数はレジスタ経由で比較する。
  単一 option の filter は従来どおり別経路をたどる。plan を作れないときは
  `emitStateBody` の 2 option 以上の拒否に、`buildAccPlan` が返した理由
  (`predCtx.accWhy`) を付けて `ErrNotImplemented` にする。理由が無いときだけ、
  畳める形の一般的な説明を出す。
  対象 layer は length-byte advance を持つ TLV walk (TCP options) であること。TCP の領域 counter は対象に含み、それ以外の counter-driven
  walk (Geneve / IPv4 options) は native path のままとなる (`buildAccPlan` が gate)。
- alternation 内の TCP 多 option も対応する
  (`eth/ipv4/(tcp|udp) where tcp.options.MSS.value == .. and ..`)。plan を
  該当 alt member に通し、acc slot を alternation の前で zero-init する
  (`genAlternation`)。`where` に tcp の atom があるとき、非マッチ枝 (udp) は walk が
  走らず acc=0 のままなので mask-check で reject される。bracket だけを畳むときは
  check が tcp member の中で走るので、udp の経路は check を通らない。

## 7. 関連ファイル / テスト

- `pkg/kunai/codegen/acc.go`: `buildAccPlan` (どの bracket と `where` の項を
  accumulator にするか判定、`never`、`folded`、`rest` の振り分け、拒否理由)、
  `accMaxAtoms`、`emitAccMaskCheck`。
- `pkg/kunai/codegen/parser_loop.go`: `emitMultiStateCallback` (cursor forget +
  分岐ガード免除)、`emitAccPrelude` (atom 評価 + acc forget)。
- `internal/program/tcp_accumulator_load_test.go`: `TestBpfTCPAccumulator{XDP,TC}`
  で 2/3/4/8/14 atom が 6.1〜7.3-rc4 の全カーネルで load することを検証する (vimto matrix)。
- `pkg/kunai/dsltest/acc_correctness_test.go`: forget がランタイムの判定結果を
  壊していないこと (一致で match、欠け / 不一致で reject) を検証する。
- `pkg/kunai/dsltest/option_bracket_test.go` の `TestBracketTwoOptionAccumulator`:
  bracket の `==` を畳んだ filter を、stack を 0x00 と 0xff で埋めて検証する。
- `pkg/kunai/compile_test.go` の `TestCompileBracketOptionsFoldIntoAccumulator`:
  畳んだ形に walk 後の slot 読み出しが無いこと、mask の bit 数、拒否理由を検証する。
