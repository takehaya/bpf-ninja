# TCP 多 option フィルタの codegen (bit accumulator + forget)

`eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7`
のように、**同じ TLV リスト (TCP options) から複数の option を 1 つの `where`
で問い合わせる**フィルタをどう eBPF に落とすか、という話。Mechanism 7
(TLV options walk、`dsl-internals.md` §6.5) の上に乗る codegen 技法。

結論だけ先に言うと、複数 option を **1 個の bit accumulator に畳んで 1 本の
bpf_loop で評価する**。素直に書くと verifier に弾かれるので、ループ内で
**cursor と accumulator を毎周「忘れさせる」(forget)** ことで収束させている。

## 1. 何が難しいか

TCP options は可変長 TLV (kind / length / payload の並び) なので、parser machine
の self-loop = `bpf_loop` で歩く。素直な実装はこうなる:

- query した option ごとに、その option の **パケット内オフセットを専用 stack
  slot に記録**する。
- ループ後に、各 slot からオフセットを引いてフィールドを読み、比較する。

これは option が 1 種類なら通るが、**2 種類以上を query すると verifier が
1M 命令予算 (`processed 1000001 insns`) を超えて reject する**。記録 slot が
N 個になると、verifier が「どの slot にどの値が入っているか」の組合せを追い、
さらに後述の cursor 非収束も重なって状態が爆発するため。

## 2. 解決の骨子: bit accumulator

「N 個の位置を記録する」のをやめて、**評価結果の bit を 1 個の slot に畳む**。

- ループの中で各 option をその場 (live cursor) で評価する。
- `option.field == const` が成り立ったら、その atom に割り当てた bit を
  accumulator slot に OR する。
- ループ後の `where` 判定は `(acc & mask) == mask` の 1 個だけになる
  (mask = 全 atom の bit の OR)。option が 1 個でも欠けると bit が 0 のまま
  なので AND が成立しない。

記録する distinct slot が 1 個に減るので、N-slot 由来の爆発が消える。

用語: **atom** = `<option>.<field> == <const>` の等式 1 個。`MSS.value == 1460`
で 1 atom、`MSS.length == 4` を足すと 2 atom (同じ MSS でもフィールドが違えば
別 atom)。

## 3. なぜループが収束しないか、そして forget

accumulator にしても、それだけでは通らない。`bpf_loop` は「今回のループ先頭
状態が前回に含まれる (RANGE_WITHIN)」と判定できたとき探索を打ち切る (収束)。
ところが先頭で生きている可変スカラが収束を妨げる:

- **cursor** (options 領域内のバイトオフセット): 毎周ランタイム長ぶん前進する
  ので、verifier が追う範囲の下限 (smin) がじわじわ上がり、前回の状態に含まれ
  ない。収束せず callback を状態ごとに再探索する。
- **accumulator**: ループの中で bit を OR していくので、verifier はその「bit の
  組合せ履歴」を精密に追う。option が D 種類あると 2^D 通りに枝分かれする。

どちらも **forget** で畳む。XOR を使った恒等変換:

```
forget(x, width):
    salt = read(scratch[0], width)   # verifier 的に width bit ぶん不定の値
    x ^= salt
    x ^= salt                        # x ^ s ^ s == x (ランタイム値は不変)
```

ランタイムでは `x` は変わらない (同じ salt で 2 回 XOR)。だが verifier は
`s ^ s == 0` を畳まないので、`x` の bit が unknown になり**範囲履歴が消える**。
次のループ先頭で `x` は毎周まったく同じ「不定」状態になり、収束する。

salt の幅 (`width`) は **「変わりうる bit を全部カバーする幅」**にする:

- cursor (0..511、9 bit) は `byte` で足りる。
- accumulator (atom 数ぶんの bit フラグ) は **`u64` 必須**。`byte` だと低 8 bit
  しか忘れず、9 個目以降の bit が履歴を持って 2^(N-8) に枝分かれする。これが
  実際にあった「~8 atom で頭打ち」の正体だった。

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
            if kind == atom.option_kind and packet[cursor + atom.field_off] == atom.cmpval:
                acc |= (1 << atom.bit)
        acc = forget(acc, u64)                 # 毎周 acc を収束 (1 ループ化の鍵)
        cursor += option_length(packet, cursor)

    if (acc & mask) != mask:                   # 全 option が一致したときだけ通す
        reject
```

ループが運ぶ可変スカラ (cursor と acc) を**両方** forget するのがポイント。
両方畳めば先頭状態が毎周同じになり、option を何個積んでも 1 反復ぶんに収束
する。cursor だけ忘れて acc を忘れないと、acc が 2^D に枝分かれして詰まる。

## 5. 分岐数ガードの免除

codegen には別途、callback の分岐命令数を静的に数える tripwire がある
(`callback_lint.go`、閾値 64)。「分岐 × MAX_DEPTH で scalar-ID が膨張する」
クラスの回帰を compile 時に捕まえるためのもの。

全 option の dispatch を 1 callback に詰めると、option が 5 種類くらいで 64 を
超える。だが forget で収束する accumulator callback では「× MAX_DEPTH」の膨張が
起きないので、このガードの前提が当てはまらない。よって **accumulator のとき
だけガードを免除**している (`emitMultiStateCallback`)。代わりに、その load は
カーネル matrix のテストで直接証明する (下記)。

## 6. 制限とパラメータ

- `accMaxAtoms = 16` (`acc.go`): accumulator が畳む atom 数の上限。技術的な壁
  でなく policy 値。TCP が構成可能な atom は最大 14 (全 option の全フィールド)
  なので、実質「TCP で書けるものは全部通る」。
- ハード上限は約 31: `where` 後の `(acc & mask) == mask` を 32bit 即値で組んで
  いるため (`emitAccMaskCheck`)。32 個以上の bit にしたければ mask をレジスタに
  積む変更が要る。
- 起動条件: distinct な option が 2 種類以上で、`where` 全体が
  `<option>.<field> == <const>` の純粋な AND であること (`buildAccPlan`)。
  単一 option や、`!=`・非 option atom が混ざる形は別経路 (従来どおり)。

## 7. 関連ファイル / テスト

- `pkg/kunai/codegen/acc.go`: `buildAccPlan` (どの `where` を accumulator に
  するか判定)、`accMaxAtoms`、`emitAccMaskCheck`。
- `pkg/kunai/codegen/parser_loop.go`: `emitMultiStateCallback` (cursor forget +
  分岐ガード免除)、`emitAccPrelude` (atom 評価 + acc forget)。
- `internal/program/tcp_accumulator_load_test.go`: `TestBpfTCPAccumulator{XDP,TC}`
  で 2/3/4/8/14 atom が 6.1〜7.0 の全カーネルで load することを検証 (vimto matrix)。
- `pkg/kunai/dsltest/acc_correctness_test.go`: forget がランタイムの判定結果を
  壊していないこと (一致で match、欠け / 不一致で reject) を検証。
