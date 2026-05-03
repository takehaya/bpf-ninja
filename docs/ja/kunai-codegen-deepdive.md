# kunai codegen deep-dive: IR から BPF 命令列へ

> 連載 3 部作の最終回。 [overview](./kunai-overview-article.md) で全体像、 [DSL deep-dive](./kunai-dsl-deepdive.md) で frontend を扱った。 本稿は **resolved IR から `cilium/ebpf` の `asm.Instructions` に lower する codegen** に踏み込む。 ABI 契約 / chain quantifier の 3 戦略 / verifier 通過テクニックが主題。

## codegen の責務

DSL frontend は IR (= 各 layer が `*vocab.ProtocolSpec` に bind 済、 dispatch 解決済、 field ref 解決済の中間表現) を作るところまで。 ここから codegen は次の責務を持つ:

- **IR を `asm.Instructions` (cilium/ebpf 形式の BPF 命令列) に lower** する
- 各 layer 境界で **verifier-safe な bounds check** を必ず emit する
- chain quantifier (`?`/`+`/`*`/`{n,m}`)、 alternation `(a|b|c)`、 parser machine、 aux header read を全部 BPF instruction 列に変換する
- 出力は **target-agnostic**: 「2 レジスタ間のパケットウィンドウと数本のワーキングレジスタ」しか仮定しない

target-agnostic というのが kunai codegen の重要な特徴で、 XDP / tc / userspace BPF / tracing を host adapter で吸収する設計の根幹になる。

## ABI 契約 — host とのレジスタ規約

codegen 出力は以下の規約を仮定する (`pkg/kunai/codegen/codegen.go` の package doc に詳細記載):

```
incoming registers (host が filter 呼び出し前にセット):
  R0 = scratch buffer の先頭 (パケット 1 バイト目)
  R1 = scratch buffer の末尾 (one past last readable byte)
  R9 = packet length (= R1 - R0)

outgoing contract:
  R2 = 1 (accept) or 0 (reject)
  実行は "filter_result" label に到達

reserved (kunai-internal):
  R3, R5  scratch (codegen が自由に clobber)
  R4      offsetBase — 現在の layer の R0 からの byte offset
  R10 stack の [-56..-80] (arith spill)
  R10 stack の [-128..-104] (bpf_loop ctx)

untouched:
  R6, R7, R8 callee-saved。 host が attach point 固有のポインタ
              (xdp_buff / data / data_end 等) を保持するのに使う
```

R4 が offsetBase というのが kunai 特有のレジスタ用法。 各 layer の codegen は R4 を「現在見ている layer の先頭 byte の offset」として使い、 layer ごとに `R4 += hs` で advance する。 layer 内で field を読むときは `R0 + R4 + field_offset` でアドレス算出。

scratch buffer は host adapter (`pkg/kunai/host/xdp/`) が per-CPU map に packet prefix をコピーした上で R0/R1 にセットする。 直接 packet pointer を渡さないのは bpf_loop callback への ctx 受け渡しを簡単にするため (callback 内で `bpf_xdp_load_bytes` のような helper 経由のアクセスが面倒)。

## 1 layer の codegen テンプレート

`pkg/kunai/codegen/codegen.go::genStaticLayer` が単一 layer の標準形:

```go
func genStaticLayer(layer, index, all) (asm.Instructions, error) {
    hs := headerSize(layer.Spec)        // primary header の固定 byte 数

    insns := emitBounds(hs, dslReject)  // (1) bounds check

    if index > 0 && layer.Dispatch != nil {
        di := genDispatch(layer, parent, parentHS, dslReject)  // (2) parent からの dispatch check
        insns = append(insns, di...)
    }

    preds := emitPredicates(layer.Predicates)  // (3) bracket predicate
    insns = append(insns, preds...)

    if layer.Spec.HasVariableLayout() {
        insns = append(insns, asm.StoreMem(R10, layerEntrySlot, R4, DWord))  // (4) layer-entry slot 保存
    }
    insns = append(insns, emitAdvance(hs))  // (5) R4 += hs

    tail := emitPrimaryVariableTail(layer.Spec)  // (6) HDRLEN_* trail (IPv4 IHL 等)
    insns = append(insns, tail...)

    if len(layer.Spec.FlagTriggers) > 0 {
        flags := emitFlagTriggers(...)  // (7) GRE C/K/S 等の flag-gated optional fields
        insns = append(insns, flags...)
    }

    return insns, nil
}
```

順序が verifier に対してクリティカル:

- **bounds 先**: bounds 通過前に LDX を出すと verifier が拒否する
- **dispatch は parent の field を見る**: 親が advance 前なら R4 = parent_start、 advance 後なら R4 = parent_end。 kunai は前者の状態で dispatch を出す
- **bracket predicate は dispatch 後**: 親 layer のパケット bytes (= dispatch 元) は predicate には関係ないが、 dispatch 失敗パスを優先するため
- **layer-entry slot 保存は advance 前**: 子の dispatch が親の primary header を読むとき、 R4 は変動しているので fp の slot に layer entry offset を保存しておく
- **HDRLEN trail は advance 後**: trail は primary header の末尾から計算する length field を消費する

## Predicate codegen — BSwap 回避と byte-swap constant

`tcp[dport == 443]` のような predicate を BPF にする。 単純に見えるが、 verifier-friendliness のための小細工がいくつか入っている。

### 1. byte-swap は const 側で

eBPF の LDX はメモリを **little-endian** で読むが、 packet byte は **network order (big-endian)**。 単純比較するには runtime byte-swap が要る。 が、 `BSwap` 命令 (opcode `0xd7`) は **kernel 6.6+** でしか使えない。 古い kernel (5.17 / 6.1) でも動かしたい。

解決: **constant 側を compile time に byte-swap しておく**。

```
LDX.HW R3, [R0 + R4 + 2]    ; tcp.dport を 16-bit load (LE 解釈)
JNE.Imm R3, byteSwap(443, 2), dslReject   ; const は事前に byte-swap (= 0xBB01)
```

これで runtime BSwap が不要になり、 5.17+ 全 kernel で同 instruction stream が動く。 `byteSwap()` は `pkg/kunai/codegen/codegen.go` の単純なバイト反転 helper。

multi-byte field (`==` で IPv4 アドレス、 IPv6 アドレス、 MAC など) の compare も同様で、 const 側を全部 byte-swap してから比較する。 IPv6 の 16 byte は 2 つの 64-bit 比較に分解 (前半 8 byte + 後半 8 byte)、 MAC の 6 byte は 4 + 2 の 2 比較に分解。

### 2. CIDR は mask + value pair

`ipv4.dst == 10.0.0.0/8` は:

```
LDX.W R3, [R0 + R4 + 16]    ; ipv4.dst を 32-bit load
And.Imm R3, byteSwap(0xff000000, 4)   ; mask = /8 = 0xff000000、 byte-swap 済
JNE.Imm R3, byteSwap(0x0a000000, 4),  dslReject   ; value = 10.0.0.0、 byte-swap 済
```

`/0` (whole space) や `/32` (host-only) は境界条件で edge case 扱い、 codegen 側で展開を最適化する。

### 3. NIBBLE は shift + compare

IPv4 version (= 上位 4 bit) のような nibble 比較:

```
LDX.B R3, [R0 + R4 + 0]    ; byte 0 を 1-byte load
RSh.Imm R3, 4              ; 上位 nibble を低位に
JNE.Imm R3, 4, dslReject   ; 4 (= IPv4) か?
```

これは Part D の SANITY 撤廃前の **dispatch sanity check** で使われていた parc (今は parser block の `transition select` に移行)。

## Where 句の short-circuit emit

`(src == 10.0.0.0/8 or dst == 192.168.0.0/16) and dport == 443` のような boolean expression。 kunai は precedence climbing で IR が tree shape (`Condition` node の and/or/not + atom)、 codegen は **short-circuit emit** で BPF にする:

```
or:  L が成立すれば全体成立 → R 評価 skip
and: L が失敗すれば全体失敗 → R 評価 skip + dslReject
not: 結果反転 (= success/fail label を入れ替える)
```

各 condition は固有の **fail label** と **next label** を取り、 codegen は fall-through (= 成功時に次の命令に進む) を多用してラベル数を減らす。 `or` で left が成立すると共通の "or-success" landing に jump、 という pattern が多い。

詳細は `pkg/kunai/codegen/where.go::genCondition`。 unique labels 振り (`dsl_or_succ_<n>` 等) で同じ名前の label が衝突しないようにしている。

## Chain quantifier の 3 戦略

ここからが kunai codegen の知的密度の高い部分。 chain quantifier (`?`, `+`, `*`, `{n,m}`) と alternation `(a|b|c)` をどう lower するか。

### 戦略 1: 静的 unroll (m ≤ 4)

`mpls{1,4}` のような **上限が小さい range quantifier** は、 各 iteration を inline 命令で展開する。 N 回繰り返しなら N 個の `genStaticLayer` 出力を順番に concat。 各 iter で peek (= 「次が同 protocol か?」を dispatch field で判定) して、 mismatch なら chain を抜ける。

```
[iter 0]
  bounds check, advance
[iter 1]
  peek parent dispatch
  if mismatch -> Ja chain_done
  bounds check, advance
[iter 2]
  ...
[chain_done]
  ; 続く layer の codegen
```

cap が 4 の理由は **verifier の path explosion**: BPF verifier は分岐の各 path を辿るので、 unroll 数 × 分岐数 で path 数が爆発する。 m = 4 で十分実用的、 5 以上は次の戦略 (bpf_loop) に切り替える。

実装: `pkg/kunai/codegen/chain.go::genStaticChain`

### 戦略 2: bpf_loop callback (m > 4 / `+` / `*`)

`mpls+` のような **上限が大きい / 無制限 quantifier** は、 1 回目の iteration を inline 命令、 2 回目以降を **bpf2bpf subprogram (callback)** に展開し、 main 命令列が `bpf_loop` ヘルパで callback を最大 N 回呼ぶ。

これは **kernel 5.17 で導入された `bpf_loop` ヘルパ**を使う設計で、 verifier はこのループを bounded として正しく扱える (= path explosion なし)。

ctx layout (main の stack `fp[-128..-104]`):

```
fp[-128..-120)  offset (u64)         current R4
fp[-120..-112)  scratchStart (u64)   PTR_TO_MAP_VALUE
fp[-112..-104)  scratchEnd (u64)     PTR_TO_MAP_VALUE + snap length
fp[-104..-96)   layerEntry (u64)     parser-machine layer の primary header offset
```

main は ctx を作って `bpf_loop(max_iter, &cb_func, &ctx, 0)` を呼ぶ:

```
StoreMem R10, fp[-128], R4         ; ctx.offset = R4
StoreMem R10, fp[-120], R0         ; ctx.scratchStart = R0
StoreMem R10, fp[-112], R1         ; ctx.scratchEnd = R1
Mov.Imm R1, max_iter
LoadFunc R2, cb_sym               ; PSEUDO_FUNC ロードで callback 関数ポインタ
Mov.Reg R3, R10
Add.Imm R3, -128                  ; R3 = &ctx
Mov.Imm R4, 0                     ; flags
Call FnLoop                       ; bpf_loop(N, cb, &ctx, 0)

; bpf_loop が caller-saved を clobber するので reload
LoadMem R4, fp[-128], DWord
LoadMem R0, fp[-120], DWord
LoadMem R1, fp[-112], DWord
```

callback subprogram は標準の bpf_loop callback signature:

```go
long callback(u32 idx, void *ctx)
```

中身:

```
LoadMem R3, R2[0]    ; ctx.offset を R3 に
LoadMem R0, R2[8]    ; ctx.scratchStart
LoadMem R1, R2[16]   ; ctx.scratchEnd

[parent dispatch peek]
if mismatch: Mov.Imm R0, 1; Return  ; bpf_loop break

[layer body codegen]
R3 += hs

StoreMem R2[0], R3   ; ctx.offset 更新
Mov.Imm R0, 0
Return                ; continue
```

callback は bpf2bpf subprogram (`Output.Callbacks` フィールドに格納) として main の Return 直後に append される。 `LoadFunc` (PSEUDO_FUNC immediate) で関数ポインタを得る。 `btf.Func` metadata がついているので verifier が型情報を引ける。

実装: `pkg/kunai/codegen/bpfloop.go`

### 戦略 3: parser machine (protocol 内部の可変長)

ipv6 の ext-header chain や srv6 の segment list は **protocol 内部の可変長構造** で、 chain quantifier (= 外側の繰り返し) ではなく、 protocol の `parser` block の state machine として表現される (前記事参照)。

codegen は state ごとに basic block を emit、 transition select は tuple-match cascade に lower、 self-loop (= 同じ state に戻る transition) は再び bpf_loop callback に展開する。

```
state start:
  (entry dispatch)
  StoreMem R10, layerEntrySlot, R4, DWord  ; 子の dispatch 用に layer entry を保存
  extract primary header
  R4 += hs
  transition select(...) {
    case (val): Ja state_X
    default: Ja dslReject
  }

state parse_ext:    ; self-loop あり
  noop landing (state label)
  extract aux
  R4 += per_iter_size
  variable trail (knownVariableTails で advance)
  transition select(...) {
    self: bpf_loop callback で iter
    other: Ja state_X
    default: Ja done
  }
```

self-loop している state は callback subprogram に展開、 main が bpf_loop を呼んで反復する。 select の各 case は 1 つの byte / tuple を比較する compare cascade として lower される。

`_` wildcard (例: ipv6 の `(6, _): accept`) も `mv.IsWildcard` 分岐で自然に対応。 tuple key は `selectAddr` という abstraction で「key の byte をどこから読むか」 (R4-relative or stack stash) を統一して扱う。

実装: `pkg/kunai/codegen/parser_machine.go` (~700 LOC)

## Verifier 通過テクニック

verifier は kunai codegen の最大の対戦相手で、 通すための小細工が多数:

### 1. BSwap 回避 (上述)

BPF_END byte-swap family + compile-time const swap で BSwap 命令を回避。 古い kernel との互換性を保つ。

### 2. Scalar narrowing と bounds check の配置

aux header stack の dynamic index `srv6.segments[srv6.last_entry]` の codegen で、 verifier が `last_entry` の値域を `< 8` (capacity) に narrow できるよう、 `JGE.Imm R3, capacity, fail` を index load の直後に出す。 narrow を逃すと後続の `R3 * elem_size` で値域不明になり LDX が拒否される。

```
LDX.B R3, [R0 + R4 + last_entry_offset]   ; index byte load
JGE.Imm R3, 8, dslReject                  ; ← narrow 必須、 verifier がこの後 R3 < 8 と推論
Mul.Imm R3, 16                            ; * elem_size = 16 byte
Add.Imm R3, offsetInLayer
Add.Reg R3, R4
Mov.Reg R5, R0
Add.Reg R5, R3                            ; R5 = element address
LDX.DW R3, [R5 + 0]                       ; field load
```

verifier は `JGE` から `R3 < 8` を伝播し、 multiply 後に `< 128` と narrow する。 後の LDX が「scratch 内の有効な範囲」と判定される。

### 3. layer-entry slot anchor (variable layout layer の child dispatch)

`HasVariableLayout()` な layer (= parser machine / HDRLEN / FlagTrigger を持つ) は R4 が advance しまくるので、 子の dispatch が親の primary header を読みたいとき R4 - parentHS では届かない。 解決: layer 入場時に R4 を fp の slot (`bpfLoopCtxLayerEntrySlot`) に保存し、 子は slot から load する。

```
[parent layer entry (variable layout の場合)]
StoreMem R10, layerEntrySlot, R4, DWord
[primary extract + R4 advance + variable trail で R4 += unknown bytes]
[next layer の dispatch]
LoadMem R3, R10, layerEntrySlot, DWord  ; ← parent の primary header start
Add.Reg R3, R0
LDX.W R3, [R3 + dispatch_field_offset]
JNE.Imm R3, expected, dslReject
```

slot は再利用される (per-layer)、 step 順序は load-bearing: **子の dispatch (= slot を read) が、 子の slot 上書き (= step 3) よりも前** に来る必要がある。 詳細は `parser_machine.go::emitState` の slot lifecycle コメント (line 108-128)。

### 4. parser-block self-validation の boundary 命令ゼロ

Part D 後の `DispatchSelfValidating` は **boundary に何も emit しない**。 親が dispatch field を持たず子が parser block で自己検証する場合、 codegen は genDispatch の switch case で `nil, nil` を返すだけ。 検証は parser machine 内の transition select が runtime に処理する。

これは「子が valid であることを runtime に確認する」 cost を boundary から parser machine 内部に移すという設計選択。 per-occurrence cost は ~3-5 BPF insn 増えるが、 全 chain 累積でも 1M instr cap の <0.001% で実害なし、 verifier path explosion 影響もなし。

## まとめ — 連載 3 部作の総括

3 記事を通して見てきた kunai の特徴:

| 層 | 設計選択 | 効果 |
|---|---|---|
| **DSL frontend** (記事 2) | lexer の value mode、 precedence climbing、 contextual keywords、 PositionedError の inner-most-wins | user-facing UX、 line:col 保持エラー、 後方互換な機能追加 |
| **Vocabulary** (記事 1, 2) | P4-16 strict subset、 命名規約による declarative metadata、 parser-block 自己検証 | 新 protocol が 1 ファイル drop、 vocab は self-contained |
| **Codegen** (本記事) | target-agnostic ABI、 chain quantifier の 3 戦略、 BSwap 回避、 layer-entry slot | 古い kernel 互換、 host adapter の自由度、 verifier 通過 |

kunai codegen の核心は **verifier との対戦**。 boundary check の位置 / scalar narrowing / register reload / scratch buffer 経由のパケット参照、 全てが「verifier が通る形」に最適化された結果。 122 commits の積み上げの大部分はこの最適化で、 細かいテクニックはコード上の `// verifier rejects ...` コメントとして散らばっている。

3 記事で **DSL → AST → IR → BPF** の流れを総覧したが、 まだ書いていない領域も多い:

- **dsltest harness** — gopacket で組んだフレームを実 BPF として load + `BPF_PROG_TEST_RUN` で挙動 gating する仕組み
- **vimto kernel matrix** — 6.1 / 6.6 / 6.12 で BPF プログラムが load 通過するかを QEMU で検証する CI
- **`make p4c-check`** — bundled `.p4` ファイルが本物の P4-16 構文として valid か Docker p4c で gating

これらは Test infrastructure の deep-dive として別シリーズで扱ってもいい。 packet filter library を 1.0 に向けてどう品質保証するかの実例として面白い領域。

連載お読みいただきありがとう。 kunai は [xdp-ninja](https://github.com/takehaya/xdp-ninja) の default filter syntax として実 packet capture に使えるので、 試してみてほしい。 vocab 追加 (1 ファイル) も歓迎。
