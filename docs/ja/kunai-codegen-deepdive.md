# kunai codegen deep-dive: IR から BPF 命令列へ

> 連載 3 部作の最終回です。[overview](./kunai-overview-article.md) で全体像を、[DSL deep-dive](./kunai-dsl-deepdive.md) で frontend を扱いました。本稿は resolved IR から `cilium/ebpf` の `asm.Instructions` に lower する codegen に踏み込みます。ABI 契約 / chain quantifier の 3 戦略 / verifier 通過テクニックが主題です。

## codegen の責務

DSL frontend が担当するのは、各 layer が `*vocab.ProtocolSpec` に bind 済みで dispatch も field ref も解決済みの中間表現、すなわち IR を作るところまでです。ここから codegen は次の責務を持ちます。

- IR を `asm.Instructions` (cilium/ebpf 形式の BPF 命令列) に lower します。
- 各 layer 境界で verifier-safe な bounds check を必ず emit します。
- chain quantifier (`?`/`+`/`*`/`{n,m}`)、alternation `(a|b|c)`、parser machine、aux header read をすべて BPF instruction 列に変換します。
- 出力は target-agnostic で、2 レジスタ間のパケットウィンドウと数本のワーキングレジスタしか仮定しません。

target-agnostic であることが kunai codegen の重要な特徴で、XDP / tc / userspace BPF / tracing を host adapter で吸収する設計の根幹になります。

## ABI 契約、host とのレジスタ規約

codegen 出力は以下の規約を仮定します。詳細は `pkg/kunai/codegen/codegen.go` の package doc に記載されています。

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

R4 を offsetBase として使うのが kunai 特有のレジスタ用法です。各 layer の codegen は R4 を現在見ている layer の先頭 byte の offset として使い、layer ごとに `R4 += hs` で advance します。layer 内で field を読むときは `R0 + R4 + field_offset` でアドレスを算出します。

scratch buffer は、host adapter (`pkg/kunai/host/xdp/`) が per-CPU map に packet prefix をコピーした上で R0/R1 にセットします。直接 packet pointer を渡さないのは、bpf_loop callback への ctx 受け渡しを簡単にするためです。packet pointer のままでは、callback 内で `bpf_xdp_load_bytes` のような helper 経由のアクセスが必要になり煩雑になります。

## 1 layer の codegen テンプレート

`pkg/kunai/codegen/codegen.go::genStaticLayer` が単一 layer の標準形です。

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
    insns = append(insns, emitAdvance(hs))  // (5) R4 += hs (固定 prefix のみ)

    if len(layer.Spec.FlagTriggers) > 0 {
        flags := emitFlagTriggers(...)  // (6) GRE C/K/S 等の flag-gated optional fields
        insns = append(insns, flags...)
    }

    return insns, nil
}
```

可変長 trailer (IPv4 IHL / TCP data_offset 等) は genStaticLayer の責務ではなく、layer.Spec.HasVariableLayout() == true の場合に parser machine (`parser_state.go::emitState` → `parser_trail.go::emitVariableTrail*`) が parser block の `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)` template を解釈して advance を emit します。旧 `<SELF>_HDRLEN_*` const family の codegen path は B-2 PR-2 で retire 済みです。

この順序は verifier に対してクリティカルです。

- bounds check が最初です。bounds 通過前に LDX を出すと verifier が拒否します。
- dispatch は parent の field を見ます。親が advance 前なら R4 = parent_start、advance 後なら R4 = parent_end で、kunai は前者の状態で dispatch を出します。
- bracket predicate は dispatch の後です。親 layer のパケット bytes (= dispatch 元) は predicate には関係ありませんが、dispatch 失敗パスを優先するためこの順序にしています。
- layer-entry slot の保存は advance の前です。子の dispatch が親の primary header を読むとき R4 は変動しているので、fp の slot に layer entry offset を保存しておきます。
- flag-trigger は固定 prefix の advance 後です。trigger bit 評価時の load offset が hs に依存するためです。

## Predicate codegen における BSwap 回避と byte-swap constant

`tcp[dport == 443]` のような predicate を BPF にします。単純に見えますが、verifier-friendliness のための小細工がいくつか入っています。

### 1. byte-swap は const 側で処理する

eBPF の LDX はメモリを little-endian で読みますが、packet byte は network order (big-endian) です。単純比較するには runtime byte-swap が必要です。しかし `BSwap` 命令 (opcode `0xd7`) は kernel 6.6+ でしか使えず、古い kernel (5.17 / 6.1) でも動かしたいという事情があります。

解決策は、constant 側を compile time に byte-swap しておくことです。

```
LDX.HW R3, [R0 + R4 + 2]    ; tcp.dport を 16-bit load (LE 解釈)
JNE.Imm R3, byteSwap(443, 2), dslReject   ; const は事前に byte-swap (= 0xBB01)
```

これで runtime BSwap が不要になり、5.17+ の全 kernel で同じ instruction stream が動きます。`byteSwap()` は `pkg/kunai/codegen/codegen.go` にある単純なバイト反転 helper です。

multi-byte field (`==` で IPv4 アドレス、IPv6 アドレス、MAC など) の compare も同様で、const 側をすべて byte-swap してから比較します。IPv6 の 16 byte は前半 8 byte と後半 8 byte の 2 つの 64-bit 比較に、MAC の 6 byte は 4 + 2 の 2 比較に分解します。

### 2. CIDR は mask + value の pair で扱う

`ipv4.dst == 10.0.0.0/8` は次のようになります。

```
LDX.W R3, [R0 + R4 + 16]    ; ipv4.dst を 32-bit load
And.Imm R3, byteSwap(0xff000000, 4)   ; mask = /8 = 0xff000000、 byte-swap 済
JNE.Imm R3, byteSwap(0x0a000000, 4),  dslReject   ; value = 10.0.0.0、 byte-swap 済
```

`/0` (whole space) や `/32` (host-only) は境界条件として edge case 扱いになり、codegen 側で展開を最適化します。

### 3. NIBBLE は shift + compare で比較する

IPv4 version (= 上位 4 bit) のような nibble 比較は次のようになります。

```
LDX.B R3, [R0 + R4 + 0]    ; byte 0 を 1-byte load
RSh.Imm R3, 4              ; 上位 nibble を低位に
JNE.Imm R3, 4, dslReject   ; 4 (= IPv4) か?
```

これは Part D の SANITY 撤廃前の dispatch sanity check で使われていたパターンで、今は parser block の `transition select` に移行しています。

## Where 句の short-circuit emit

`(src == 10.0.0.0/8 or dst == 192.168.0.0/16) and dport == 443` のような boolean expression を扱います。kunai では precedence climbing により、IR は `Condition` node の and/or/not と atom からなる tree shape になっており、codegen は short-circuit emit で BPF にします。

```
or:  L が成立すれば全体成立 → R 評価 skip
and: L が失敗すれば全体失敗 → R 評価 skip + dslReject
not: 結果反転 (= success/fail label を入れ替える)
```

各 condition は固有の fail label と next label を取り、codegen は成功時に次の命令へ進む fall-through を多用してラベル数を減らします。`or` で left が成立すると共通の or-success landing に jump する、という pattern が多く使われます。

詳細は `pkg/kunai/codegen/where.go::genCondition` を参照してください。label を unique に振る (`dsl_or_succ_<n>` 等) ことで、同じ名前の label が衝突しないようにしています。

## Chain quantifier の 3 戦略

ここからが kunai codegen の知的密度の高い部分です。chain quantifier (`?`, `+`, `*`, `{n,m}`) と alternation `(a|b|c)` をどう lower するかを見ていきます。

### 戦略 1: 静的 unroll (m ≤ 4)

`mpls{1,4}` のような上限が小さい range quantifier は、各 iteration を inline 命令で展開します。N 回繰り返しなら N 個の `genStaticLayer` 出力を順番に concat します。各 iter で、次が同じ protocol かどうかを dispatch field で判定する peek をして、mismatch なら chain を抜けます。

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

cap が 4 である理由は verifier の path explosion です。BPF verifier は分岐の各 path を辿るので、unroll 数 × 分岐数で path 数が爆発します。m = 4 で十分実用的であり、5 以上は次の戦略 (bpf_loop) に切り替えます。

実装は `pkg/kunai/codegen/chain.go::genStaticChain` にあります。

### 戦略 2: bpf_loop callback (m > 4 / `+` / `*`)

`mpls+` のような上限が大きい、または無制限の quantifier は、1 回目の iteration を inline 命令に、2 回目以降を bpf2bpf subprogram (callback) に展開し、main 命令列が `bpf_loop` ヘルパで callback を最大 N 回呼びます。

これは kernel 5.17 で導入された `bpf_loop` ヘルパを使う設計で、verifier はこのループを bounded として正しく扱えるため、path explosion が起きません。

ctx layout (main の stack `fp[-128..-104]`) は次のとおりです。

```
fp[-128..-120)  offset (u64)         current R4
fp[-120..-112)  scratchStart (u64)   PTR_TO_MAP_VALUE
fp[-112..-104)  scratchEnd (u64)     PTR_TO_MAP_VALUE + snap length
fp[-104..-96)   layerEntry (u64)     parser-machine layer の primary header offset
```

main は ctx を作って `bpf_loop(max_iter, &cb_func, &ctx, 0)` を呼びます。

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

callback subprogram は標準の bpf_loop callback signature を持ちます。

```go
long callback(u32 idx, void *ctx)
```

中身は次のとおりです。

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

callback は bpf2bpf subprogram (`Output.Callbacks` フィールドに格納) として main の Return 直後に append されます。`LoadFunc` (PSEUDO_FUNC immediate) で関数ポインタを得ます。`btf.Func` metadata がついているので verifier が型情報を引けます。

実装は `pkg/kunai/codegen/bpfloop.go` にあります。

### 戦略 3: parser machine (protocol 内部の可変長)

ipv6 の ext-header chain や srv6 の segment list は protocol 内部の可変長構造で、前記事で述べたとおり、外側の繰り返しである chain quantifier ではなく protocol の `parser` block の state machine として表現されます。

codegen は state ごとに basic block を emit し、transition select は tuple-match cascade に lower し、同じ state に戻る transition である self-loop は再び bpf_loop callback に展開します。

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

self-loop している state は callback subprogram に展開され、main が bpf_loop を呼んで反復します。select の各 case は 1 つの byte / tuple を比較する compare cascade として lower されます。

ipv6 の `(6, _): accept` のような `_` wildcard も `mv.IsWildcard` 分岐で自然に対応します。tuple key は `selectAddr` という abstraction で、key の byte を R4-relative と stack stash のどちらから読むかを統一して扱います。

実装は `pkg/kunai/codegen/parser_state.go` (state walk root) + `parser_trail.go` (variable-trail) + `parser_select.go` (select tuple-key) + `parser_loop.go` (bpf_loop callback) にあり、元の 1 ファイルから機能境界で 4 分割されています。

## Verifier 通過テクニック

verifier は kunai codegen の最大の対戦相手で、通すための小細工が多数あります。

### 1. 前述のとおり BSwap を回避する

BPF_END byte-swap family + compile-time const swap で BSwap 命令を回避します。古い kernel との互換性を保ちます。

### 2. Scalar narrowing と bounds check を配置する

aux header stack の dynamic index `srv6.segments[srv6.last_entry]` の codegen では、verifier が `last_entry` の値域を `< 8` (capacity) に narrow できるよう、`JGE.Imm R3, capacity, fail` を index load の直後に出します。narrow を逃すと後続の `R3 * elem_size` で値域が不明になり、LDX が拒否されます。

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

verifier は `JGE` から `R3 < 8` を伝播し、multiply 後に `< 128` と narrow します。後の LDX が scratch 内の有効な範囲への load と判定されます。

### 3. variable layout layer の child dispatch を layer-entry slot anchor で支える

parser machine / HDRLEN / FlagTrigger を持つ `HasVariableLayout()` な layer は R4 が何度も advance するので、子の dispatch が親の primary header を読みたいとき R4 - parentHS では届きません。解決策として、layer 入場時に R4 を fp の slot (`bpfLoopCtxLayerEntrySlot`) に保存し、子は slot から load します。

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

slot は per-layer に再利用され、step の順序が重要です。子の dispatch (= slot を read) が、子の slot 上書き (= step 3) よりも前に来る必要があります。詳細は `parser_state.go::emitState` の slot lifecycle コメントを参照してください。

### 4. parser-block self-validation では boundary 命令をゼロにする

Part D 後の `DispatchSelfValidating` は boundary に何も emit しません。親が dispatch field を持たず子が parser block で自己検証する場合、codegen は genDispatch の switch case で `nil, nil` を返すだけです。検証は parser machine 内の transition select が runtime に処理します。

これは、子が valid であることを runtime に確認する cost を、boundary から parser machine 内部に移すという設計選択です。per-occurrence cost は ~3-5 BPF insn 増えますが、全 chain 累積でも 1M instr cap の <0.001% で実害はなく、verifier path explosion への影響もありません。

## まとめ、連載 3 部作の総括

3 記事を通して見てきた kunai の特徴をまとめます。

| 層 | 設計選択 | 効果 |
|---|---|---|
| DSL frontend (記事 2) | lexer の value mode、precedence climbing、contextual keywords、PositionedError の inner-most-wins | user-facing UX、line:col 保持エラー、後方互換な機能追加 |
| Vocabulary (記事 1, 2) | P4-16 strict subset、命名規約による declarative metadata、parser-block 自己検証 | 新 protocol が 1 ファイル drop、vocab は self-contained |
| Codegen (本記事) | target-agnostic ABI、chain quantifier の 3 戦略、BSwap 回避、layer-entry slot | 古い kernel 互換、host adapter の自由度、verifier 通過 |

kunai codegen の核心は verifier との対戦です。boundary check の位置、scalar narrowing、register reload、scratch buffer 経由のパケット参照のすべてが、verifier が通る形に最適化された結果です。122 commits の積み上げの大部分はこの最適化で、細かいテクニックはコード上の `// verifier rejects ...` コメントとして散らばっています。

3 記事で DSL → AST → IR → BPF の流れを総覧しましたが、まだ書いていない領域も多くあります。

- dsltest harness は、gopacket で組んだフレームを実 BPF として load し、`BPF_PROG_TEST_RUN` で挙動を gating する仕組みです。
- vimto kernel matrix は、6.1 / 6.6 / 6.12 で BPF プログラムが load を通過するかを QEMU で検証する CI です。
- `make p4c-check` は、bundled `.p4` ファイルが本物の P4-16 構文として valid かどうかを Docker の p4c で gating します。

これらは Test infrastructure の deep-dive として別シリーズで扱う余地があります。packet filter library を 1.0 に向けてどう品質保証するかの実例として面白い領域です。

連載をお読みいただきありがとうございました。kunai は [xdp-ninja](https://github.com/takehaya/xdp-ninja) の default filter syntax として実 packet capture に使えるので、ぜひ試してみてください。vocab 追加 (1 ファイル) も歓迎します。
