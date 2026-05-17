# DSL 文法定義

xdp-ninja の DSL は **filter 式 DSL** と **p4lite vocab DSL** の 2 言語で構成される。本ドキュメントは両者の formal EBNF と、各 production rule に対応する parser 関数 / 例文を載せる。

文法を変更したらこのドキュメント + 該当 parser コード + (将来) `pkg/kunai/parser/grammar_test.go` の例文表を **同時更新** する規律でメンテする。

記法は W3C EBNF 風:
- `A ::= B` 定義
- `A | B` 選択
- `A?` 0 or 1
- `A*` 0 回以上
- `A+` 1 回以上
- `(A B)` グループ
- `'literal'` リテラル
- `[...]` 文字クラス

---

## 1. Filter 式 DSL

CLI に `<expr>` (位置引数) で渡される一行式。DSL が default。`--cbpf` で legacy tcpdump 構文に切替。

### 1.1 Top-level

```ebnf
filter         ::= layer-chain where-clause? capture-clause*
layer-chain    ::= layer ('/' layer)*
where-clause   ::= 'where' or-expr
capture-clause ::= 'capture' capture-spec ('where' or-expr)?
```

| Production | parser | 例文 (accept) | 例文 (reject) |
|---|---|---|---|
| `filter` | `parser.go::parseFilter` | `eth/ipv4/tcp` | `(空文字列)` |
| `layer-chain` | `layer.go::parseLayerChain` | `eth/ipv4/tcp` | `eth//tcp` (空 layer) |
| `where-clause` | `where.go::parseWhereClause` | `... where tcp.dport == 443` | `... where` (空 expr) |
| `capture-clause` | `capture.go::parseCaptureClause` | `... capture headers+64` | `... capture` (空 spec) |

### 1.2 Layer

```ebnf
layer          ::= layer-atom quantifier? predicate*
layer-atom     ::= proto-name ('@' label)?
                 | '(' layer ('|' layer)+ ')'        (* alternation *)
proto-name     ::= [a-z] [a-z0-9_]*
label          ::= [a-zA-Z_] [a-zA-Z0-9_]*
quantifier     ::= '?' | '+' | '*' | '{' INT '}' | '{' INT ',' INT '}'
```

| Production | parser | 例文 |
|---|---|---|
| `layer` | `layer.go::parseLayerItem` | `ipv4@outer[ttl==64]` |
| `layer-atom` (proto) | `layer.go::parseProtoLeaf` | `ipv4@outer` |
| `layer-atom` (alt) | `layer.go::parseLayerAltGroup` | `(vlan\|qinq)` |
| `quantifier` | `layer.go::parseQuantifier` / `parseQuantRange` | `?` / `+` / `{1,4}` |

**MVP 制約 (resolver / codegen が enforce)**:
- Alternation は alt 数 2-4、全 alt が同じ header size、ネスト不可、先頭 layer に置けない、quantifier 不可
- `?` / `*` は最初の layer に置けない (親 dispatch を peek できないため)
- 1 protocol あたり最大 2 ラベル

### 1.3 Predicate

```ebnf
predicate      ::= '[' field-path op value ']'
                 | '[' field-path 'in' value-list ']'      (* F7: integer 値の OR-chain *)
                 | '[' field-path 'has' flag-name ']'      (* F6 bitwise & で superseded *)
field-path     ::= field-name ('.' field-name)*            (* aux access: <aux>.<field> *)
field-name     ::= [a-z] [a-z0-9_]*
op             ::= '==' | '!=' | '<' | '<=' | '>' | '>='
value          ::= integer | ipv4 | ipv4-cidr | ipv6 | ipv6-cidr | mac
value-list     ::= '[' value (',' value)* ']'
flag-name      ::= [A-Z] [A-Z0-9_]*
integer        ::= '-'? ('0x' [0-9a-fA-F]+ | [0-9]+)        (* 値域: [-2^63, 2^64) *)
ipv4           ::= INT '.' INT '.' INT '.' INT              (* 各 INT: 0..255、zero-prefix 拒否 *)
ipv4-cidr      ::= ipv4 '/' INT                             (* INT: 0..32、host bits ゼロ必須 *)
ipv6           ::= (* RFC 4291 形式、zone id (%xxx) 拒否、bracket 拒否 *)
ipv6-cidr      ::= ipv6 '/' INT                             (* INT: 0..128、host bits ゼロ必須 *)
mac            ::= [0-9a-fA-F]{2} (':' [0-9a-fA-F]{2}){5}   (* colon 区切り 6 octet *)
```

| Production | parser | 例文 |
|---|---|---|
| `predicate` (cmp) | `predicate.go::parsePredicate` | `[dport==443]`, `[src!=fe80::1]`, `[opt.next_ext == 0]` |
| `predicate` (in) | `predicate.go::parsePredicate` (`PredIn` branch) | `[dport in [80, 443]]` *(codegen reject)* |
| `predicate` (has) | `predicate.go::parsePredicate` (`PredHas` branch) | `[flags has SYN]` *(codegen reject)* |
| `field-path` (1-part) | `predicate.go::parseFieldPath` | `dport` / `src` |
| `field-path` (2-part = aux) | `predicate.go::parseFieldPath` | `opt.next_ext` (gtp の auxiliary header field) |

**Op 仕様**:
- `==` / `!=`: 全 value 型で動く
- `<`, `<=`, `>`, `>=`: 整数のみ (IP / MAC は意味的に不可)

**CIDR 特例**:
- `/0 ==` → 命令ゼロ (常に match)
- `/0 !=` → `Ja dsl_reject` (常に miss)
- `/32` (v4) / `/128` (v6) → host match に collapse
- **host bits 非ゼロは parse-time reject**: `10.0.0.5/24` は不可 (`10.0.0.0/24` を要求)。`10.0.0.5/30` のような boundary 不一致もすべて reject。エラーメッセージで `network would be 10.0.0.4/30` 形で誘導 (型仕様: [`dsl-types.md §4.5`](./dsl-types.md#45-cidr-リテラル))

**Bracket aux predicate**:
- `proto[<aux>.<field> op value]` で auxiliary header の field を読む
- 例: `gtp[opt.next_ext == 0]` (= GTP-U の opt block で next_ext == 0)
- gating 付き aux (GTP の opt 等) は parser machine の state graph から「extract される条件」を resolver が逆算して codegen が gate emit
- gate fail (= aux 未抽出) は predicate false (= packet reject)
- aux header stack (`gtp.exts`, `srv6.segments` 等) は bracket 内では index 必須、または `where any/all(...)` で量化

### 1.4 Where 節

```ebnf
or-expr        ::= and-expr (('or' | '||') and-expr)*
and-expr       ::= not-expr (('and' | '&&') not-expr)*
not-expr       ::= ('not' | '!') not-expr | atom
atom           ::= '(' or-expr ')'
                 | bool-atom                                  (* bare Bool: tcp.syn / gtp.opt.exists / true *)
                 | action-atom
                 | quant-atom
                 | cmp-expr                                   (* literal allowed on either side *)
bool-atom      ::= bool-literal | aux-exists | field-ref      (* Int<N> field also coerces to Bool here *)
bool-literal   ::= 'true' | 'false'
aux-exists     ::= field-ref '.' 'exists'
action-atom    ::= 'action' op action-value
                 | action-value op 'action'                   (* symmetric: XDP_DROP == action *)
action-value   ::= ident                                      (* host-registered action name; see below *)
quant-atom     ::= ('any' | 'all') '(' or-expr ')'
cmp-expr       ::= cmp-operand op cmp-operand
cmp-operand    ::= arith-expr | network-literal
arith-expr     ::= arith-term (('+' | '-' | '|' | '^') arith-term)*
arith-term     ::= arith-factor (('*' | '/' | '%' | '&' | '<<' | '>>') arith-factor)*
arith-factor   ::= ('-')? integer | field-ref | '(' arith-expr ')'
field-ref      ::= ident index? ('.' ident index?)*           (* see field-ref shapes below *)
index          ::= '[' (integer (':' integer)? | field-ref) ']'
                                                                (* `[N]` = aux stack static index *)
                                                                (* `[lo:hi]` = bit-slice; half-open, bit 0 = MSB; see dsl-types.md §3.4 *)
                                                                (* `[<field-ref>]` = aux stack dynamic index *)
network-literal ::= ipv4 | ipv4-cidr | ipv6 | ipv6-cidr | mac
```

**`action` atom の意味**: `action` キーワードは DSL レベルで予約された atom で、**host が「パケット処理完了状態を保持する 1 register」を登録すればそれをフィルタ対象にできる** 機能。XDP host (`--mode exit`) が XDP retval を、将来の TC host adapter が TC verdict を、それぞれ「completion-state register」として `Capabilities.Action` 経由で expose する。右辺 `ident` は host が登録した name → int32 mapping を resolver が lookup する形なので、有効な名前集合は host が決める (DSL レベルのキーワードではない)。バンドルされた XDP host adapter は `XDP_ABORTED` / `XDP_DROP` / `XDP_PASS` / `XDP_TX` / `XDP_REDIRECT` を登録する。`action` 自体を「XDP 専用」から「完了状態 register」と一般化する semantic refactor は dsl-followups.md F15 参照。

**LHS / RHS 対称性**: `cmp-expr` は両 operand に network literal (IPv4/IPv6/MAC/CIDR) を許す (例: `443 == tcp.dport`、`10.0.0.0/24 == ipv4.dst`、`fe80::1 == ipv6.src`)。LHS literal の検出は parser が lexer 値モードで先読みする実装で、network literal が `==` / `!=` の前にあるときだけ確定する (ordered cmp は仕様上 reject)。型ルールは [`dsl-types.md §6.2`](./dsl-types.md#62-比較演算)。

**Bool atom**: `bool-atom` 位置に `field-ref` が来た場合、その field の型が `Int<N>` であれば Bool 文脈で `!= 0` として coerce される (C 風)。詳細は [`dsl-types.md §5.4`](./dsl-types.md#54-intn--bool-coercion-bool-文脈)。

`bool-atom` の三つの形を取り得る:

```
where true                              # bool-literal
where gtp.opt.exists                    # aux-exists (= aux header の抽出有無)
where tcp.dport                         # field-ref → Int<16>→Bool decay (`!= 0`)
where (tcp.dport == 443) == gtp.opt.exists   # parens 越しの bool-eq (iff)
```

`bool-atom` を `==` / `!=` で組合せた form は `WAtomBoolEq` (= iff / xor) として扱われる ([`dsl-types.md §6.2`](./dsl-types.md#62-比較演算))。

**field-ref shapes** (where 節で使えるフィールドアクセス):

| Shape | 例 | 意味 |
|---|---|---|
| `proto.field` | `tcp.dport` | primary header の field |
| `@label.field` | `outer.src` | 同 protocol が複数あるときラベルで識別 |
| `proto.aux.field` | `gtp.opt.next_ext` | 単発 aux header の field (auto gating) |
| `proto.aux.exists` | `gtp.opt.exists` | aux が抽出されたかの bool。`where gtp.opt.exists` のように bare bool atom として書ける |
| `proto.stack[N].field` | `srv6.segments[0].addr` | aux header stack の N 番目 (静的 index) |
| `proto.stack[proto.f].field` | `srv6.segments[srv6.last_entry].addr` | 動的 index (parent header field 由来) |
| `proto.options.NAME.field` | `tcp.options.MSS.value` | TCP/IPv4 option lookup (`<NAME>` は declared option) |

| Production | parser | 例文 |
|---|---|---|
| `or-expr` | `where.go::parseOrExpr` | `tcp.dport == 443 or tcp.dport == 80` |
| `and-expr` | `where.go::parseAndExpr` | `... and ipv4.ttl > 64` |
| `not-expr` | `where.go::parseNotExpr` | `not action == XDP_DROP` |
| `action-atom` | `where.go::parseActionAtom` | `action == XDP_DROP` (fexit only) |
| `quant-atom` | `where.go::parseQuantAtom` | `any(srv6.segments.addr == fc00::1)` |
| `arith-cmp` | `where.go::parseArithCmp` | `ipv4.total_length > 100` |
| `arith-expr` | `where.go::parseArithExpr` | `ipv4.total_length - 20` |
| `arith-factor` | `where.go::parseArithFac` | `outer.dst` / `0xc0a80101` / `tcp.options.MSS.value` |

**Quantifier 仕様** (`any` / `all`):
- `any(EXPR)` = ∃: EXPR 内の aux header stack 参照 (index 無し) を iteration 変数として扱い、stack の少なくとも 1 entry が EXPR を満たすとき true
- `all(EXPR)` = ∀: 全 entry が EXPR を満たすとき true
- iteration 変数は EXPR 内に **1 個だけ** stack 参照 (index 無し) を要求。複数 / 0 個は parse-time error
- 静的 unroll で stack capacity 回反復。SRv6 segments のような parent-count 系は per-iter `iter < parent.last_entry+1` の guard を入れて実 entry 数を超えた walk が誤 match しないよう保護
- 例: `where any(srv6.segments.addr == fc00::1)` (経路に該当 segment が含まれる)、`where all(vlan.id < 4096)` *(VLAN tag は chain なので別パス、現在 quantifier は aux stack 限定)*

**MVP 制約**:
- 算術ネスト最大 16 段 (`maxArithDepth`、 17 段以上 → ErrNotImplemented)
- `action == NAME` は host 側で `Capabilities.Action` map と `ActionFetcher` を提供しているときのみ。XDP の場合は **fexit attach (`--mode exit`)** で `pkg/kunai/host/xdp.FexitCapabilities()` 経由に有効化される
- 同 protocol が 2 段以上ある場合 `proto.field` だけだと ambiguous → `@label.field` 必須
- Aux predicate / stack index access / options lookup は wrapper protocol の中身を見るため (PR-A〜PR-D で landing)、protocol 側の `out` parameter declaration が必要 (詳細は `dsl-internals.md §6`)
- Aux 系の補助関数 / stack walk は bracket form (`proto[…]`) と where form の両方で動くが、CIDR / IPv4 / MAC literal predicate を aux field に対して書くのは現在 `ErrNotImplemented` (整数比較は OK)

### 1.5 Capture 節

```ebnf
capture-spec   ::= 'all'
                 | 'headers' ('+' INT)?
                 | 'absolute' INT
                 | IDENT ('+' INT)?                 (* layer label or protocol name *)
                 | field-ref (',' field-ref)*       (* parser only, codegen reject *)
```

| Production | parser | 例文 |
|---|---|---|
| `capture-spec` | `capture.go::parseCaptureSpec` | `all` / `headers` / `headers+64` / `inner+64` / `ipv4` / `absolute 96` |
| `CapToLayer` | `capture.go::parseCaptureIdent` | `inner` (label) / `ipv4` (proto, chain 内 1 つだけのとき) |
| `CapAbsolute` | `capture.go::parseCaptureIdent` (text == "absolute") | `absolute 96` |
| (CapFields) | `capture.go::parseCaptureSpec` (`CapFields` branch) | `tcp.flags, ipv4.dst` *(codegen reject)* |

**意味論**:
- `headers (+N)?` — chain 全 layer の固定 header 合計 + 任意 N bytes
- `<label_or_proto> (+N)?` — 指定 layer の末尾までを capture (+ 任意 N bytes)。label が複数候補にマッチする protocol 名なら ambiguous error。chain 内に存在しないと unknown error
- `absolute N` — 先頭固定 N bytes (chain shape に依存しない、quantifier 制約も無し)

**MVP 制約**:
- chain (`+`/`*`/`{n,m}`) を含む filter で `headers (+N)?` / `<label_or_proto> (+N)?` 不可 (静的に長さ確定不能、`absolute N` は影響なし)
- per-capture `where` は filter 全体の `where` と AND 合成
- `absolute` は capture 内 contextual keyword。label が `absolute` という名前と衝突する稀ケースは `absolute+0` で label 解釈を強制可能

---

## 2. p4lite Vocab DSL

`pkg/kunai/protocols/*.p4` の中身を parse する。P4-16 の **strict subset** ([P4-16 仕様](https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html))。

### 2.1 Top-level

```ebnf
file           ::= top-decl*
top-decl       ::= header-decl | const-decl | extern-decl | parser-decl
extern-decl    ::= 'extern' ident '{' opaque-body '}'        (* body skipped; vocab loader currently consumes only ParserCounter *)
```

| Production | parser | 例文 |
|---|---|---|
| `file` | `vocab/p4lite/parser.go::Parse` | (proto file 全体) |

**Reject keywords** (`vocab/p4lite/lexer.go::rejectedKeywords`): `action`, `table`, `control`, `apply`。`extern` は受理されるが本体は opaque-skip され、現在 vocab loader が認識する extern は **`ParserCounter`** のみ (B-5 / mechanism 8)。

### 2.2 Header

```ebnf
header-decl    ::= 'header' ident '{' field+ '}'
field          ::= 'bit' '<' INT '>' ident ';'
```

| Production | parser | 例文 |
|---|---|---|
| `header-decl` | `vocab/p4lite/parser.go::parseHeader` | `header eth_h { bit<48> dst; ... }` |

**制約**:
- `bit<N>`: N は 1..2048
- 全 field の bit 合計 = byte 倍数 (loader が enforce)
- primary header 名は `<filename>_h` (e.g. `mpls.p4` → `mpls_h`)
- field 型は `bit<N>` のみ。`int<N>` / `varbit<N>` / `bool` field は未対応 (P4 範囲内だが p4lite で除外)

### 2.3 Const

```ebnf
const-decl     ::= 'const' const-type ident '=' literal ';'
const-type     ::= 'bit' '<' INT '>' | 'bool'
literal        ::= integer | 'true' | 'false'
```

| Production | parser | 例文 |
|---|---|---|
| `const-decl` | `vocab/p4lite/parser.go::parseConst` | `const bit<16> IPV4_ETH_ETHERTYPE = 0x0800;` |

**Dispatch 命名規約** (loader が `vocab/loader.go` 内 regex で classify):

| 名前パターン | regex | 意味 |
|---|---|---|
| `<SELF>_<PARENT>_<FIELD>` | `reField` | 親の `field` がこの値のとき自分にディスパッチ |
| `<SELF>_<PARENT>_NO_CHECK = true` | `reNoCheck` | 検査なしで blind cast |
| `<SELF>_MAX_DEPTH = N` | `reMaxDepth` | bpf_loop chain の上限 (既定 8、最大 64) |
| `<SELF>_CHAIN_END_<FIELD> = V` | `reChainEnd` | chain 終了条件 (例: MPLS の s-bit) |

(legacy `<SELF>_<PARENT>_SANITY_<TYPE>` は廃止。代わりに parser block 内で `transition select(field) { v: accept; default: reject; }` 形式で **self-validating dispatch** を declare する。`reSanityName` regex は legacy 名を見つけたら明示エラーで弾くために残す)

**制約**:
- bit 幅 1..64 (uint64 で値を保持)
- 整数リテラルは 10進 / `0x` 16進のみ (`0b` バイナリ / `0o` 8進 / sized literal `8w0xff` は未対応)
- 式 (`A + 1`) や名前参照は不可

### 2.4 Parser fragment

```ebnf
parser-decl    ::= 'parser' ident '(' params ')' '{' counter-decl? state+ '}'
params         ::= param (',' param)*
param          ::= 'packet_in' ident
                 | 'out' type-ref ident
type-ref       ::= ident ('[' INT ']')?              (* header stack *)
counter-decl   ::= 'ParserCounter' '(' ')' ident ';'  (* mechanism 8: pc; declared once, scoped to the parser block *)
state          ::= 'state' ident '{' stmt* transition '}'
stmt           ::= ident '.' 'extract' '(' arg ')' ';'                                   (* primary / aux header extract *)
                 | 'pkt' '.' 'advance' '(' advance-arg ')' ';'                           (* mechanism 1 / 8 trailer skip *)
                 | ident '.' counter-op ';'                                              (* mechanism 8 ParserCounter ops: pc.set / pc.decrement *)
arg            ::= ident ('.' ident)?                (* ident or ident.next *)
advance-arg    ::= integer                                                               (* template C: literal byte count *)
                 | '(' '(' 'bit' '<' INT '>' ')' '(' 'hdr' '.' ident '-' integer ')' ')' '<<' integer
                                                                                          (* template A: ((bit<N>)(hdr.<F> - K)) << S — IPv4 IHL / TCP data_offset 系 *)
                 | '(' '(' 'bit' '<' INT '>' ')' lookahead-expr ')' '<<' integer
                                                                                          (* template B: lookahead-driven trailer (TCP TLV options length byte) *)
lookahead-expr ::= 'pkt' '.' 'lookahead' '<' 'bit' '<' INT '>' '>' '(' ')' ('[' INT ':' INT ']')?
                                                                                          (* MSB-first inclusive bit-slice *)
counter-op     ::= 'set' '(' counter-set-arg ')'                                         (* pc.set(<aux>.<field>) or pc.set(((bit<N>)(...)) << S) *)
                 | 'decrement' '(' counter-decrement-arg ')'                              (* pc.decrement(<INT>) or pc.decrement(<aux>.<field>) *)
counter-set-arg ::= ident '.' ident                                                       (* aux.field, e.g. ipv4.ihl *)
                 | '(' '(' 'bit' '<' INT '>' ')' '(' ident '.' ident '-' integer ')' ')' '<<' integer
                                                                                          (* same template-A shape as pkt.advance *)
counter-decrement-arg ::= integer | ident '.' ident                                       (* literal or aux.field *)
transition     ::= 'transition' transition-target ';'
transition-target ::= 'accept' | 'reject' | ident
                 | 'select' '(' key-list ')' '{' case+ '}'
key-list       ::= key (',' key)*
key            ::= ident ('.' ident)*                                                    (* dotted field path *)
                 | lookahead-expr                                                         (* pkt.lookahead<bit<N>>() (with optional bit-slice) as a select key *)
                 | ident '.' 'is_zero' '(' ')'                                            (* pc.is_zero() — bool match-key, paired with `true` / `false` cases *)
case           ::= case-keyset ':' transition-target ';'
case-keyset    ::= integer | 'true' | 'false' | '_' | 'default'
                 | '(' case-keyset (',' case-keyset)* ')'
```

| Production | parser | 例文 |
|---|---|---|
| `parser-decl` | `vocab/p4lite/parser.go::parseParser` | `parser EthParser(packet_in pkt, out eth_h hdr) {...}` |
| `state` | `vocab/p4lite/parser.go::parseState` | `state start { pkt.extract(hdr); transition accept; }` |
| `transition` | `vocab/p4lite/parser.go::parseTransition` | `transition select(eth.ethertype) { 0x0800: ipv4; default: reject; }` |

**制約**:
- 引数 direction は `packet_in` / `out` のみ (`in` / `inout` 未対応)
- statement は `obj.extract(target)` / `obj.extract(target.next)` / `pkt.advance(...)` / `pc.set(...)` / `pc.decrement(...)` のみ。`verify` / 代入文 / `if` / `else` などは未対応 (詳細は `vocab/p4lite/conformance_test.go::TestSubsetRejectsParserStatementsBeyondExtract`)
- `pkt.advance` template:
  - **A**: `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)` — primary header の field × scale で trailer 長を決める (IPv4 IHL、TCP data_offset)。詳細は internals §6.5 mechanism 1
  - **B**: `pkt.advance(((bit<N>)pkt.lookahead<bit<M>>()[lo:hi]) << S)` — wire 上の length byte を peek して advance (TCP TLV options)。詳細は §6.5 mechanism 7
  - **C**: `pkt.advance(<INT>)` — 固定 byte 数。`pkt.advance(8)` 等
- `pc.set(...)` は parser block の **start state** でのみ呼べる (counter は per-parser-invocation で 0 に初期化、変更は 1 回限り)
- `pc.decrement(N)` / `pc.decrement(<aux>.<field>)` は self-loop 反復毎に呼ぶ。zero に到達した時点で `select(pc.is_zero())` の `true` ケースが発火
- `select` case は整数 / `true`/`false` (1-key bool match の場合) / `_` / `default` / tuple のみ。mask (`val &&& mask`) / range (`a..b`) / 名前参照は未対応

**convention**: bundled vocab は固定 size protocol (vlan / udp / icmp 等) でも常に `parser <Proto>Parser(...) { state start { pkt.extract(hdr); transition accept; } }` の trivial block を declare する。loader は `isTrivialMachine` で同 shape を検出して `ParseStateMachine = nil` に集約する (legacy fixed-size codegen path)。block の有無で生成 BPF は変わらないが、全 vocab が同じ「header + const + parser block」3 段構成になり、`make p4c-check` も自然に通る。

### 2.5 例文ファイル

最小 vocab 例 (`pkg/kunai/protocols/eth.p4` 抜粋):

```p4
header eth_h {
    bit<48> dst;
    bit<48> src;
    bit<16> ethertype;
}

const bool ETH_MPLS_NO_CHECK = true;

parser EthParser(packet_in pkt, out eth_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
```

---

## 3. メンテナンス規約

文法の変更を入れるときは以下を **同じ PR で**:

1. 該当 EBNF rule の更新 (本ファイル)
2. parser 関数の修正 (`pkg/kunai/parser/` または `pkg/kunai/vocab/p4lite/`)
3. 例文表 (本ファイルの「例文」列) の更新
4. 型に関わる変更なら [`dsl-types.md`](./dsl-types.md) も更新
5. (将来) `pkg/kunai/parser/grammar_test.go` の例文 table 更新 — accept / reject 各 1 ケース以上

drift 検知は CI で grammar_test が走ることで担保される予定 (現状は手動レビュー)。

---

## Chain root convention

DSL の `layer-chain` は grammar 上 root を制約しないが、 operational semantic としては:

- Ethernet 経由の packet を XDP/TC で受け取る前提 → chain は **`eth/...` で始める**
- VLAN/QinQ stacking なら `eth/(vlan|qinq)/...`
- VXLAN inner なら `eth/ipv4/udp/vxlan/eth/...` (outer + inner)

例外:
- `--mode tc-entry` の clsact なら入り口で既に L2 解析済の場合あり、 短い chain で OK
- 自前 testing で特定 protocol だけ codegen 確認したい時 (vocab 学習目的) は短 chain も valid

短 chain (root が `eth` 以外) は resolver で warning が出るが compile は通る。

---

## 4. 参考

- [P4-16 v1.2.5 公式仕様](https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html) (BNF: G "Appendix: P4 grammar")
- [p4c parser grammar](https://github.com/p4lang/p4c/blob/main/frontends/parsers/p4/p4parser.ypp)
- [`dsl-usage.md`](./dsl-usage.md) — エンドユーザー向けガイド (本ドキュメントのカジュアル版)
- [`pkg/kunai/vocab/p4lite/conformance_test.go`](../../pkg/kunai/vocab/p4lite/conformance_test.go) — p4lite が拒否する P4-16 構文を pin する test (subset boundary の正規定義)
