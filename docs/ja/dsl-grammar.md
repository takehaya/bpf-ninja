# DSL 文法定義

xdp-ninja の DSL は filter 式 DSL と p4lite vocab DSL の 2 言語で構成されます。本ドキュメントには、両者の formal EBNF と、各 production rule に対応する parser 関数 / 例文を載せています。

文法を変更したら、このドキュメントと該当 parser コード、さらに将来は `pkg/kunai/parser/grammar_test.go` の例文表を同時更新する規律でメンテナンスします。

記法は W3C EBNF 風で、次のとおりです。
- `A ::= B` 定義
- `A | B` 選択
- `A?` 0 or 1
- `A*` 0 回以上
- `A+` 1 回以上
- `(A B)` グループ
- `'literal'` リテラル
- `[...]` 文字クラス

## 1. Filter 式 DSL

CLI に位置引数 `<expr>` として渡される一行式です。default は DSL で、`--cbpf` を指定すると legacy tcpdump 構文に切り替わります。

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
quantifier     ::= '?' | '+' | '*' | '{' INT '}' | '{' INT ',' INT? '}'
```

| Production | parser | 例文 |
|---|---|---|
| `layer` | `layer.go::parseLayerItem` | `ipv4@outer[ttl==64]` |
| `layer-atom` (proto) | `layer.go::parseProtoLeaf` | `ipv4@outer` |
| `layer-atom` (alt) | `layer.go::parseLayerAltGroup` | `(vlan\|qinq)` |
| `quantifier` | `layer.go::parseQuantifier` / `parseQuantRange` | `?` / `+` / `{1,4}` |

resolver / codegen が enforce する MVP 制約は次のとおりです。
- Alternation は alt 数 2-4、先頭 layer に置けない、quantifier 不可、各 alt は親からの Field dispatch 必須 (NoCheck 不可)。ネストした group は flatten され、header size は alt 間で異なっていても構いません
- `?` / `*` は親 dispatch を peek できないため、最初の layer に置けない
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

Op の仕様は次のとおりです。
- `==` / `!=` は全 value 型で動きます。
- `<`, `<=`, `>`, `>=` は整数のみで、IP / MAC は意味的に不可です。

CIDR の特例は次のとおりです。
- `/0 ==` は命令ゼロになり、常に match します。
- `/0 !=` は `Ja dsl_reject` になり、常に miss します。
- v4 の `/32` と v6 の `/128` は host match に collapse します。
- host bits 非ゼロは parse-time で reject します。`10.0.0.5/24` は不可で、`10.0.0.0/24` を要求します。`10.0.0.5/30` のような boundary 不一致もすべて reject し、エラーメッセージで `network would be 10.0.0.4/30` の形に誘導します。型仕様は [`dsl-types.md §4.5`](./dsl-types.md#45-cidr-リテラル) を参照してください。

Bracket aux predicate の仕様は次のとおりです。
- `proto[<aux>.<field> op value]` で auxiliary header の field を読みます。
- 例えば `gtp[opt.next_ext == 0]` は、GTP-U の opt block で next_ext == 0 であることを表します。
- GTP の opt のような gating 付き aux では、parser machine の state graph から extract される条件を resolver が逆算し、codegen が gate を emit します。
- gate fail、つまり aux 未抽出の場合は predicate が false になり、packet は reject されます。
- `gtp.exts` や `srv6.segments` のような aux header stack は、bracket 内では index を必須とするか、`where any/all(...)` で量化します。

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

`action` キーワードは DSL レベルで予約された atom で、host がパケット処理完了状態を保持する 1 register を登録すれば、それをフィルタ対象にできる機能です。XDP host (`--mode exit`) が XDP retval を、将来の TC host adapter が TC verdict を、それぞれ completion-state register として `Capabilities.Action` 経由で expose します。右辺の `ident` は host が登録した name → int32 mapping を resolver が lookup する形なので、有効な名前集合は DSL レベルのキーワードではなく host が決めます。バンドルされた XDP host adapter は `XDP_ABORTED` / `XDP_DROP` / `XDP_PASS` / `XDP_TX` / `XDP_REDIRECT` を登録します。`action` 自体を XDP 専用から完了状態 register へ一般化する semantic refactor は dsl-followups.md F15 を参照してください。

LHS / RHS は対称です。`cmp-expr` は両 operand に IPv4/IPv6/MAC/CIDR の network literal を許します。例えば `443 == tcp.dport`、`10.0.0.0/24 == ipv4.dst`、`fe80::1 == ipv6.src` と書けます。LHS literal の検出は parser が lexer 値モードで先読みする実装で、network literal が `==` / `!=` の前にあるときだけ確定します。ordered cmp は仕様上 reject されます。型ルールは [`dsl-types.md §6.2`](./dsl-types.md#62-比較演算------) を参照してください。

`bool-atom` 位置に `field-ref` が来た場合、その field の型が `Int<N>` であれば、C 風に Bool 文脈で `!= 0` として coerce されます。詳細は [`dsl-types.md §5.4`](./dsl-types.md#54-intn--bool-coercion-bool-文脈) を参照してください。

`bool-atom` は次の三つの形を取り得ます。

```
where true                              # bool-literal
where gtp.opt.exists                    # aux-exists (= aux header の抽出有無)
where tcp.dport                         # field-ref → Int<16>→Bool decay (`!= 0`)
where (tcp.dport == 443) == gtp.opt.exists   # parens 越しの bool-eq (iff)
```

`bool-atom` を `==` / `!=` で組み合わせた form は `WAtomBoolEq` (= iff / xor) として扱われます ([`dsl-types.md §6.2`](./dsl-types.md#62-比較演算------))。

field-ref の shape、つまり where 節で使えるフィールドアクセスは次のとおりです。

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

`any` / `all` の quantifier 仕様は次のとおりです。
- `any(EXPR)` は ∃ にあたり、EXPR 内の index 無しの aux header stack 参照を iteration 変数として扱い、stack の少なくとも 1 entry が EXPR を満たすとき true になります。
- `all(EXPR)` は ∀ にあたり、全 entry が EXPR を満たすとき true になります。
- iteration 変数として、EXPR 内に index 無しの stack 参照を 1 個だけ要求します。複数または 0 個は parse-time error です。
- 静的 unroll で stack capacity 回反復します。SRv6 segments のような parent-count 系は、per-iter `iter < parent.last_entry+1` の guard を入れて、実 entry 数を超えた walk が誤 match しないよう保護します。
- 例えば `where any(srv6.segments.addr == fc00::1)` は、経路に該当 segment が含まれることを表します。`where all(vlan.id < 4096)` も書けますが、VLAN tag は chain なので別パスで、現在 quantifier は aux stack 限定です。

MVP 制約は次のとおりです。
- 算術ネストは最大 16 段 (`maxArithDepth`) で、17 段以上は ErrNotImplemented になります。
- `action == NAME` は、host 側で `Capabilities.Action` map と `ActionFetcher` を提供しているときのみ使えます。XDP の場合は fexit attach (`--mode exit`) で `pkg/kunai/host/xdp.FexitCapabilities()` 経由で有効化されます。
- 同 protocol が 2 段以上ある場合、`proto.field` だけでは ambiguous になるため `@label.field` が必須です。
- PR-A〜PR-D で landing した aux predicate / stack index access / options lookup は、wrapper protocol の中身を見るため、protocol 側の `out` parameter declaration が必要です。詳細は `dsl-internals.md §6` を参照してください。
- Aux 系の補助関数 / stack walk は bracket form (`proto[...]`) と where form の両方で動きますが、CIDR / IPv4 / MAC literal predicate を aux field に対して書くのは現在 `ErrNotImplemented` です。整数比較は可能です。

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
| `CapAbsolute` | `capture.go::parseCaptureIdent` (`text == "absolute"`) | `absolute 96` |
| (CapFields) | `capture.go::parseCaptureSpec` (`CapFields` branch) | `tcp.flags, ipv4.dst` *(codegen reject)* |

意味論は次のとおりです。
- `headers (+N)?` は、chain 全 layer の固定 header 合計に、指定があれば任意の N bytes を加えた範囲を capture します。
- `<label_or_proto> (+N)?` は、指定 layer の末尾までを、指定があれば任意の N bytes を加えて capture します。label が複数候補にマッチする protocol 名なら ambiguous error、chain 内に存在しなければ unknown error になります。
- `absolute N` は先頭固定の N bytes を capture します。chain shape に依存せず、quantifier 制約もありません。

MVP 制約は次のとおりです。
- chain (`+`/`*`/`{n,m}`) を含む filter では、静的に長さを確定できないため `headers (+N)?` / `<label_or_proto> (+N)?` は使えません。`absolute N` は影響を受けません。
- per-capture の `where` は filter 全体の `where` と AND 合成されます。
- `absolute` は capture 内の contextual keyword です。label が `absolute` という名前と衝突する稀なケースでは、`absolute+0` で label 解釈を強制できます。

## 2. p4lite Vocab DSL

`pkg/kunai/protocols/*.p4` の中身を parse します。[P4-16 仕様](https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html) の strict subset です。

### 2.1 Top-level

```ebnf
file           ::= top-decl*
top-decl       ::= header-decl | const-decl | extern-decl | parser-decl
extern-decl    ::= 'extern' ident '{' opaque-body '}'        (* body skipped; vocab loader currently consumes only ParserCounter *)
```

| Production | parser | 例文 |
|---|---|---|
| `file` | `vocab/p4lite/parser.go::Parse` | (proto file 全体) |

Reject keywords (`vocab/p4lite/lexer.go::rejectedKeywords`) は `action`, `table`, `control`, `apply` です。`extern` は受理されますが本体は opaque-skip され、現在 vocab loader が認識する extern は `ParserCounter` のみです (B-5 / mechanism 8)。

### 2.2 Header

```ebnf
header-decl    ::= 'header' ident '{' field+ '}'
field          ::= 'bit' '<' INT '>' ident ';'
```

| Production | parser | 例文 |
|---|---|---|
| `header-decl` | `vocab/p4lite/parser.go::parseHeader` | `header eth_h { bit<48> dst; ... }` |

制約は次のとおりです。
- `bit<N>` の N は 1..2048 です。
- 全 field の bit 合計は byte の倍数で、loader が enforce します。
- primary header 名は `<filename>_h` です。例えば `mpls.p4` なら `mpls_h` になります。
- field 型は `bit<N>` のみです。`int<N>` / `varbit<N>` / `bool` field は、P4 の範囲内ですが p4lite では除外しており未対応です。

### 2.3 Const

```ebnf
const-decl     ::= 'const' const-type ident '=' literal ';'
const-type     ::= 'bit' '<' INT '>' | 'bool'
literal        ::= integer | 'true' | 'false'
```

| Production | parser | 例文 |
|---|---|---|
| `const-decl` | `vocab/p4lite/parser.go::parseConst` | `const bit<16> IPV4_ETH_ETHERTYPE = 0x0800;` |

Dispatch 命名規約は次のとおりです。loader が `vocab/loader.go` 内の regex で classify します。

| 名前パターン | regex | 意味 |
|---|---|---|
| `<SELF>_<PARENT>_<FIELD>` | `reField` | 親の `field` がこの値のとき自分にディスパッチ |
| `<SELF>_<PARENT>_NO_CHECK = true` | `reNoCheck` | 検査なしで blind cast |
| `<SELF>_MAX_DEPTH = N` | `reMaxDepth` | bpf_loop chain の上限 (既定 8、最大 64) |
| `<SELF>_CHAIN_END_<FIELD> = V` | `reChainEnd` | chain 終了条件 (例: MPLS の s-bit) |

legacy の `<SELF>_<PARENT>_SANITY_<TYPE>` は廃止されました。代わりに parser block 内で `transition select(field) { v: accept; default: reject; }` 形式で self-validating dispatch を declare します。`reSanityName` regex は、legacy 名を見つけたら明示エラーで弾くために残しています。

制約は次のとおりです。
- bit 幅は 1..64 で、値は uint64 で保持します。
- 整数リテラルは 10 進と `0x` の 16 進のみです。`0b` バイナリ、`0o` 8 進、sized literal `8w0xff` は未対応です。
- `A + 1` のような式や名前参照は不可です。

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

制約は次のとおりです。
- 引数 direction は `packet_in` / `out` のみで、`in` / `inout` は未対応です。
- statement は `obj.extract(target)` / `obj.extract(target.next)` / `pkt.advance(...)` / `pc.set(...)` / `pc.decrement(...)` のみです。`verify` / 代入文 / `if` / `else` などは未対応です。詳細は `vocab/p4lite/conformance_test.go::TestSubsetRejectsParserStatementsBeyondExtract` を参照してください。
- `pkt.advance` の template は次の 3 種です。
  - template A の `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)` は、IPv4 IHL や TCP data_offset のように、primary header の field × scale で trailer 長を決めます。詳細は internals §6.5 mechanism 1 を参照してください。
  - template B の `pkt.advance(((bit<N>)pkt.lookahead<bit<M>>()[lo:hi]) << S)` は、TCP TLV options のように、wire 上の length byte を peek して advance します。詳細は §6.5 mechanism 7 を参照してください。
  - template C の `pkt.advance(<INT>)` は固定 byte 数で、`pkt.advance(8)` などと書きます。
- `pc.set(...)` は parser block の start state でのみ呼べます。counter は per-parser-invocation で 0 に初期化され、変更は 1 回限りです。
- `pc.decrement(N)` / `pc.decrement(<aux>.<field>)` は self-loop の反復毎に呼びます。zero に到達した時点で `select(pc.is_zero())` の `true` ケースが発火します。
- `select` case は、整数、1-key bool match の場合の `true`/`false`、`_`、`default`、tuple のみです。mask の `val &&& mask`、range の `a..b`、名前参照は未対応です。

convention として、bundled vocab は vlan / udp / icmp などの固定 size protocol でも、常に `parser <Proto>Parser(...) { state start { pkt.extract(hdr); transition accept; } }` の trivial block を declare します。loader は `isTrivialMachine` で同 shape を検出し、legacy fixed-size codegen path である `ParseStateMachine = nil` に集約します。block の有無で生成 BPF は変わりませんが、全 vocab が同じ header + const + parser block の 3 段構成になり、`make p4c-check` も自然に通ります。

### 2.5 例文ファイル

最小の vocab 例として、`pkg/kunai/protocols/eth.p4` の抜粋を示します。

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

## 3. メンテナンス規約

文法の変更を入れるときは、以下を同じ PR で行います。

1. 本ファイルの該当 EBNF rule の更新
2. `pkg/kunai/parser/` または `pkg/kunai/vocab/p4lite/` の parser 関数の修正
3. 例文表、つまり本ファイルの例文列の更新
4. 型に関わる変更なら [`dsl-types.md`](./dsl-types.md) も更新
5. 将来は `pkg/kunai/parser/grammar_test.go` の例文 table を accept / reject 各 1 ケース以上で更新

drift 検知は CI で grammar_test が走ることで担保される予定で、現状は手動レビューです。

## Chain root convention

DSL の `layer-chain` は grammar 上 root を制約しませんが、operational semantic としては次のとおりです。

- Ethernet 経由の packet を XDP/TC で受け取る前提では、chain は `eth/...` で始めます。
- VLAN/QinQ stacking なら `eth/(vlan|qinq)/...` とします。
- VXLAN inner なら、outer + inner で `eth/ipv4/udp/vxlan/eth/...` とします。

例外は次のとおりです。

- `--mode tc-entry` の clsact では、入り口で既に L2 解析済みの場合があり、短い chain で問題ありません。
- vocab 学習目的で、自前 testing として特定 protocol だけ codegen を確認したい時は、短 chain も valid です。

root が `eth` 以外の短 chain は resolver で warning が出ますが、compile は通ります。

## 4. 参考

- [P4-16 v1.2.5 公式仕様](https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html)。BNF は Appendix G の P4 grammar にあります。
- [p4c parser grammar](https://github.com/p4lang/p4c/blob/main/frontends/parsers/p4/p4parser.ypp)
- [`dsl-usage.md`](./dsl-usage.md) はエンドユーザー向けガイドで、本ドキュメントのカジュアル版です。
- [`pkg/kunai/vocab/p4lite/conformance_test.go`](../../pkg/kunai/vocab/p4lite/conformance_test.go) は p4lite が拒否する P4-16 構文を pin する test で、subset boundary の正規定義です。
