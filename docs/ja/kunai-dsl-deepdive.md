# kunai DSL deep-dive: lexer / parser / resolver の実装

> [前記事](./kunai-overview-article.md) では kunai 全体の設計思想を扱いました。本稿では DSL one-liner が AST → IR になるまでの frontend (lexer / parser / resolver) を深く読みます。BPF codegen は別記事に譲ります。

## 全体像と本稿の対象範囲

```
DSL one-liner ─→ lexer ─→ tokens ─→ parser ─→ AST ─→ resolver ─→ IR ─→ codegen ─→ BPF
                ───────────  ←─ 本稿が扱うのはこの範囲 ─→  ────────────────
```

DSL は具体的には次のような文法です。

```
LayerChain WhereClause? CaptureClause?

LayerChain    := Layer ('/' Layer)*
Layer         := ProtoName ('@' Label)? Quantifier? Predicates?
              |  '(' Layer ('|' Layer)+ ')' Quantifier?
Quantifier    := '?' | '+' | '*' | '{' Int (',' Int)? '}'
Predicates    := '[' Predicate (',' Predicate)* ']'
Predicate     := AuxFieldPath '==' Value | AuxFieldPath
WhereClause   := 'where' WhereExpr
CaptureClause := 'capture' CaptureSpec
```

formal な BNF は `docs/ja/dsl-grammar.md` にあります。本稿はそれを実装側から眺めます。

## Lexer: 識別子 mode と value mode の切り替え

DSL の lexer は通常の C 系 lexer と違って state-aware に書かれています。切り替えの肝は次の事実です。

- 通常時、`192.168.1.1` のような token は数字 → ドット → 数字 → ドットの並びで連続するので、通常の lexer ルール (`[0-9]+` / `[A-Za-z_][A-Za-z0-9_]*` / 句読点) では 7 token に分割されます。
- しかし semantic としては `192.168.1.1` は 1 つの IPv4 literal です。

そこで kunai の lexer は `==` `!=` `<` `>` `in` といった compare operator の直後に来る token を value mode で読みます。value mode では識別子・整数・IP literal・MAC literal・hex literal・CIDR を atomic token として吸い取ります。

```
where ipv4.src == 192.168.1.0/24
                 ^^^^^^^^^^^^^^^^
                 value mode で 1 token として lex
```

`==` を見ると lexer 側で次の token を value mode で読むフラグを立て、1 token 消費したら識別子 mode に戻ります。where IP literal 機能を後付けで追加したとき、value mode でマッチに失敗したら通常 mode に rewind する必要があったため、状態遷移は `pkg/kunai/lexer/lexer.go::Save / Restore` で saveable に保たれています。

トークン種は `pkg/kunai/lexer/token.go` にあります。

```
TokIdent  ('eth', 'ipv4', 'where', 'capture', 'and', 'or', 'not', 'in', 'any', 'all', ...)
TokInt    (10進 / 0x16進)
TokString (literal "abc")
TokIPv4 / TokIPv6 / TokCIDR4 / TokCIDR6 / TokMAC
TokSlash, TokDot, TokAt, TokQuestion, TokPlus, TokStar, TokLBrace, TokRBrace, ...
TokEq, TokNeq, TokLt, TokGt, TokLte, TokGte, TokIn
TokLParen, TokRParen, TokPipe, TokComma, TokSemi, TokColon
TokAny  ← any() / all() 量化詞用 (TokAll は capture 等で既存)
```

`where`、`capture`、`and`、`or`、`not`、`in`、`any`、`all` は contextual keywords として実装されています。`TokIdent` として lex され、parser 側で文脈によって判別されます。

## Parser: 再帰下降 + precedence climbing

parser は `pkg/kunai/parser/` 以下に置かれ、構文単位ごとにファイルが分かれています。

```
parser/
├── parser.go         entry point: Parse(expr, file, reservedLabels) → *ast.Filter
├── layer.go          chain (a/b/c)、 quantifier、 alternation parse
├── predicate.go      bracket [field==value] parse + field path
├── where.go          where 句 (and/or/not + arith + IP literal + any/all + action)
└── capture.go        capture clause (headers+N / label(+N)? / absolute N)
```

### 1. Chain 構文

```go
parseLayerChain → []*ast.Layer
parseLayer      → *ast.Layer
                  ├─ parseAlternation `(a|b|c)`
                  └─ parseSimpleLayer `proto[@label][quant][predicates]`
```

`/` で区切られた layer の list を作ります。各 layer の構造は次のとおりです。

```go
type Layer struct {
    Kind         LayerKind  // LayerProto or LayerAltGroup
    ProtoName    string     // "ipv4" 等 (LayerProto のみ)
    Alternatives []*Layer   // alt group の場合 (LayerAltGroup)
    Label        string     // "@inner" の "inner"
    Quant        QuantKind  // QuantOne / QuantOpt / QuantPlus / QuantStar / QuantRange
    RangeMin     int        // {n,m} の n
    RangeMax     int        // {n,m} の m
    Predicates   []*Predicate  // bracket 内の field == value 群
    Pos          Position
}
```

quantifier は `?` `+` `*` のいずれか、または `{n,m}` の range です。`{n}` (= `{n,n}`) も、上限を省略した `{n,}` (open upper bound、`RangeMax = -1`) も許可されます。

alternation `(a|b|c)` は layer-level の OR です。chain 中で IPv4 でも IPv6 でもよいという条件を 1 layer slot として扱えます。後の resolver で各 alt の dispatch const が agree することを要求します。これは MVP 制約で、bracket predicate は alt-group 単位で課されます。

### 2. Bracket predicate

`tcp[dport==443, src==10.0.0.0/8]` のような layer 修飾子です。predicate は `field == value` 形式で、equality のみをサポートし、bracket では bool 演算を書けません。field path は `<aux>[<index>].<field>` を許します。

```
tcp[dport == 443]
gtp[opt.next_ext == 0]                       # aux header の field
srv6[segments[0].addr == fc00::1]            # aux header stack の static index
```

bracket predicate は layer-local な検査で、codegen 上は layer の bounds check 直後に inline で emit されます。`where` 句との違いは次のとおりです。

- bracket は layer 個別の検査で、1 行が 1 箇所だけに当たり、dispatch check と同居します。
- where は chain 全体に対する論理式で、cross-layer 比較や複雑な論理を書けます。

### 3. Where 句 (precedence climbing)

`where (src == 10.0.0.0/8 or dst == 192.168.0.0/16) and dport == 443` のような boolean expression を読みます。precedence は次のとおりです。

```
3 (tightest): not, atom (arith / IP literal / parens / quantifier)
2:           and
1 (loosest): or
```

実装は `pkg/kunai/parser/where.go::parseWhereExpr` の precedence climbing です。atom は次の 5 形式です。

| atom | 例 |
|---|---|
| arith comparison | `outer.total_length == inner.total_length + 36` |
| IP / MAC / CIDR literal compare | `ipv4.src == 192.168.1.1`, `ipv4.dst == 10.0.0.0/8`, `eth.src == aa:bb:cc:dd:ee:ff` |
| `in` 演算 | `ipv4.dst in 10.0.0.0/8` (CIDR 包含) |
| quantifier 関数 | `any(srv6.segments.addr == fc00::1)`, `all(...)` |
| action atom | `action == XDP_DROP` (host capability dependent) |

IP literal compare は value mode が必要になる箇所で、`==` の右辺で value mode に切り替えます。lexer の `Save / Restore` を使って、value mode で literal を試し、失敗したら識別子 mode に戻して arith として読み直す backtracking が `parser/where.go` の `tryNetworkLiteral` に実装されています。

### 4. Capture clause

```
capture headers           # 全 layer の header を含めるサイズ
capture headers+128       # それ + 128 byte
capture <label>           # 特定 layer まで
capture <label>+N         # 同 + N byte
capture absolute 256      # 先頭 256 byte 固定
```

`absolute` は contextual keyword で、TokIdent として lex され parser で識別されます。label と同名の `absolute` を書きたい場合は `absolute+0` で逃せる、という gimmick も実装されています。

## Resolver: AST から IR へ

parser は AST を返しますが、まだ `eth` `ipv4` は文字列のままで、dispatch も仮の状態、label 解決も未着手です。resolver (`pkg/kunai/resolve/`) がこれを vocabulary と照合して resolved IR を作ります。

resolver の主要な仕事は次のとおりです。

### 1. Layer の vocab bind

```go
type LayerInstance struct {
    Spec        *vocab.ProtocolSpec  // ← ここで vocab が bind される
    Quant       ast.QuantKind
    RangeMin, RangeMax int
    Index       int                  // 同 protocol の何個目か (auto-assigned)
    Label       string               // "@inner" の解決済み
    Predicates  []*Predicate
    Dispatch    *DispatchChoice      // 親からの dispatch
    Alternation []*LayerInstance     // alt group の場合
    Pos         ast.Position
}
```

vocab bind は `r.vocab[al.ProtoName]` の単純な map 引きです。missing なら `unknown protocol "foo"` エラーになります。

### 2. Label table

`@inner` や `@outer` 等の label は次の 3 つで管理します。

- Explicit label (`ipv4@outer`) は user が指定する label です。
- Auto index (`ipv4#0`, `ipv4#1`) は同 chain で 2 個目以降の同 protocol に自動で振られます。
- Dual registration では explicit label と auto-index の両方を `LabelTable` に登録し、where 句から `outer.total_length` でも、同 protocol が 1 個だけなら `ipv4.total_length` でも参照できます。

label の collision detection は厳密で、`udp@ipv4` のような protocol 名と同名の label は禁止され、同名 label の重複も禁止されます。MVP として 1 protocol あたりの labeled instance は最大 2 個までです。これは `outer` / `inner` を想定したもので、SRv6 3 段は別途検討します。

### 3. Dispatch resolution

子 layer の親 layer への dispatch を解決します。選択肢は 3 つあります。

```go
type DispatchType int
const (
    DispatchField           // 親が next-protocol field を持つ (eth.ethertype == 0x0800)
    DispatchNoCheck         // 親が dispatch field を持たないが trust する (EoMPLS など)
    DispatchSelfValidating  // 親が dispatch field を持たないが、 子の parser block が自己検証する (ipv4 の version=4)
)
```

resolver は子 spec の `SelectDispatchConst(parentName)` method で Field / NoCheck の優先順位で探し、nil なら `spec.IsSelfValidating()` で子の parser block が自己検証可能かを query します。結果がすべて nil なら `no dispatch constant for "foo" under "udp"` エラーになります。

なお dispatch の alt group 対応は意外に難しいところです。`(ipv4|ipv6)/tcp` の場合、tcp は ipv4 と ipv6 両方の親を持ちえますが、resolver は `selectAltParentDispatch` で全 alt の dispatch const が type / field / value で agree することを要求します。TCP_IPV4_PROTOCOL=6 と TCP_IPV6_NEXT_HEADER=6 は値が一致するので OK です。

### 4. Field reference の resolution

`ipv4.total_length`, `gtp.opt.next_ext`, `srv6.segments[0].addr`, `tcp.options.MSS.value` といった field path は、resolver で IR の `FieldRef` に変換されます。

```go
type FieldRef struct {
    Layer *LayerInstance        // どの layer か
    Field *vocab.Field           // primary header 内の field metadata
    Aux   *AuxRef                // optional: aux header (gtp.opt 等)
}

type AuxRef struct {
    HeaderName    string
    OutParam      string         // parser block の out 引数名 ("opt", "exts", "segments", ...)
    OffsetInLayer int            // primary header 末尾からの byte offset
    HeaderSize    int            // 1 entry のサイズ
    FieldBitOff   int            // aux header 内の field bit offset
    FieldBitWidth int
    Stack         *StackIndex    // [N] / [proto.field] / iterator
    OwnerOption      *AuxLayout  // option aux 配下の stack の owner (option-walk 経路)
    OffsetAfterOwner int         // owner aux 末尾からの byte offset
    Gating        *AuxGating     // aux 本体が active か判定する条件 (E|S|PN bit 等)
}
```

aux ref については、parser block の `out` 引数として宣言された auxiliary header を vocab loader が分析して `AuxLayout` を populate し、resolver がそれを引いて FieldRef.Aux に詰めます。path は次の 6 形態です。

| 構文 | 意味 |
|---|---|
| `<layer>.<field>` | primary header の field |
| `<layer>.<aux>.<field>` | 単発 aux header の field (gtp.opt) |
| `<layer>.<aux>[N].<field>` | aux header stack の static index (srv6.segments[0]) |
| `<layer>.<aux>[<layer>.<field>].<field>` | aux header stack の dynamic index (srv6.segments[srv6.last_entry]) |
| `<layer>.options.<NAME>.<field>` | TCP / IPv4 option lookup (option-walk 経路) |
| `<layer>.options.<NAME>.<stack>[N].<field>` | option aux 配下の stack (tcp.options.SACK.blocks[0].left) |

各 path 形は `pkg/kunai/resolve/where.go` の resolver 関数群 (`resolveAuxField`, `resolveAuxStackField`, `resolveOptionField`, `resolveOptionStackField`) で個別に実装され、IR.FieldRef.Aux に対応する metadata を埋めます。

## Error reporting: PositionedError

DSL は user-input なので、タイポや type mismatch、`@label` 重複などでエラーが頻発します。そのとき、DSL one-liner の何文字目で何が起きたかを line:col 形式で出すことが UX 上重要です。

kunai は `*lexer.SyntaxError` という error 型を貫通させており、lexer / parser / resolver / codegen のどこで error が起きても position が保たれます。

```go
type SyntaxError struct {
    File    string
    Pos     ast.Position  // {Line, Col}
    Message string
    Hint    string
}
```

特に codegen 段階のエラー、例えば nibble sanity の値が 4 bit に収まらないといったものは、元の DSL 式のどの layer / field から来たかを `withPos(err, pos)` で wrap します。invariant は inner-most position wins です。

```go
func withPos(err error, pos ast.Position) error {
    if err == nil {
        return nil
    }
    var pe *PositionedError
    if errors.As(err, &pe) {
        return err  // 既に position 付きなら上書きしない
    }
    return &PositionedError{Pos: pos, Wrapped: err}
}
```

これにより、予想外のところで wrap されて enclosing layer の位置になってしまう事態を防ぎ、error を予測可能にしています。emit*Predicate のような最深部で wrap した error は、genLayer / genCondition の outer wrapper を抜けて main に到達するまで position を保ちます。

## 練習: 1 行 DSL の AST と IR を組み立てる

実例を次に示します。

```
eth/ipv4@outer/udp/gtp/ipv4@inner/tcp[dport==443] where outer.dst == inner.src
```

これがどういう AST / IR になるかを脳内で組み立ててみます。

AST (parsed) は次のようになります。

```
Filter
├─ Layers: [
│    Layer{Proto="eth"},
│    Layer{Proto="ipv4", Label="outer"},
│    Layer{Proto="udp"},
│    Layer{Proto="gtp"},
│    Layer{Proto="ipv4", Label="inner"},
│    Layer{Proto="tcp", Predicates: [Predicate{Field=FieldPath{"dport"}, Value=443}]},
│  ]
├─ Where: ArithCompare{
│    L: FieldPath{"outer", "dst"},
│    Op: ==,
│    R: FieldPath{"inner", "src"},
│  }
└─ Capture: nil
```

IR (resolved) は次のようになります。

```
Program
├─ Layers: [
│    LayerInstance{Spec=eth, Index=0},
│    LayerInstance{Spec=ipv4, Index=0, Label="outer", Dispatch=Field(IPV4_ETH_ETHERTYPE)},
│    LayerInstance{Spec=udp,  Index=0, Dispatch=Field(UDP_IPV4_PROTOCOL)},
│    LayerInstance{Spec=gtp,  Index=0, Dispatch=Field(GTP_UDP_DPORT)},
│    LayerInstance{Spec=ipv4, Index=1, Label="inner", Dispatch=SelfValidating},  ← gtp 後の ipv4 は parser-block 自己検証
│    LayerInstance{Spec=tcp,  Index=0, Dispatch=Field(TCP_IPV4_PROTOCOL),
│                              Predicates=[Predicate{Field=FieldRef{tcp, dport}, Op=Eq, Value=443}]},
│  ]
├─ Where: Condition{
│    Kind: WAtomArith,
│    Op:   CmpEq,
│    L:    ArithExpr{Field=FieldRef{ipv4_outer, dst}},
│    R:    ArithExpr{Field=FieldRef{ipv4_inner, src}},
│  }
└─ LabelTable: {"outer": layers[1], "inner": layers[4], "ipv4#0": layers[1], "ipv4#1": layers[4], ...}
```

注目点は次のとおりです。

1. inner ipv4 の dispatch は `SelfValidating` です。gtp は IPV4_GTP_* dispatch const を持ちませんが、ipv4 の parser block (`transition select(version) { 4: accept; ... }`) で自己検証されるので resolver が許可します。
2. Index は auto-assigned です。同 chain に ipv4 が 2 個あり、出現順に 0, 1 が振られます。explicit label と一緒に dual register されます。
3. field path の解決では、`outer.dst` は LabelTable["outer"] = layers[1] を引いて、`ipv4_h.dst` field の metadata を bind します。`inner.src` も同様です。

この IR が codegen に渡って BPF 命令列になります。ここから先は別記事で扱います。

## まとめ

DSL frontend の特徴は次のとおりです。

1. lexer の value mode は、IP literal 等の atomic token を読むために `==` の後に切り替わる lexer state です。backtracking 対応により、where 句の literal vs arith を後付けで追加できました。
2. parser は構文ごとにファイルを分離し、layer / predicate / where / capture を独立 module にしています。boolean 演算は precedence climbing で処理します。
3. resolver の 3 仕事は、vocab bind (1) / label table (2 個ルール + auto-index) / dispatch resolution (Field / NoCheck / SelfValidating fallback) です。
4. field path には 6 形態 (primary / aux / aux stack static / aux stack dynamic / option lookup / option 配下 stack) があり、resolver で吸収して IR の `FieldRef.Aux` に詰めます。
5. PositionedError は inner-most-wins で、codegen 深部で起きた error も DSL の line:col を保ったまま user に届きます。

このレイヤを cleanly に切ったおかげで、codegen は DSL syntax を知らずに IR だけを見れば仕事が済み、vocab loader は protocol metadata だけに専念できる、という modularity を獲得しています。

次回は codegen に踏み込む予定です。BPF instruction emission、chain quantifier の bpf_loop 展開、parser machine の state graph compilation、verifier 通過のテクニック (BSwap 回避 / scalar narrowing / bounds check 配置) などを扱います。
