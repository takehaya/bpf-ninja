# kunai DSL deep-dive: lexer / parser / resolver の実装

> [前記事](./kunai-overview-article.md) では kunai 全体の設計思想を扱った。 本稿では DSL one-liner が AST → IR になるまでの **frontend (lexer / parser / resolver)** を深く読む。 BPF codegen は別記事に譲る。

## 全体像と本稿の対象範囲

```
DSL one-liner ─→ lexer ─→ tokens ─→ parser ─→ AST ─→ resolver ─→ IR ─→ codegen ─→ BPF
                ───────────  ←─ 本稿が扱うのはこの範囲 ─→  ────────────────
```

DSL は具体的には次のような文法:

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

formal な BNF は `docs/ja/dsl-grammar.md` に。 本稿はそれを実装側から眺める。

## Lexer: 識別子 mode と value mode の切り替え

DSL の lexer は通常の C 系 lexer と違って **state-aware** に書かれている。 切り替えの肝は次の事実:

- 通常時: `192.168.1.1` のような token は **数字 → ドット → 数字 → ドット …** で連続するので、 通常の lexer ルール (`[0-9]+` / `[A-Za-z_][A-Za-z0-9_]*` / 句読点) では 7 token に分割される
- しかし semantic としては `192.168.1.1` は **1 つの IPv4 literal**

そこで kunai の lexer は `==` `!=` `<` `>` `in` といった compare operator の **直後に来る token** を **value mode** で読む。 value mode では識別子・整数・IP literal・MAC literal・hex literal・CIDR を **atomic token** として吸い取る。

```
where ipv4.src == 192.168.1.0/24
                 ^^^^^^^^^^^^^^^^
                 value mode で 1 token として lex
```

`==` を見て lexer 側で「次の token は value mode で読む」フラグを立て、 1 token 消費したら識別子 mode に戻る。 状態遷移は `pkg/kunai/lexer/lexer.go::Save / Restore` で saveable に保たれている (where IP literal 機能を後付けで追加したときに、 value mode でマッチに失敗したら通常 mode に rewind する必要があった)。

トークン種は `pkg/kunai/lexer/token.go`:

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

`where`、 `capture`、 `and`、 `or`、 `not`、 `in`、 `any`、 `all` は **contextual keywords** として実装されている (`TokIdent` でレキシングされ、 parser 側で文脈で判別)。

## Parser: 再帰下降 + precedence climbing

parser は `pkg/kunai/parser/` 以下、 構文単位ごとにファイル分離:

```
parser/
├── parser.go         entry point: Parse(expr, file, reservedLabels) → *ast.File
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

`/` で区切られた layer の list を作る。 各 layer の構造:

```go
type Layer struct {
    Kind         LayerKind  // LayerSimple or LayerAltGroup
    ProtoName    string     // "ipv4" 等 (LayerSimple のみ)
    Alternatives []*Layer   // alt group の場合 (LayerAltGroup)
    Label        string     // "@inner" の "inner"
    Quant        Quant      // QuantOne / QuantOpt / QuantPlus / QuantStar / QuantRange
    RangeMin     int        // {n,m} の n
    RangeMax     int        // {n,m} の m
    Predicates   []*Predicate  // bracket 内の field == value 群
    Pos          Position
}
```

quantifier は `?` `+` `*` のいずれか、 または `{n,m}` の range。 `{n}` (= `{n,n}`) も許可。 `{n,}` はエラー (上限なしは `+` で表現)。

alternation `(a|b|c)` は **layer-level の OR**。 chain 中で「IPv4 でも IPv6 でも」を 1 layer slot として扱える。 後の resolver で各 alt の dispatch const が agree することを要求 (= MVP 制約、 bracket predicate は alt-group 単位で課す)。

### 2. Bracket predicate

`tcp[dport==443, src==10.0.0.0/8]` のような layer 修飾子。 predicate は `field == value` 形式 (= equality only、 bracket では bool 演算なし)。 field path は `<aux>[<index>].<field>` を許す:

```
tcp[dport == 443]
gtp[opt.next_ext == 0]                       # aux header の field
srv6[segments[0].addr == fc00::1]            # aux header stack の static index
```

bracket predicate は **layer-local な検査** で、 codegen 上は layer の bounds check 直後に inline で emit される。 `where` 句との違い:
- bracket: layer 個別、 1 行が 1 箇所だけに当たる、 dispatch check と同居
- where: chain 全体に対する論理式、 cross-layer 比較や複雑な論理を書ける

### 3. Where 句 — precedence climbing

`where (src == 10.0.0.0/8 or dst == 192.168.0.0/16) and dport == 443` のような boolean expression を読む。 precedence:

```
3 (tightest): not, atom (arith / IP literal / parens / quantifier)
2:           and
1 (loosest): or
```

実装は precedence climbing (`pkg/kunai/parser/where.go::parseWhereExpr`)。 atom は次の 5 形式:

| atom | 例 |
|---|---|
| arith comparison | `outer.total_length == inner.total_length + 36` |
| IP / MAC / CIDR literal compare | `ipv4.src == 192.168.1.1`, `ipv4.dst == 10.0.0.0/8`, `eth.src == aa:bb:cc:dd:ee:ff` |
| `in` 演算 | `ipv4.dst in 10.0.0.0/8` (CIDR 包含) |
| quantifier 関数 | `any(srv6.segments.addr == fc00::1)`, `all(...)` |
| action atom | `action == XDP_DROP` (host capability dependent) |

IP literal compare は **value mode** が要る箇所 (= `==` の右辺で value mode 切替)。 lexer の `Save / Restore` で 「value mode で literal を試す → ダメなら識別子 mode に戻して arith として読み直す」 backtracking が実装されている (`tryNetworkLiteral` in `parser/where.go`)。

### 4. Capture clause

```
capture headers           # 全 layer の header を含めるサイズ
capture headers+128       # それ + 128 byte
capture <label>           # 特定 layer まで
capture <label>+N         # 同 + N byte
capture absolute 256      # 先頭 256 byte 固定
```

`absolute` は **contextual keyword** (TokIdent として lex され parser で識別)。 label と同名の `absolute` を書きたい場合は `absolute+0` で逃せる、 という gimmick も実装されている。

## Resolver: AST から IR へ

parser が AST を返すが、 まだ `eth` `ipv4` は文字列のまま、 dispatch も仮、 label 解決も未着手。 resolver (`pkg/kunai/resolve/`) がこれを vocabulary と照合して **resolved IR** を作る。

resolver の主要な仕事:

### 1. Layer の vocab bind

```go
type LayerInstance struct {
    Spec        *vocab.ProtocolSpec  // ← ここで vocab が bind される
    Quant       ast.Quant
    RangeMin, RangeMax int
    Index       int                  // 同 protocol の何個目か (auto-assigned)
    Label       string               // "@inner" の解決済み
    Predicates  []*Predicate
    Dispatch    *DispatchChoice      // 親からの dispatch
    Alternation []*LayerInstance     // alt group の場合
    Pos         ast.Position
}
```

vocab bind は `r.vocab[al.ProtoName]` の単純な map 引き。 missing なら `unknown protocol "foo"` エラー。

### 2. Label table

`@inner`, `@outer` 等の label は次の 3 つで管理:

- **Explicit label** (`ipv4@outer`) — user 指定
- **Auto index** (`ipv4#0`, `ipv4#1`) — 同 chain で 2 個目以降の同 protocol に auto 振り
- **Dual registration** — explicit label + auto-index 両方を `LabelTable` に登録、 where 句から `outer.total_length` でも `ipv4.total_length` (1 個だけなら省略可) でも参照可能

label の **collision detection** は厳密で、 protocol 名と同名の label (`udp@ipv4` 等) は禁止、 同名 label の重複も禁止。 MVP として 1 protocol あたり最大 2 個の labeled instance まで (`outer` / `inner` を想定、 SRv6 3 段は別途検討)。

### 3. Dispatch resolution

子 layer の親 layer への dispatch を解決する。 4 つの選択肢:

```go
type DispatchType int
const (
    DispatchField           // 親が next-protocol field を持つ (eth.ethertype == 0x0800)
    DispatchNoCheck         // 親が dispatch field を持たないが trust する (EoMPLS など)
    DispatchSelfValidating  // 親が dispatch field を持たないが、 子の parser block が自己検証する (ipv4 の version=4)
)
```

resolver は `vocab.SelectDispatchConst(parentName)` で Field / NoCheck の優先順位で探し、 nil なら `spec.IsSelfValidating()` で子の parser block が自己検証可能か query する。 結果がすべて nil なら `no dispatch constant for "foo" under "udp"` エラー。

なお dispatch の **alt group 対応** が地味に難しい。 `(ipv4|ipv6)/tcp` の場合、 tcp は ipv4 と ipv6 両方の親を持ちうるが、 resolver は `selectAltParentDispatch` で「全 alt の dispatch const が type / field / value で agree する」 を要求する (= TCP_IPV4_PROTOCOL=6 と TCP_IPV6_NEXT_HEADER=6 が値一致するので OK)。

### 4. Field reference の resolution

`ipv4.total_length`, `gtp.opt.next_ext`, `srv6.segments[0].addr`, `tcp.options.MSS.value` といった field path は resolver で IR の `FieldRef` に変換される:

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
    Option        *OptionLookup  // tcp.options.MSS の lookup
    Gating        *AuxGating     // aux 本体が active か判定する条件 (E|S|PN bit 等)
}
```

aux ref は parser block の `out` 引数として宣言された auxiliary header を vocab loader が分析して `AuxLayout` を populate、 resolver がそれを引いて FieldRef.Aux に詰める。 4 段階の path:

| 構文 | 意味 |
|---|---|
| `<layer>.<field>` | primary header の field |
| `<layer>.<aux>.<field>` | 単発 aux header の field (gtp.opt) |
| `<layer>.<aux>[N].<field>` | aux header stack の static index (srv6.segments[0]) |
| `<layer>.<aux>[<layer>.<field>].<field>` | aux header stack の dynamic index (srv6.segments[srv6.last_entry]) |
| `<layer>.options.<NAME>.<field>` | TCP / IPv4 option lookup (option-walk 経路) |

各 path 形は `pkg/kunai/resolve/where.go` の resolver 関数群 (`resolveAuxField`, `resolveAuxStackField`, `resolveOptionField`) で個別に実装され、 IR.FieldRef.Aux に対応する metadata を埋める。

## Error reporting: PositionedError

DSL は user-input なので、 タイポやら type mismatch やら `@label` 重複やらでエラーが頻発する。 そのとき**「DSL one-liner の何文字目で何が起きたか」を line:col 形式で出す**ことが UX 上重要。

kunai は `*lexer.SyntaxError` という error 型を貫通させていて、 lexer / parser / resolver / codegen のどこで error が起きても position が保たれる:

```go
type SyntaxError struct {
    File string
    Pos  ast.Position  // {Line, Col}
    Msg  string
}
```

特に codegen 段階のエラー (例: 「nibble sanity の値が 4 bit に収まらない」) は、 元の DSL 式のどの layer / field から来たかを `withPos(err, pos)` で wrap する。 invariant は **「inner-most position wins」**:

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

これで予測可能な error: 「予想外のところで wrap されて enclosing layer の位置になる」 を防いでいる。 emit*Predicate のような最深部で wrap した error が、 genLayer / genCondition の outer wrapper を抜けて main に到達するまで position を保つ。

## 練習: 1 行 DSL の AST と IR を組み立てる

実例:

```
eth/ipv4@outer/udp/gtp/ipv4@inner/tcp[dport==443] where outer.dst == inner.src
```

これがどういう AST / IR になるか脳内で組み立ててみる。

**AST (parsed)**:

```
File
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

**IR (resolved)**:

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

注目点:

1. **inner ipv4 の dispatch が `SelfValidating`**: gtp は IPV4_GTP_* dispatch const を持たないが、 ipv4 の parser block (`transition select(version) { 4: accept; ... }`) で自己検証されるので resolver が allow
2. **Index が auto-assigned**: 同 chain に ipv4 が 2 個あり、 出現順に 0, 1 が振られる。 explicit label と一緒に dual register される
3. **field path の解決**: `outer.dst` は LabelTable["outer"] = layers[1] を引いて、 `ipv4_h.dst` field の metadata を bind する。 `inner.src` も同様

この IR が codegen に渡って BPF 命令列になる。 ここから先は別記事で。

## まとめ

DSL frontend の特徴:

1. **lexer の value mode**: IP literal 等の atomic token を読むため、 `==` 後に切り替わる lexer state。 backtracking 対応で where 句の literal vs arith を後付け追加できた
2. **parser は構文ごとにファイル分離**: layer / predicate / where / capture を独立 module に。 precedence climbing で boolean 演算
3. **resolver の 3 仕事**: vocab bind (1) / label table (2 個ルール + auto-index) / dispatch resolution (Field / NoCheck / SelfValidating fallback)
4. **field path の 5 形態**: primary / aux / aux stack static / aux stack dynamic / option lookup を resolver で吸収、 IR の `FieldRef.Aux` に詰める
5. **PositionedError の inner-most-wins**: codegen 深部で起きた error も DSL の line:col を保ったまま user に届く

このレイヤを cleanly 切ったおかげで、 codegen は IR だけ見れば仕事が済む (DSL syntax を知らなくてよい)、 vocab loader は protocol metadata だけに専念できる、 という modularity を獲得している。

次回は **codegen** に踏み込む予定: BPF instruction emission、 chain quantifier の bpf_loop 展開、 parser machine の state graph compilation、 verifier 通過のテクニック (BSwap 回避 / scalar narrowing / bounds check 配置) など。
