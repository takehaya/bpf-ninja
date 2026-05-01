# `pkg/kunai/` コード解説 (レビュー用ガイド)

xdp-ninja の DSL 実装 (`pkg/kunai/` 配下) を読むための内部ガイド。本書は **コードを読み下すための地図** として使う。ユーザ向け仕様は [`dsl-usage.md`](./dsl-usage.md)、formal な EBNF は [`dsl-grammar.md`](./dsl-grammar.md) にある。

合計 6060 行 (test 除く)、9 パッケージ。**外から内へ**たどると依存方向が綺麗に取れる構造。

## 全体像

```
                             cmd/xdp-ninja/main.go (--dsl)
                                   │
                                   ▼
                ┌────────────────────────────────────┐
                │ kunai.Compile(expr, caps)          │  pkg/kunai/compile.go (45 行)
                │  Lex → Parse → Resolve → Codegen   │
                └─┬──────┬──────────┬───────────┬────┘
                  │      │          │           │
                  ▼      ▼          ▼           ▼
              lexer/  parser/  resolve/    codegen/
                  │      │          │           │
                  └──────┴────┬─────┴───────────┘
                              ▼
                            ast/  ir/   ← 型定義のみ
                              ▲
                              │
                          vocab/ ← .p4 → ProtocolSpec
                              │
                              ▼
                         vocab/p4lite/ ← P4-16 subset parser
                              │
                              ▼
                        protocols/*.p4 (//go:embed)
                              │
                              ▼
                          dslvocab/ ← Bundled() の cache wrapper
```

依存方向は単方向 (循環なし)。leaf の `ast/` `ir/` `vocab/` から読むと積み上げが見える。

## パッケージごとのツアー (依存順、leaf → root)

### 1. `ast/` (270 行) — 純粋な型定義

`ast.go` が AST のルート型。`Filter` (= 1 つの `--dsl` 式に対応)、その下に `Layer[]` / `WhereExpr` / `CaptureClause[]`。`Predicate` / `WhereExpr` / `CaptureClause` 等の各 Sum 型は `kinds.go` の enum (`PredKind`, `WhereKind`, `CaptureKind`, `ValueKind`, `Quantifier`, `CmpOp`) で識別される。

**読みどころ**:
- `ast.go:8` のパッケージ doc に `Unsupported string` フィールドの意図が書いてある — parser が受理した「これから codegen でやる予定」(PredIn/PredHas/CapFields) を明示マークする仕掛け
- `value.go` — predicate 値の Sum 型 (`Int`, `V4 [4]byte`, `V6 [16]byte`, `MAC [6]byte`, `Prefix int` for CIDR)
- (本ブランチで `xdp.go` は撤去 — XDP 知識は `codegen/caps.go::XDPActions` + `XDPFexitFetcher` に host-supplied 形で外出し)

ここは型の倉庫なので **ロジックは無い**。

### 2. `lexer/` (593 行) — 2 モード切替トークナイザ

`lexer.go` が本体、`scanvalue.go` が IPv4/IPv6/MAC のリテラル parser、`token.go` が token kind の enum。

**核心 = 2 モード**:
- **structural mode** (`Lexer.Next()`) — `/`, `[`, `]`, `where`, `capture`, identifier 等の構文骨格を tokenize
- **value mode** (`Lexer.NextValue()`) — `[field==10.0.0.1]` の `10.0.0.1` のように、predicate 内の値だけを丸ごと scanvalue で読む。IPv4/IPv6/MAC が `/`, `:`, `.` を含むため、structural の `/` (chain separator) と区別する必要がある

**読み始め**: `lexer.go` のパッケージ doc → `Next()` → `NextValue()`。`scanvalue.go` は IPv6 RFC 4291 の `::` 短縮を処理しているので少し重い。

### 3. `parser/` (731 行) — 再帰下降 + precedence climbing

`parser.go` がエントリ + 共通ヘルパ、各文法部分は別ファイル:
- `layer.go` — layer chain (`/`)、quantifier (`?+*{n,m}`)、alternation (`(a|b)`)
- `predicate.go` — `[field op value]`、cmp/in/has の 3 形
- `where.go` — `where` 節。**precedence climbing** で or > and > not > arith
- `capture.go` — `capture all/headers/headers+N`

**読み始め**: `parser.go::parseFilter` → 各 `parse*` を辿る。再帰下降なので素直。`where.go::parseArithExpr/Term/Factor` は precedence climbing の典型形。

### 4. `vocab/` + `vocab/p4lite/` (約 1200 行)

2 階層に分かれる:
- **`vocab/p4lite/`** — `.p4` ファイル (P4-16 strict subset) を AST 化。`lexer.go` (319) + `parser.go` (589) + `types.go` (136) で完結。再帰下降。受理する構文の境界は `conformance_test.go` で pin されている (= subset の正規定義)
- **`vocab/`** — p4lite AST → `ProtocolSpec`。`loader.go::Load` がエントリ。`classifyConsts` が **正規表現 4 本**で const 名を分類:
  - `reField` (`<SELF>_<PARENT>_<FIELD>`)
  - `reSanity` (`<SELF>_<PARENT>_SANITY_<TYPE>`)
  - `reChainEnd` (`<SELF>_CHAIN_END_<FIELD>`)
  - `reMaxDepth` (`<SELF>_MAX_DEPTH`)
  - + NoCheck (`<SELF>_<PARENT>_NO_CHECK`、bool true)

**読みどころ**: `vocab/loader.go::classifyConsts` (文書化規約の本丸)、`vocab/model.go` (`ProtocolSpec` / `DispatchConst` の型定義、ここに `Type DispatchType {Field, Sanity, NoCheck}` がある)

### 5. `dslvocab/` (~30 行) — bundled vocab の cache wrapper

`Bundled()` だけ。`protocols/*.p4` を `//go:embed` で取り込み、`vocab.Load` 結果を `sync.Once` でキャッシュ。キャッシュしないと毎回パースする (テストで顕著)。Compile 1 回ごとに 17 ファイルパースは無駄、というシンプルな最適化。

### 6. `ir/` (142 行) — vocab 解決済の中間表現

`Program` → `LayerInstance[]` (vocab 参照済) + `Condition` (where) + `CaptureInfo`。AST と似ているが:
- AST の `Layer.ProtoName: string` → IR の `LayerInstance.Spec: *vocab.ProtocolSpec` (ポインタ参照)
- AST の `Predicate.Field.Path: []string` → IR の `Predicate.Field: *FieldRef{Layer, Field}` (具体 binding)
- AST の `Layer.Alternatives` → IR の `Alternation: []*LayerInstance` (展開済)

resolve がここを構築、codegen はここしか触らない。

### 7. `resolve/` (約 380 行) — AST + vocab → IR

- `resolve.go::Resolve` — エントリ、layer / where / capture を順に variant
- `layer.go::resolveLayer` — protocol 名 → vocab spec、親 → 子の dispatch const 探索 (`selectDispatch`)、alternation の親子整合性チェック
- `predicate.go::resolvePredicate` — value type 分類 (`ValInt` / `ValIPv4` / `ValIPv6` / `ValMAC` / `ValCIDR`)、field 範囲チェック
- `where.go` — field path bind (`proto.field` or `@label.field`)、ambiguous 判定
- `capture.go` — `headers+N` の長さ静的計算

**読みどころ**: `layer.go::selectAltParentDispatch` — alternation 後の layer が「全 alt から到達可能」を要求する制約 (uniform dispatch) の enforce 箇所。MVP の重要な制約。

### 8. `codegen/` (1960 行、最大) — IR → `asm.Instructions`

7 ファイル構成。読む順:
1. **`codegen.go::Gen`** (615 行) — 全体の骨格。**パッケージ doc が読みどころ最上位**。ABI (R0/R1/R2/R4 の役割、`offsetBase` 概念、`dslReject` / `filter_result` ラベル) はここに集約
2. **`dispatch.go`** (~110 行) — Field / Sanity (NIBBLE) / NoCheck の dispatch 検査 emit
3. **`predicate.go`** (394 行) — predicate codegen。整数 / IPv4 / IPv6 / MAC / CIDR、`==` / `!=` / ordered。**`multiWordRoute` ヘルパ**で == と != を統一
4. **`chain.go`** (96 行) — `{n,m}` で `m≤4` の静的アンロール
5. **`bpfloop.go`** (359 行) — `+/*/{n,m>4}` の bpf_loop emit。bpf2bpf subprogram + BTF func_info を作る最重要ファイル
6. **`alternation.go`** (152 行) — alt の sequence 展開
7. **`where.go`** (344 行) — where 節 (or / and / not / arith / action atom)。短絡評価 + precedence climbing の codegen 版
8. **`capture.go`** — `headers+N` の長さ algo

**コア概念 5 つ**:
- **R4 = `offsetBase`** — 現 layer の scratch 内 byte offset を持つ register。各 layer 終端で `Add R4, hs` で前進
- **`loadFromOffset(off, size)`** ヘルパ — `R3 = R0 + R4 + off; LDX R3, R3, off, size` の 3 命令を統一
- **byteSwap trick** — eBPF LDX は LE で読むので、network-order 定数を codegen 時に byte-swap して LE 形式で immediate に埋める。1 命令節約
- **`landingNoop(label)`** — `Mov.Reg(R3, R3).WithSymbol(label)` の no-op landing。`?` skip / `or` 終端 / `not` 反転 / `!=` match landing で再利用
- **`Output{Main, Callbacks, Capture}`** — 戻り値 3 段。`Main` が filter 本体、`Callbacks` が bpf_loop 用 bpf2bpf subprogram (BTF tag 付き)、`Capture` は wrapper への metadata

### 9. `compile.go` (45 行) — 全部束ねる薄い entry

`Compile(expr, mode)` が:
1. `lexer.New(expr)` → Lexer
2. `parser.New(lex)` → Parser → `Filter` (AST)
3. `dslvocab.Bundled()` → vocab map
4. `resolve.Resolve(filter, vocab)` → `Program` (IR)
5. `codegen.Gen(prog, mode)` → `Output`

たった数行のパイプライン。各段の入口点を確認できる。

## 「ここを押さえると一気にわかる」キー概念 5 つ

レビュー時にここを抑えていれば 70% 把握できる:

1. **runFilter ABI** (`codegen/codegen.go` パッケージ doc、L1-22)
   入: R0==scratch_start, R1==scratch_end, R9==pkt_len。出: R2=={0,1}。R6-R8 callee-saved 禁忌。R4==offsetBase は codegen 専用。これが分からないと codegen はどこも読めない

2. **Vocab dispatch 命名規約** (`vocab/loader.go::classifyConsts`)
   `<SELF>_<PARENT>_<FIELD>` 等の正規表現マッチで const の意味を決める。文書化された規約の **唯一の実装箇所**。バグがあるならここ

3. **2 モード lexer** (`lexer/lexer.go`)
   `[` 内では `NextValue()`、それ以外では `Next()`。これを知らずに lexer を読むと混乱する

4. **AST → IR の 1 段** (`resolve/resolve.go::Resolve`)
   parser が「proto 名と field 名の string」を作るだけ → resolve が vocab ポインタに bind、dispatch const を選び、ラベルを ambiguity check する。**resolve が型安全性の防壁**

5. **byteSwap trick + offsetBase** (`codegen/codegen.go::byteSwap`, `loadFromOffset`)
   全 codegen がこの 2 つに乗る。読み解けば predicate / dispatch / chain は全部素直

## レビュー時のチェックリスト (推奨観点)

- [ ] **AST の各 Sum 型が完備か**: `ast/kinds.go` の enum ごとに parser が全 variant を作っているか、resolve / codegen で漏れがないか
- [ ] **`Unsupported string` の伝達**: parser が立てたフラグが resolve / codegen まで届いているか (verifier 通過まで届かない → silently 動く → バグ)
- [ ] **2 モード lexer の境界**: `[` `]` `==` `!=` の前後でモード切替が破綻していないか
- [ ] **vocab regex の貪欲性**: `<SELF>_CHAIN_END_<FIELD>` が `<SELF>_<PARENT>_<FIELD>` に紛れ込まないか (実装は `reChainEnd` を `reField` より先に試す配置で対処済)
- [ ] **resolve の error path 網羅**: bad vocab / 同名 protocol / alt size mismatch / ラベル ambiguity の各エラーが出るか
- [ ] **codegen の register clobber**: R6-R8 を一切触っていないか、bpf_loop callback では R6-R9 全部触っていないか
- [ ] **byteSwap の方向**: 入力が BE (network) で出力が LE (immediate) になっているか、逆にしていないか
- [ ] **bpf_loop callback の BTF**: `bpfloop.go::genCallback` で func_info を attach しているか
- [ ] **Test の網羅性**: 各 codegen path に対応する verifier load test (`internal/program/load_dsl_test.go::dslEntryExprs`) があるか

## 関連ドキュメント

- [`dsl-overview.md`](./dsl-overview.md) — DSL ドキュメント index
- [`dsl-grammar.md`](./dsl-grammar.md) — formal EBNF + 例文
- [`pkg/kunai/README.md`](../../pkg/kunai/README.md) — library 利用者向け (英語)
