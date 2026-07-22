# DSL 内部仕様

bpf-ninja DSL の設計動機、全体アーキテクチャ、codegen ABI、vocab 開発ガイド、P4-16 互換性を 1 本にまとめた内部資料です。CLI 利用者向けは [`dsl-usage.md`](./dsl-usage.md) を、文法定義は [`dsl-grammar.md`](./dsl-grammar.md) を参照してください。

型、演算子、形式意味論は [`dsl-types.md`](./dsl-types.md) (Part I + Part II) に分離しています。本書はそれと重ならないよう、resolver より下のレイヤである vocab、codegen ABI、可変長構造を中心に扱います。

## 目次

1. [設計動機](#1-設計動機)
2. [全体アーキテクチャ](#2-全体アーキテクチャ)
3. [Vocab 開発ガイド](#3-vocab-開発ガイド)
4. [Codegen ABI](#4-codegen-abi)
5. [P4-16 互換性](#5-p4-16-互換性)
6. [可変長構造の分類と表現](#6-可変長構造の分類と表現)
7. [制限と将来拡張](#7-制限と将来拡張)

## 1. 設計動機

### 1.1 背景

bpf-ninja は non-invasive な XDP 観測ツールです。BPF trampoline (fentry / fexit) で本番 XDP プログラムにアタッチし、target を改変せずに pcap を取得します。

既存のフィルタ実装は cbpfc (Cloudflare の cBPF→eBPF transpiler) で tcpdump 構文を解釈します。しかし、次の課題があります。

- 多段カプセル化を書きにくいことです。cbpfc が L2 + L3 の絶対 offset しか扱えないため、GTP-U の extension chain、SRv6 の segment list、MPLS label stack、QinQ、L2/L3 VPN を tcpdump で書くのは事実上不可能です。
- operator 視点の表現力が不足していることです。VXLAN の inner で TCP/443 のような直感的記述ができません。
- 観測ホストの target XDP は改変できないことです。Cilium / Katran / 5G UPF などは operationally-sealed です。

### 1.2 ゴール

- 多段カプセル化を `eth/ipv4/udp/gtp/ipv4/tcp` のようにプロトコルスタックの形で記述できるようにします。
- verifier-safe な BPF を吐きます。全ループに静的上限を設け、bounds check を codegen が emit します。
- SRE / operator が読めるようにし、P4 expert 限定にしません。
- target XDP に手を入れず、既存の fentry / fexit wrapper にそのまま乗せます。

### 1.3 設計判断

| 判断 | 理由 |
|---|---|
| 薄い user-facing DSL + 厚い vocab | プロトコル知識は再利用可能な `.p4` ファイルに切り出す |
| kernel | CI matrix で実測する範囲は 6.1 / 6.6 / 6.12 / 6.18 / 7.0。`bpf_loop` を要する features (`+`/`*`/`{n,m>4}` chain quantifier、parser machine self-loop) は kernel 5.17+ 導入なので 5.17〜6.0 でも理論上動くが CI 未実測。fixed chain (`{1,4}` 以下、self-loop 無し) は更に古い kernel でも動作可能。predicate codegen は `BSWAP` (6.6+) を避け `BPF_END` byte-swap で済ませる |
| DSL がデフォルト、`--cbpf` opt-in | DSL の surface が安定したので default 化、cbpfc パスは legacy fallback として残す (deprecation notice 付き) |
| baked-in vocab | `//go:embed *.p4` で `.p4` ファイル群を binary に同梱、deploy 時に外部依存ゼロ |
| vocab は p4lite (P4-16 strict subset) | p4c で parse 可能な範囲に留める (互換性は §5 参照) |
| MVP はラベル 2 段まで | `@outer` / `@inner` の 2 段で VXLAN / GTP-U の典型ケースをカバー |
| codegen は純 Go | cilium/ebpf の `asm.Instructions` を直接組む、外部 toolchain 不要 |

### 1.4 明示的な除外項目

- map references は `map["name"][key]` を filter 内に書く機能で、per-packet lookup overhead と zero-config 原則に抵触します。
- L7 semantic parsing は DNS body / HTTP header / TLS 内部の解析で、cooperation Tier 3 として将来に持ち越します。
- temporal conditions は、直前 SYN から N 秒以内のような時間軸条件です。
- blind protocol auto-detection は encap 型の heuristic 推測です。明示的な layer chain 指定が要件です。

## 2. 全体アーキテクチャ

### 2.1 三層構造

```
┌─────────────────────────────────────────────────────┐
│ One-liner DSL (user-facing)                         │
│   eth/ipv4/udp/gtp/ipv4/tcp[dport==443]              │
└───────────────┬─────────────────────────────────────┘
                │ parse  (pkg/kunai/parser/)
                ↓
┌─────────────────────────────────────────────────────┐
│ AST (pkg/kunai/ast/)                             │
│   Filter / Layer / Predicate / WhereExpr / Capture  │
└───────────────┬─────────────────────────────────────┘
                │ resolve  (pkg/kunai/resolve/)
                │   ↑ vocab 参照 (pkg/kunai/vocab/)
                ↓
┌─────────────────────────────────────────────────────┐
│ IR (pkg/kunai/ir/)                               │
│   Program / LayerInstance / Condition / FieldRef    │
│   ※ vocab 解決済 (DispatchChoice / Spec バインド)    │
└───────────────┬─────────────────────────────────────┘
                │ codegen  (pkg/kunai/codegen/)
                ↓
┌─────────────────────────────────────────────────────┐
│ Output{ Main, Callbacks, CaptureInfo }              │
│   asm.Instructions (cilium/ebpf)                    │
│   bpf2bpf subprogram (chain callback) + BTF func    │
└───────────────┬─────────────────────────────────────┘
                │ load  (internal/program/program.go::compileFilter)
                ↓
┌─────────────────────────────────────────────────────┐
│ kernel BPF verifier → fentry / fexit attach          │
└─────────────────────────────────────────────────────┘
```

### 2.2 各段の役割と主要ファイル

| 段 | パッケージ | 入口 | 役割 |
|---|---|---|---|
| Lex | `pkg/kunai/lexer/` | `Lexer.Next()` / `NextValue()` | structural / value の 2 モード切替トークナイザ |
| Parse | `pkg/kunai/parser/` | `Parse()` | AST 構築 (再帰下降、where のみ precedence climbing) |
| AST | `pkg/kunai/ast/` | (型定義) | Filter / Layer / Predicate / WhereExpr / Capture / Value 等 |
| Vocab load | `pkg/kunai/vocab/` | `Bundled()` | `.p4` → `ProtocolSpec` (cache 付き) |
| Resolve | `pkg/kunai/resolve/` | `Resolve()` | AST + vocab → IR、dispatch 選択、ラベル解決 |
| IR | `pkg/kunai/ir/` | (型定義) | 解決済みプログラム表現 |
| Codegen | `pkg/kunai/codegen/` | `Gen(p, caps)` | IR → `Output{Main, Callbacks, Capture}` |
| Compile | `pkg/kunai/compile.go` | `Compile(expr, caps)` | 全部束ねる薄い wrapper |
| Load 統合 | `internal/program/program.go` | `compileFilter(expr, useDSL)` | DSL or cbpfc を選び runFilter wrapper に乗せる |
| CLI | `cmd/bpf-ninja/main.go` | `resolveFilterSyntax()` | DSL がデフォルト、`--cbpf` で legacy 経路 |

### 2.3 パッケージごとのツアー (依存順、leaf → root)

`pkg/kunai/` 配下は test を除いて ~12,800 行、10 パッケージです。外から内へたどると依存方向を素直に追える構造で、leaf の `ast/` `ir/` `vocab/` から読むと積み上げが見えます。

#### `ast/` (~560 行、純粋な型定義)

`ast.go` が AST のルート型です。`Filter` が 1 つの DSL filter 式に対応し、その下に `Layer[]` / `WhereExpr` / `CaptureClause[]` が並びます。`Predicate` / `WhereExpr` / `CaptureClause` 等の各 Sum 型は `kinds.go` の enum (`PredKind`, `WhereKind`, `CaptureKind`, `ValueKind`, `Quantifier`, `CmpOp`, `ArithOp`) で識別されます。

読みどころは次のとおりです。

- `ast.go` のパッケージ doc にある `Unsupported string` フィールドの意図です。parser が受理した、これから codegen で対応する予定のもの (PredIn/PredHas/CapFields) を明示的にマークします。
- `value.go` は predicate 値の Sum 型 (`Int`, `V4 [4]byte`, `V6 [16]byte`, `MAC [6]byte`, `Prefix int`) です。

ロジックは無く、型の倉庫です。

#### `lexer/` (~730 行、2 モード切替トークナイザ)

`lexer.go` が本体で、`scanvalue.go` が IPv4/IPv6/MAC のリテラル parser、`token.go` が token kind enum です。

核心は 2 モードの切替です。

- structural mode (`Lexer.Next()`) は `/`, `[`, `]`, `where`, `capture`, identifier 等の構文骨格を扱います。
- value mode (`Lexer.NextValue()`) は `[field==10.0.0.1]` の `10.0.0.1` 部分を扱います。IPv4/IPv6/MAC が `/`, `:`, `.` を含むため、structural の `/` (chain separator) と区別する必要があります。

#### `parser/` (~1,310 行、再帰下降 + precedence climbing)

`parser.go` がエントリと共通ヘルパです。文法部分は次の別ファイルに分かれています。

- `layer.go` は layer chain (`/`)、quantifier (`?+*{n,m}`)、alternation (`(a|b)`) を扱います。
- `predicate.go` は `[field op value]` を扱い、bit-slice `[lo:hi]` index を含みます。
- `where.go` は `where` 節です。precedence climbing で、bool atom / `Bool == Bool` / LHS network literal 対称化 / 負数 literal に対応します。
- `capture.go` は `capture all/headers/headers+N/<label>+N/proto+N/absolute N` を扱います。

#### `vocab/` + `vocab/p4lite/` (~3,100 行)

2 階層構成です。

- `vocab/p4lite/` は `.p4` ファイル (P4-16 strict subset) を AST 化します。再帰下降で、受理する構文の境界は subset の正規定義である `conformance_test.go` で pin します。
- `vocab/` は p4lite AST を `ProtocolSpec` に変換します。`loader.go::Load` がエントリで、`classifyConsts` がまず `KUNAI_` 接頭辞 (inter-layer dispatch のマーカ) の有無で分岐し、残りを正規表現で次のように分類します。dispatch shape (Field / NoCheck) は `KUNAI_` 付きで、構造系 (CHAIN_END / MAX_DEPTH) と value-only は無印です。
  - `reField` (`KUNAI_<SELF>_<PARENT>_<FIELD>`)
  - `reChainEnd` (`<SELF>_CHAIN_END_<FIELD>`)
  - `reMaxDepth` (`<SELF>_MAX_DEPTH`)
  - + NoCheck (`KUNAI_<SELF>_<PARENT>_NO_CHECK`)
  - + Self-validating dispatch (parser-block 自検査)
- `vocab/parser_machine.go` は aux header layout / gating / stack capacity を `parser_machine` block から抽出します。

#### `dslvocab/` (~30 行、bundled vocab の cache wrapper)

`Bundled()` のみです。`protocols/*.p4` を `//go:embed` で取り込み、`vocab.Load` の結果を `sync.Once` でキャッシュします。

#### `ir/` (~340 行、vocab 解決済の中間表現)

`Program` の下に、vocab 参照済の `LayerInstance[]`、where の `Condition`、`CaptureInfo` が並びます。AST と似ていますが、次の点が異なります。

- AST `Layer.ProtoName: string` → IR `LayerInstance.Spec: *vocab.ProtocolSpec`
- AST `Predicate.Field.Path: []string` → IR `Predicate.Field: *FieldRef{Layer, Field, Aux, Slice}` (具体 binding)
- AST `Layer.Alternatives` → IR `Alternation: []*LayerInstance` (展開済)

`FieldRef.Slice` で bit-slice を、`FieldRef.EffectiveBits()` で slice-aware な bits を表します。

#### `resolve/` (~1,600 行、AST + vocab → IR + 型システム)

- `resolve.go::Resolve` / `ResolveWithOptions` はエントリです。`Options.StrictArithLint` で F1 lint pass を opt-in します。
- `layer.go::resolveLayer` は protocol 名 → vocab spec の解決、dispatch const 探索、alternation の親子整合性を担当します。
- `predicate.go::resolveBracketPredicate` は value type 分類と field 範囲チェック (slice 含む) を行います。
- `where.go` は field path bind、bool atom / aux exists / quantifier 経路を扱います。
- `capture.go` は `headers+N` の長さを静的に計算します。
- `typing.go` は型システム本体で、`checkArithCondition` / `checkBracketIntFit` / `checkLiteralWidthShape` / `attachSlice` / `detachTrailingSlice` / `tryDesugarMultiLDXSliceCmp` / `splitSliceIntoLDXChunks` / `lintArithCondition` (F1) を含みます。
- `typing_errors.go` は型エラー専用の helper です。`typing_errors_test.go` で [`dsl-types.md §8`](./dsl-types.md#8-型エラー一覧) catalog との drift を pin します。

読みどころは次のとおりです。

- `layer.go::selectAltParentDispatch` は alternation の uniform dispatch 制約を enforce します。
- `typing.go::tryDesugarMultiLDXSliceCmp` は F12 mid-width slice cmp の AND/OR-chain desugar です。
- `typing.go::attachSlice` は bit-slice の field-aware バリデーションです。

#### `codegen/` (~5,500 行で最大、IR → `asm.Instructions`)

ファイル構成を読む順に示します。

1. `codegen.go::Gen` は全体の骨格です。共通 helper として、slice 用 `applySliceToOffset` / `slicePostAdjust` / `nextLDXSize`、anchor 三種 `layerAnchorFor` / `absAnchor` / `slotAnchor` / `emitFieldLoad`、per-layer entry slot allocator `whereLayerEntrySlot` を含みます。パッケージ doc が読みどころの最上位です。ABI (R0/R1/R2/R4 の役割、`offsetBase` 概念、`dslReject` / `filter_result` ラベル、`KunaiStackTop` / `ScratchBufSize` の sizing 契約) はここに集約されています。§4 の codegen ABI を参照してください。
2. `caps.go` は host 提供の `Capabilities` と `ActionFetcher` interface です。`Capabilities` は `Lex` (ReservedLabels) / `Lang` (Action map + ActionFetcher) / `Host` (packet layout) の 3 つのフェーズ別グループを束ねる薄い集約体です。
3. `dispatch.go` は Field / NoCheck / SelfValidating の dispatch 検査を emit します。Sanity family は撤廃済みで、parser-block 自検証に統合されています。§3.2 / §5 を参照してください。
4. `predicate.go` は predicate codegen です。整数 / IPv4 / IPv6 / MAC / CIDR、`==` / `!=` / ordered を扱い、F3 IPv6 ordered cmp (`emitIPv6OrderedCmp`)、F7 整数 in (`emitInPredicate`)、bit-slice 適用も含みます。`multiWordRoute` ヘルパで `==` と `!=` を統一しています。
5. `chain.go` は `{n,m}` で `m≤4` の静的アンロールです。
6. `bpfloop.go` は `+/*/{n,m>4}` の bpf_loop emit です。bpf2bpf subprogram と BTF func_info を扱い、whole-chain skip の `*` は `emitPeekedIterZero` で parent dispatch を peek します。
7. `alternation.go` は alt の sequence 展開です。P3-12 で per-alt body emit + matched flag に、P3-13 で nested alt の resolver flatten に対応しました。
8. `where.go` は where 節 (or / and / not / arith / action atom / bool atom / bool eq / quantifier any-all) です。het-alt 後の field addressing は PR-A/B 由来で、`layerAnchorFor` が abs / slot anchor を出し分けます。F4 Int<128> arith pipeline (`genArithCompare128` / `genArith128FieldOpConst` / `genArith128FieldOpField` / `genArithField128Load`、ABI-clean な stack-bridged carry/borrow)、F6 bitwise ALU 統合、F10 BoolEq の `genConditionAsBool`、F13 slice の `emitSliceShiftMask`、TLV-walk option access を含みます。TLV-walk option access の `genDynamicOffsetAuxLoad` は、parser-machine が記録した dynamic offset slot から absolute scratch offset を読み出して field を取得します。
9. `capture.go` は `headers+N` の長さ algo です。
10. `option_demand.go` は、TLV-walk callback が record する dynamic-aux offset の per-(layer, queried-aux) demand-driven 割当です。`queriedOptions` map が where/capture/predicate を walk して実際に参照される aux を集め、eligible aux 数ではなく referenced aux 数で課金する形で、`dynamicAuxOffsetSlotBase` から下の領域を per-layer demand size に応じて pack します。
11. `callback_lint.go` は bpf_loop callback の compile-time branch-count tripwire です。`assertCallbackComplexity` が conditional + Ja の総数を count し、`callbackBranchThreshold` を超えたら `ErrNotImplemented` で reject します。rationale と閾値の根拠は同ファイル冒頭のコメントにあります。new branch in callback → MAX_DEPTH × scalar-ID inflation という fingerprint への systemic mitigation です。
12. `parser_state.go` / `parser_trail.go` / `parser_select.go` / `parser_loop.go` は parser-machine codegen の 4 ファイルです。`parser_state.go` は状態 walk root + entry dispatch を、`parser_trail.go` は `pkt.advance` 系 variable trailer (mechanism 1) を、`parser_select.go` は transition select tuple-key resolution (lookahead / bit-slice) を、`parser_loop.go` は bpf_loop callback (multi-state TLV walk + parser self-loop + dynamic aux slot prelude) を担当します。
13. `parser_counter.go` は、mechanism 8 の `extern ParserCounter { ... }` における `pc.set` / `pc.decrement` / `pc.is_zero` を bpf_loop callback の prelude / per-iter ops に下ろします。1-key (`select(pc.is_zero())`) / 2-key (`select(pc.is_zero(), pkt.lookahead<bit<8>>())`) 双方の dispatch を生成します。

#### `compile.go` (~50 行、全部束ねる薄い entry)

`Compile(expr, caps)` は次のパイプラインを実行します。

1. `dslvocab.Bundled()` → vocab map
2. `parser.Parse(expr, ...)` → `Filter` (AST)
3. `resolve.Resolve(filter, vocab, caps.Lang.Action)` → `Program` (IR)
4. `codegen.Gen(prog, caps)` → `Output`

数行のパイプラインです。各段の入口点を確認できます。

### 2.4 ここを押さえると一気にわかるキー概念

レビュー時にここを押さえていれば 70% 把握できます。

1. runFilter ABI (`codegen/codegen.go` パッケージ doc)
   入力は R0==scratch_start, R1==scratch_end, R9==pkt_len、出力は R2=={0,1} です。R6-R8 は callee-saved で禁忌、R4==offsetBase は codegen 専用です。これが分からないと codegen はどこも読めません。詳細は §4 を参照してください。

2. Vocab dispatch 命名規約 (`vocab/loader.go::classifyConsts`)
   `<SELF>_<PARENT>_<FIELD>` 等の正規表現マッチで const の意味を決めます。文書化された規約の唯一の実装箇所です。

3. 2 モード lexer (`lexer/lexer.go`)
   `[` 内では `NextValue()` を、それ以外では `Next()` を使います。これを知らずに lexer を読むと混乱します。

4. AST → IR の 1 段 (`resolve/resolve.go::Resolve`)
   parser は proto 名と field 名の string を作るだけで、resolve が vocab ポインタに bind し、dispatch const を選び、ラベルを ambiguity check します。resolve が型安全性の防壁であり、typing.go の入口でもあります。

5. byteSwap trick + offsetBase (`codegen/codegen.go::byteSwap`, `loadFromOffset`)
   全 codegen がこの 2 つに乗ります。読み解けば predicate / dispatch / chain はすべて素直に読めます。

### 2.5 レビュー時のチェックリスト

`pkg/kunai/` 配下を review するときの推奨観点は次のとおりです。

- [ ] AST の各 Sum 型が完備かを確認します。`ast/kinds.go` の enum ごとに parser が全 variant を作っているか、resolve / codegen で漏れがないかを見ます。
- [ ] `Unsupported string` の伝達を確認します。parser が立てたフラグが resolve / codegen まで届いているかを見ます。verifier 通過まで届かないと silently 動いてバグになります。
- [ ] 2 モード lexer の境界を確認します。`[` `]` `==` `!=` の前後でモード切替が破綻していないかを見ます。
- [ ] vocab regex の貪欲性を確認します。`<SELF>_CHAIN_END_<FIELD>` が `<SELF>_<PARENT>_<FIELD>` に紛れ込まないかを見ます。実装は `reChainEnd` を `reField` より先に試す配置で対処済みです。
- [ ] resolve の error path の網羅を確認します。bad vocab / 同名 protocol / alt size mismatch / ラベル ambiguity / 型エラー (`typing_errors.go`) の各エラーが出るかを見ます。
- [ ] codegen の register clobber を確認します。R6-R8 を一切触っていないか、bpf_loop callback では R6-R9 をすべて触っていないかを見ます。
- [ ] byteSwap の方向を確認します。入力が BE (network) で出力が LE (immediate) になっているか、逆にしていないかを見ます。
- [ ] bpf_loop callback の BTF を確認します。`bpfloop.go::genCallback` で func_info を attach しているかを見ます。
- [ ] bit-slice の post-adjust を確認します。non-aligned slice が `emitSliceShiftMask` 経由で正しい shift+mask を emit しているかを見ます。
- [ ] Test の網羅性を確認します。各 codegen path に対応する verifier load test (`internal/program/load_dsl_test.go::dslEntryExprs`) があるか、型 helper が `resolve/typing_test.go` で unit テストされているかを見ます。

## 3. Vocab 開発ガイド

新プロトコルを DSL に追加する手順です。`pkg/kunai/protocols/<name>.p4` を 1 ファイル足し、規約どおりの const を書けば codegen がそのまま走ります。

> hands-on の完全版は [`dsl-vocab-authoring.md`](./dsl-vocab-authoring.md) です。parser block の state machine の書き分け (可変長 8 機構)、@kunai_* annotation、loader 制約の早見表、テスト手順はそちらが正典です。この §3 は const 規約と設計判断のサマリです。

### 3.1 ファイル配置

- 1 プロトコル = 1 ファイルで、`pkg/kunai/protocols/<lowercase-name>.p4` に置きます。
- 拡張子を除いたファイル名が、DSL でレイヤを書くときの protocol 名になります。例えば `mpls.p4` なら `eth/mpls/ipv4` と書きます。
- バンドルは `embed.go` の `//go:embed *.p4` で取り込まれるので、ファイルを置けばリビルドだけで読み込まれます。

### 3.2 ファイル構成 (3 セクション)

#### Header 宣言 (必須)

```p4
header mpls_h {
    bit<20> label;
    bit<3>  tc;
    bit<1>  s;
    bit<8>  ttl;
}
```

ルールは次のとおりです。

- Primary header 名は `<protoname>_h` で、上記なら `mpls_h` です。これがマッチしないと vocab loader が reject します。
- フィールドは `bit<N> name;` の繰り返しで、`N` は 1..2048 です。
- 全フィールドの bit 合計は 8 の倍数で、header total が byte-aligned である必要があります。
- フィールド名は lowercase + underscore + 数字です。

オプション解析用などの補助 header も同ファイルに書けます。codegen には primary だけが渡ります。

#### Const 宣言 (dispatch + メタデータ)

const は名前で意味が決まります。

| パターン | 意味 |
|---|---|
| `KUNAI_<SELF>_<PARENT>_<FIELD>` | 親 protocol の `field` がこの値のときに自分 (SELF) として展開 |
| `KUNAI_<SELF>_<PARENT>_NO_CHECK` | 検査せず blind cast (ユーザの記述順を信じる) |
| `<SELF>_MAX_DEPTH` | bpf_loop chain (`+`/`*`/`{n,m>4}`) のループ上限。未指定なら codegen 既定 (8) |
| `<SELF>_CHAIN_END_<FIELD>` | chain 終了条件 (例: MPLS s-bit が 1 で終端) |

`<SELF>` は uppercase のファイル名、`<PARENT>` は uppercase の親 protocol 名です。`KUNAI_` は inter-layer dispatch のマーカで、親レイヤから自分への遷移を表す dispatch const (Field / NoCheck / self-dispatch) にだけ付けます。value-only な select-match 値 (routing_type / option kind / next-header 種別など、親が実在プロトコルでない phantom parent のもの。例: `SRV6_ROUTING_TYPE`、`IPV6_NH_FRAGMENT`) と、`<SELF>_MAX_DEPTH` / `<SELF>_CHAIN_END_<FIELD>` のような構造 const には付けません。loader (`classifyConsts`) はこの規約を強制し、無印の dispatch shape も `KUNAI_` 付きの非 dispatch も loud-reject します。親が Field/NoCheck のいずれも持たず、子が parser block で自己検証する場合 (例: ipv4 の `transition select(hdr.version) { 4: accept; default: reject; }`) は vocab const が不要で、resolver が `DispatchSelfValidating` を合成します。詳細は §3.3 を参照してください。

Field dispatch は一番よく使う形です。

```p4
const bit<16> KUNAI_IPV4_ETH_ETHERTYPE  = 0x0800;
const bit<16> KUNAI_IPV4_VLAN_ETHERTYPE = 0x0800;
```

`ipv4` が eth または vlan 経由で来るとき、親の `ethertype` は `0x0800` です。

- ビット幅は親フィールドの幅と一致させます。`ethertype` は 16 bit なので `bit<16>` です。
- 値は親フィールド幅に収まる整数です。
- field 名は親 header の field 名 (lowercase) と完全一致させます。

Self-validating parser は旧 SANITY 機構の置き換えです。

```p4
// ipv4.p4: parser block が version=4 を自己検証する
parser IPv4Parser(packet_in pkt, out ipv4_h hdr) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.version) {
            4:       accept;
            default: reject;
        }
    }
}
```

mpls / gtp / vxlan inner 等の親に次プロトコルを示す field が無くても、子の parser block が `transition select(<primary-field>) { ...; default: reject; }` を持っていれば、resolver が `DispatchSelfValidating` を合成して chain を許可します。boundary では何も emit せず、parser machine の transition select が実行時に reject します。

- 旧 `<SELF>_<PARENT>_SANITY_<TYPE>` / `<SELF>_SANITY_<TYPE>` const family は撤廃されました。legacy 名で declare すると vocab loader が error で reject します。
- self-validation は標準 P4-16 構文のみで表現するので、vocab が self-contained になります。srv6 の `transition select(hdr.routing_type) { SRV6_ROUTING_TYPE: walk; default: reject; }` と同じ idiom です (`SRV6_ROUTING_TYPE` は値 4 を表す value-only const)。
- ipv4 のように self-validation (`transition select(version) { 4: skip_options; default: reject; }`) と variable-trailer (`pkt.advance(((bit<32>)(hdr.ihl - 5)) << 5)`) が parser block 内で同居しても、codegen は state graph を順番に消化するため問題ありません。`validateLayoutExclusivity` は両立を許可します。
- 親が Field/NoCheck/SelfValidating のいずれの dispatch も持たない場合は、resolver が `no dispatch constant for ...` で reject します。

NoCheck dispatch は次のように書きます。

```p4
const bool KUNAI_ETH_MPLS_NO_CHECK = true;
const bool KUNAI_MPLS_MPLS_NO_CHECK = true;
```

EoMPLS や VXLAN inner Ethernet などのように、親と自分の境界に検査機構が無い形です。ユーザが one-liner で順序を明示することで境界を表現します。

- `bool` 型が必須で、`= true` のみ有効です。`false` は宣言禁止です。
- `mpls+` 等の chain で、iter 1+ の self-dispatch にも使えます。

MAX_DEPTH は次のように書きます。

```p4
const bit<8> MPLS_MAX_DEPTH = 8;
```

bpf_loop で最大何回イテレーションするかを決めます。未宣言なら既定 8 で、上限は 64 です。

CHAIN_END は次のように書きます。

```p4
const bit<1> MPLS_CHAIN_END_S = 1;
```

chain 中、SELF の `s` field が `1` のとき chain を終了します。MPLS の bottom-of-stack ビットがこの典型です。

#### Parser 宣言

```p4
parser MplsParser(packet_in pkt, out mpls_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
```

固定長プロトコルは、1 state で primary を extract して accept するこの最小形を書きます。loader が trivial と判定し、parser machine を作らず固定長の高速経路を通ります。それ以外の形 (自己検証 select、self-loop、TLV walk、ParserCounter walk など) は、§6.5 の Mechanism 3/5/7/8 のとおり、実行コードに lower される state machine になります。state machine の書き分けは [`dsl-vocab-authoring.md` §6-§7](./dsl-vocab-authoring.md) を参照してください。

### 3.3 どの dispatch type を選ぶか

優先順位は Field(parent) > NoCheck(parent) > SelfValidating (子の parser block が自己検証) です。const ベースの形 (Field / NoCheck) が parser-block 自己検証より優先されます。

判断フローは次のとおりです。

1. 親 protocol に次プロトコルを示すフィールドがあるかを確認します。
   - ある場合は Field を使い、`KUNAI_<SELF>_<PARENT>_<FIELD> = <value>` と書きます。
2. 子の primary header に、IPv4 / IPv6 の version や SRv6 の routing_type のような識別可能な field があるかを確認します。
   - ある場合は parser block での自己検証を推奨します。`transition select(hdr.<field>) { <ok>: accept; default: reject; }` と書き、vocab const は不要です。
3. encapsulation の Ethernet inner などのように、どちらも無い場合に対応します。
   - NO_CHECK を使い、`KUNAI_<SELF>_<PARENT>_NO_CHECK = true` と書きます。

### 3.4 Self-dispatch (chain 用)

`KUNAI_<SELF>_<SELF>_*` は chain (`+`/`*`/`{n,m}`) のときに iter 1+ で読まれます。self-dispatch も dispatch edge なので `KUNAI_` を付けます。

- VLAN は `KUNAI_VLAN_VLAN_ETHERTYPE = 0x8100` です。inner VLAN は、外側の ethertype が再び 0x8100 になることで識別します。
- MPLS は `KUNAI_MPLS_MPLS_NO_CHECK = true` です。label 区切りは無いので blind chain になります。

self-dispatch が無いプロトコルは `+` / `*` / `{n,m}` で chain できず、静的に固定回数しか展開できません。

### 3.5 サンプル: 新しい encapsulation を追加する

4 byte header で ipv4 を貫通する VXLAN-like な仮想プロトコル `foo` を足す場合は、次のように書きます。

```p4
// pkg/kunai/protocols/foo.p4
header foo_h {
    bit<8>  version;
    bit<8>  flags;
    bit<16> reserved;
}

// foo は UDP の dport==4444 で識別
const bit<16> KUNAI_FOO_UDP_DPORT = 4444;

parser FooParser(packet_in pkt, out foo_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
```

別ファイル `eth.p4` 側に次の const を追加します。

```p4
const bool KUNAI_ETH_FOO_NO_CHECK = true;
```

これで DSL から `eth/ipv4/udp[dport==4444]/foo/eth/ipv4/tcp` が書けます。

### 3.6 テスト

```bash
# 1. 全 vocab がロードできる + 既存テストが緑
go test ./pkg/kunai/vocab/... ./pkg/kunai/resolve/...

# 2. DSL でコンパイルが通る
go test ./pkg/kunai/... -run TestCompile

# 3. 実 verifier 通過 (vimto 必要)
go test -c -o /tmp/test ./internal/program/
vimto exec -- /tmp/test -test.run TestBpfEntryWithDSLFilter -test.v
```

`internal/program/load_dsl_test.go` の `dslEntryExprs` に新プロトコルのケースを足すと、後の回帰防止になります。

### 3.7 デバッグ (典型エラー)

vocab loader エラーは次のとおりです。

```
foo.p4: const "FOO_BAR_BAZ_QUX" does not match <SELF>_{<PARENT>_<FIELD>|MAX_DEPTH|CHAIN_END_<FIELD>} or KUNAI_<SELF>_{<PARENT>_<FIELD>|<PARENT>_NO_CHECK}
```

const 名がパターンに一致していません。`<SELF>_` を抜かしている、parent 名のスペルが違うなどが典型です。dispatch const なのに `KUNAI_` を付け忘れていると、より具体的な `is an inter-layer dispatch edge — prefix it with KUNAI_` エラーになります。逆に value-only const (routing_type / option kind 等) に `KUNAI_` を付けると `drop the KUNAI_ prefix for a value-only select-match const` で reject されます。

```
foo.p4: const "FOO_BAR_SANITY_NIBBLE" uses the SANITY family, which has been removed — declare a parser-block `transition select(<field>) { ...; default: reject; }` to self-validate the protocol instead
```

旧 SANITY const family は撤廃されました。parser block で `transition select(<primary-field>) { <ok>: accept; default: reject; }` を書けば同じ意味になります。例は ipv4.p4 にあります。

```
foo.p4: missing primary header "foo_h"
```

primary header の名前が `<filename>_h` になっていません。

resolver エラーは次のとおりです。

```
no dispatch constant for "foo" under "udp" (declare KUNAI_FOO_UDP_<FIELD> or KUNAI_FOO_UDP_NO_CHECK in foo.p4, or have foo.p4 self-validate via a parser-block `transition select(...) { ...; default: reject; }`)
```

DSL で `eth/ipv4/udp/foo` を書いたものの、`foo.p4` に `KUNAI_FOO_UDP_*` (Field / NoCheck) も、parser block での自己検証 (`transition select(<primary-field>) { ...; default: reject; }`) も無い状態です。どちらかを宣言します。

```
alternation alts disagree on dispatch for "tcp" and at least one alt uses self-validating dispatch — codegen only handles diverged Field dispatch (per-alt JNE check)
```

alt group 後の layer の dispatch const が alt 間で揃っておらず、かつ Field dispatch でない alt が混ざっている状態です。揃っていないこと自体はエラーではなく、全 alt が Field dispatch であれば alt ごとの diverged dispatch として codegen されます。NoCheck や self-validating の alt が混ざる場合のみ reject されます。

codegen エラーは次のとおりです。

```
chained "foo" has no self-dispatch const (declare KUNAI_FOO_FOO_<FIELD> or KUNAI_FOO_FOO_NO_CHECK in foo.p4)
```

`foo+` / `foo*` / `foo{n,m>1}` を書いたものの、`foo.p4` に `KUNAI_FOO_FOO_*` self-dispatch がありません。

parser machine 固有の制約として、codegen が `ErrNotImplemented` で reject するものを次に示します。

| エラー | 意味 | 対処 |
|---|---|---|
| `select key is N bits; MVP supports up to 8` | `transition select(...)` の鍵が 1 byte 超 | 1 byte field に分けるか、複数 select に分割 |
| `variable-trail select with N keys exceeds stash slots` | tuple-select の鍵が 3 本超 | tuple を分解 |
| `variable-trail scale N is not a power of two` | variable-length trail の scale が非 2 冪 | vocab 側で 2 冪に丸めるか、cap 直書きを検討 |
| `parser machine self-loop depth N exceeds cap M` | self-loop の反復上限超過 | vocab に `<SELF>_MAX_DEPTH = N` で上限 declare (デフォルト 8、最大 64) |

これらは現状、§7.1 の MVP 制限表の Parser machine 行でも追跡しています。新しい vocab 著者が引っかかった場合に最初に確認する箇所です。

### 3.8 設計上の心構え

1. NO_CHECK は最後の手段です。Field dispatch か parser block の自己検証で識別できるなら、必ずそれを使います。NO_CHECK は user の記述順だけが頼りで、間違えると誤読します。
2. MAX_DEPTH は実利用上限ではなく安全弁です。MPLS なら現実は 4-8 段ですが、verifier に与える loop 上限として一桁を選びます。
3. Field の値は byte-swap なしで書きます。codegen 側で network-order に直すため、IPv4 の `ETHERTYPE = 0x0800` のように直感どおりに書けます。
4. 自己検証は標準 P4-16 構文 (`transition select(<primary-field>) { <ok>: ...; default: reject; }`) だけで書きます。kunai 独自 const に頼らないので vocab が self-contained になり、p4c でもそのまま意味が読めます。

## 4. Codegen ABI

DSL output が既存の runFilter wrapper にどう乗るかを説明します。コードを読む前にここを押さえてください。詳細実装は `pkg/kunai/codegen/codegen.go` のパッケージ doc にあります。

### 4.1 レジスタ規約

| Register | 役割 |
|---|---|
| R0 | scratch buffer 先頭 (in: wrapper が先読みしておいた packet bytes) |
| R1 | scratch buffer 末尾 (in: bounds check 用) |
| R2 | filter result (out: 1==accept / 0==reject) |
| R3 / R5 | 自由に clobber 可 (working)。ただし R5 は alt-diverged dispatch (P3-12) で `matchedAltReg` に流用される。alt block が match した alt index を R5 に書き、直後の layer dispatch が `JNE R5, i` で per-alt 分岐する。alt block 入口から次 layer dispatch 完了までの区間で R5 を別用途に潰してはいけない (`pkg/kunai/codegen/alternation.go::matchedAltReg`) |
| R4 | offsetBase: 現 layer の scratch buffer 内開始位置 (codegen 専用) |
| R6-R8 | host 占有 (callee-saved from kunai's view、kunai は読み書き禁忌)。bpf-ninja wrapper では xdp_buff / data / data_end を保持。注: filter 後に走る `captureWithXdpOutput` (`internal/program/program.go`) が R6 を使うので、kunai が clobber すると capture 出力先 ctx が壊れる |
| R9 | packet length (in: wrapper が事前計算)。read-only: filter 後に `captureWithXdpOutput` が `Mov R3, R9` で `MaxCapLen` を計算するパスがある (per-CPU map にコピーする bytes 長)。kunai が R9 に書くと capture 長が silent truncation する。`TestZeroCapsIsHostAgnostic` が R6-R8 / shallow stack を pin する一方、R9 への write も同じ違反として扱う必要がある (Int<128> dual-half compare で見落とした履歴あり、commit `b6d5e7f` 後に修正) |
| R10 | stack pointer |

Stack 占有 (詳細は `codegen.go` パッケージ doc の `KunaiStackTop` 周辺) は次のとおりです。

- kunai 占有: arith spill `[-56..-184]` (`maxArithDepth = 16` slot × 8 byte、10b で 8 → 16 bump)、bpf_loop ctx `[-208..-176]` (4 slot: `bpfLoopCtxOffsetSlot=-208` / `bpfLoopCtxScratchStartSlot=-200` / `bpfLoopCtxScratchEndSlot=-192` / `bpfLoopCtxLayerEntrySlot=-184`)、per-layer entry slot `[-224..-224-8N]` (`whereLayerEntrySlot`、PR-A/B 由来、het-alt 後の where / capture が runtime offset を読むのに使用、`whereLayerEntrySlotCap = 7` 上限 = 56 byte)、dynamic aux offset slot `[-280..-512]` (`dynamicAuxOffsetSlot(layerPos, slotIdx)`、TLV-walk callback の lifted prelude が record、demand walker が割り当てた option 数だけ消費、`dynamicAuxMaxSlotsPerLayer = 5` × `whereLayerEntrySlotCap = 7` 上限 = 280 byte cap、realistic vocab で TCP options (1 layer × 1〜5 slot = 8〜40 byte) が最大)
- host 占有: `(KunaiStackTop, 0)` = `(-56, 0)` の任意の slot。bpf-ninja wrapper は `-48` で tracing args ptr、`-12..-8` で metadata
- 境界定数は `pkg/kunai/codegen.KunaiStackTop = int16(-56)` です。kunai がここより浅いオフセットを書くことは無く、regression test `TestZeroCapsIsHostAgnostic` で守ります。
- scratch buffer サイズは `pkg/kunai/codegen.ScratchBufSize = 512` byte です。host wrapper はこの prefix を per-CPU scratch buffer に materialise してから kunai filter に jump します。新 protocol を vocab に足すときは、`sum(per-protocol max trail) + sum(fixed primary headers) ≤ ScratchBufSize` が成立するかを、codegen.go パッケージ doc の sizing contract に従って検証します。

### 4.2 制御フロー

成功時は R2==1 → `Ja filter_result` → wrapper の最終分岐に戻ります。
失敗時は `Ja dsl_reject` → R2==0 → fall through → `filter_result` の流れです。

### 4.3 layer の emit 単位

各 layer は以下のステップで emit します。

1. bounds check として `R3 = R0 + R4 + hs; R3 > R1 → dsl_reject` を emit します。
2. dispatch check を行います。Field では親の field を読んで const と比較し、NoCheck では何もせず、SelfValidating では parser-block 自検証 (Sanity family の置換) になります。
3. predicate を emit し、layer のフィールド条件を AND で連鎖します。
4. `NeedsRuntimeOffset` 設定時は per-layer entry slot を書き出します。het-alt 後の where/capture/option-walk が runtime offset を読むため、`Store R4 → fp[whereLayerEntrySlot(LayerPos)]` を emit します。
5. `Add R4, hs` で R4 を進めます。
6. HDRLEN 末尾消費 (`emitPrimaryVariableTail`) として、IPv4 IHL / TCP data_offset の trailing bytes を R4 に加算します。
7. flag-triggered sub-header advance (`emitFlagTriggers`) として、GRE C/K/S 等の flag-gated 4B sub-header を per-flag に R4 advance します。

### 4.4 chain (`+` / `*` / `{n,m}`)

`m≤4` は chain.go で静的アンロールし、それ以上は bpfloop.go の bpf_loop 経由になります。whole-chain skip の `*` は `emitPeekedIterZero` で parent dispatch を peek し、不一致なら chain 全体を skip します。

bpf_loop callback は bpf2bpf subprogram として emit し、BTF `func_info` を `internal/program` 側 wrapper で attach します。callback 内の規約は次のとおりです。

- R6-R9 は verifier 制約により禁忌です。
- ABI は R1==index, R2==ctx です。
- ctx struct は stack 上の 4 slot (すべて u64、各 8 byte) で、`{offset, scratchStart, scratchEnd, layerEntry}` です。base offset は `bpfLoopCtxBaseOffset = -208` で、10b の `maxArithDepth` 8 → 16 bump に伴い -64 シフトしました。各 slot 定数は `bpfloop.go::bpfLoopCtx*Slot` です。

### 4.5 alternation (`(a|b|c)`)

各 alt を sequence 展開します。P3-12 / P3-13 で MVP 制約は大幅に緩和されました。

- alt 数は `altCountCap` により 2-4 です。
- heterogeneous header size に対応しています。per-alt body emit + inline advance により、`(ipv4|ipv6)` で 20 vs 40 byte が動きます。
- alt 後の layer の diverged dispatch に対応しています。`AltConsts` を per-alt に持ち、`matchedAltReg=R5` で per-alt JNE 分岐します。
- ネスト alt は resolver で flatten します。quantifier 付き内側 alt を除き、`((a|b)|(c|d))` → `(a|b|c|d)` になります。
- parent dispatch が無いため、先頭 layer には置けません。
- 内側 alt への quantifier (`(a|b)?`) は意味が違うので reject します。

### 4.6 where 節

短絡評価は次のとおりです。

- AND の左辺が false なら dsl_reject に飛びます。
- OR の左辺が true なら `Ja or_done` で右辺をスキップします。

NOT は inner success label を作って `Ja failLabel` で反転します。

算術は tree walk で R3 に結果を残す契約で、stack に左オペランドを退避します。ネストは `maxArithDepth = 16` の 16 段までです。10b で 8 → 16 に bump し、stack 再配置で `whereLayerEntrySlotBase = -224` / `dynamicAuxOffsetSlotBase = -280` に連鎖シフト、`whereLayerEntrySlotCap = 7` になりました。

het-alt 後の field addressing では、resolver の `markRuntimeOffsetLayers` が het-alt より後ろの layer を `NeedsRuntimeOffset = true` でマークします。codegen は `layerAnchorFor` で、その layer の field load を abs anchor (R0+静的 prefix) ではなく slot anchor (R10[whereLayerEntrySlot] + R0) で emit します。het-alt の無い filter は、slot 経路ゼロ、命令数増加なしの完全 fast path を維持します。詳細は `codegen.go::layerAnchor` 周辺と `where.go::layerAnchorFor` を参照してください。

action atom (`action == NAME`) では、codegen は `caps.Lang.ActionFetcher.EmitFetch(R3)` を呼んで R3 に action u32 をロードする命令列を取得し、続けて `JNE R3, caps.Lang.Action[NAME], dsl_reject` を emit します。既定 fexit ABI (`pkg/kunai/host/xdp.FexitFetcher` / `pkg/kunai/host/tc.FexitFetcher`) は `stack[-48] → args[1]` の 2 段 LDX を返します。BPF tracing args ABI が host 非依存なので EmitFetch ロジックは XDP / tc で共通で、違いは XDP_DROP=1 と TC_ACT_SHOT=2 のような Actions map の値です。`caps.Lang.Action == nil` のときは、host が action 値を提供できないため resolver が atom を拒否します。userspace target 等は `pkg/kunai/host/<name>/` で独自の fetcher を実装すれば再利用可能で、kunai コアは host 知識を持ちません。

### 4.7 capture 節

`headers+N` の N は静的に計算します。chain を含む filter ではコンパイル時に長さを確定できないため reject します。`captureWithXdpOutput(eventsFD, isFexit, maxCapLen)` の `maxCapLen` 引数として wrapper に渡します。per-capture の `where` は filter 全体の `where` と AND 合成します。

`CaptureInfo.MaxCapLen` の解釈では、0 は analyser bail と句なしの両方を含む sentinel で、host 側 fallback を意味します。bpf-ninja host は libpcap 既定の `DefaultCapLen = 1500` を埋めます。つまり `capture` 句を書かなければ tcpdump 互換の full packet capture になります。これは設計上重要な点です。`tcp where dport==443` と書けば payload まで取れるという principle of least surprise を満たすため、`inferMinCapLenFromWhere` の値は `MaxCapLen` には流さず、in-kernel scratch read sizing である `FilterMinPrefix` にのみ流します。ringbuf 予約を縮めて throughput を上げたい場合は `capture headers` 等を明示します。R32 bench script `benchmark/pipelines/r32_dynamic_scratch.sh` はその明示を行っています。

### 4.8 byte-swap trick

eBPF の LDX は x86 上で little-endian で読みます。packet bytes は network order (BE) です。runtime BSwap を avoid するため、codegen 時に定数を byte-swap して LE 形式で immediate に埋めます。`==` / `!=` の単純比較が 1 命令で済みます。`<` や `>` 等の ordered 比較は意味的に LE にできないので、runtime BSwap を入れます。

### 4.9 pinned-map 集合照合 (`layer[field in @NAME]`)

パケットフィールドを pinned BPF hash map に集合照合する述語です。設計の要点は、kunai が map を一切知らない不変条件を保つことにあります。codegen は `FnMapLookupElem` や `LoadMapPtr` を emit せず、`Output` にも map 参照を持ちません。実現は host adapter 境界の典型例となる 2 段構成です。

- kunai 側の `predicate.go::emitInSetPredicate` は、フィールドを境界チェック付きで load し、`HostTo(BE)` で host order の数値に正規化してから、host が指定した R10 スロットに store します。map lookup は emit しません。set atom は verdict に影響させず、レイヤ到達に失敗したときだけ `dslReject` へ飛びます。抽出したスロットは `{SetName, FieldName, StackOff, StoreSize}` を並べた `Output.Extractions` で host に返します。host はスロット offset を `codegen.SetSlotResolver` で渡します。これは `caps.Lang.SetSlots` に置く `ActionFetcher` と同型の注入面で、返すのは int16 offset と幅だけであり、map や FD や BTF は渡りません。
- host 側の `internal/program/setslots.go` は、filter 実行後にそのスロットのバイト列をキーとして `FnMapLookupElem` を emit し、miss なら capture を skip します。この処理は `emitPktSetLookups` にあります。事前に `emitPktSetKeyZeroing` で buffer を zero 埋めし、pad を 0 に保ちます。

制約は次のとおりです。

- エンディアン契約があります。`set add` は `setmap.BuildKey` の `binary.NativeEndian` により host order で書き、パケットは network order です。kunai の `HostTo(BE)` 正規化と host の native store で両者を一致させます。ここがずれると全 miss するので、差分テストの `TestBpfDSLSetMatchPacketField` が守ります。
- スタックに制約があります。抽出スロットは filter 実行中に書かれ filter 後に読まれるため、kunai 領域の `[-56, ...)` には置けません。両 attach path で空いている 16 バイトの host 領域 `[-40, -24)` を使うので、合計キー幅は 16 バイトまで、1 フィールドは 8 バイトまでです。
- 構文は bracket predicate 専用で、`where` 句では使えません。bracket は layer の連言に必ず入るので、`@set` は構造的にトップレベルの AND になり、v1 の集合は AND という意味論と一致します。複合キーは 1 つの角括弧にカンマ併記します。
- `any` や `all` の aux にあたる iterator-stack 上のフィールドは、last-write-wins になるため resolver が拒否します。

### 4.10 キャプチャレコードのメタデータ

`captureWithRingbuf` と `captureXDPNative` は ringbuf スロットの先頭に 20 バイトのメタデータヘッダを置き、その後ろにパケット本体を続けます。正典は `internal/capture/capture.go` のコメントで、capture 側の `MetadataSize` と program 側の `metadataSize` は `TestMetadataSizeMatchesCapture` が同期を保証します。

レイアウトは次のとおりです。全フィールドはホストエンディアンで、BPF の store がネイティブエンディアンで書くため、ユーザー空間は `binary.NativeEndian` で読みます。

| offset | size | field | 意味 |
| --- | --- | --- | --- |
| 0 | 8 | kernel_ts_ns | ingest 時の `bpf_ktime_get_ns` または HW rx timestamp |
| 8 | 4 | action | XDP action。fexit のみ有効で、fentry と xdp-native は固定値 |
| 12 | 1 | mode | 0 が entry、1 が exit、2 が xdp-native |
| 13 | 1 | _pad | 予約 |
| 14 | 2 | caplen | コピー済みパケット長 |
| 16 | 4 | tag | マッチした set エントリの value。set 未マッチや set 無しのときは 0 |

tag は set lookup がヒットしたときに host スタックの専用スロット経由で書きます。複数の set をまたぐときはソース順で最後にマッチした set の value が入ります。value 幅が 8 バイトのときは下位 32 ビットだけを載せます。この tag を使ってパケットを set の value ごとに別々の pcap へ振り分ける機能が CLI の `--split-by-tag` で、詳細は [`dsl-usage.md`](./dsl-usage.md) を参照してください。

## 5. P4-16 互換性

`pkg/kunai/vocab/p4lite/` は、bpf-ninja の vocab loader が `.p4` ファイルを読むための P4-16 の限定サブセットのパーサです。

実装ファイルは次のとおりです。

- `lexer.go` (319 行) はトークナイザとキーワード認識です。
- `parser.go` (589 行) は recursive descent です。
- `types.go` (136 行) は AST 型です。

結論として、p4lite は P4-16 の strict subset であり、P4-16 仕様の範囲内に収まっています。p4c が parse できる範囲ですが、action / table / control / apply / extern という明示的な reject keyword は p4lite で弾きます。

### 5.1 サマリ表

| 領域 | P4-16 | p4lite | 評価 |
|---|---|---|---|
| Top-level decl | header / struct / header_union / enum / error / match_kind / typedef / type / extern / action / table / control / parser / package / instantiation / const | header / const / parser | strict subset |
| Header field 型 | bool / error / match_kind / `bit<N>` / `int<N>` / `varbit<N>` / typedef'd / struct nest / header stack | `bit<N>` のみ | strict subset |
| Const 型 | 任意 typeRef + 任意 expression | `bit<N>` (1..64) + `bool`、整数リテラルのみ | strict subset |
| Parser パラメータ direction | in / out / inout / 無指定 | `packet_in` / `out` のみ | strict subset (architecture 依存) |
| Parser local element | const / var / instantiation / value_set | 無し | strict subset |
| Parser statement | assignment / method call / direct application / block / conditional / const / var / empty | `obj.extract(target)` / `obj.extract(target.next)` のみ | strict subset |
| Transition | accept / reject / state name / select | 同左 | full |
| Select case keyset | 整数 / default / `_` / mask (`val &&& mask`) / range (`a..b`) / 名前参照 / tuple | 整数 / `_` / default / tuple | mask & range 未対応 |
| 整数リテラル | 10進 / 0x hex / 0o oct / 0b bin / sized (`4w0xff`, `8s10`) | 10進 / 0x hex のみ | bin / oct / sized 未対応 |
| Annotation (`@name`) | 全所に書ける | 一切受けない | strict subset |
| コメント | `//` / `/* */` | 同左 | full |

### 5.2 p4lite が拒否するもの

`vocab/p4lite/lexer.go::rejectedKeywords` で明示的に reject するのは次のキーワードです。

- `action`, `table`, `control`, `apply`

これらが書かれた `.p4` ファイルを読むと `p4lite does not support "..."` エラーになります。`extern` は受理されますが、vocab loader が認識する extern は B-5 / mechanism 8 の `ParserCounter` のみです。Hash / Counter / Register / 任意の architecture extern といった他の extern は、parser 段階で本体を opaque-skip し、loader が silently 無視します。

これ以外の P4-16 上位宣言 (`struct`, `header_union`, `enum`, `error`, `match_kind`, `typedef`, `type`, `package`) は明示 reject 対象ではありませんが、トップレベルで `header` / `const` / `parser` 以外のキーワードに遭遇すると `expected 'header', 'const', or 'parser'` エラーで弾かれます。

### 5.3 P4-16 で valid だが p4lite が reject するもの

いずれも vocab 用途で意味を持たないと判断して除外しています。

- `action`, `table`, `control`, `apply` は match-action パイプライン定義です。kernel verifier に通る eBPF を直接吐く bpf-ninja では使いません。
- `extern` の本体ボディについて、match-action / external function call を意味する extern は意味的に未対応です。ただし B-5 で `ParserCounter` のみ extern 宣言として受理しています。lexer は `extern` を accept し、parser は本体を opaque-skip し、vocab loader が ParserCounter インスタンス化を認識します。`Hash`、`Counter`、`Register` 等の通常の P4 architecture extern は loader が無視します。
- `varbit<N>` と header stacks 内宣言は、動的長 header / オプション解析のためのものです。今は scratch 512B 内の静的フィールドアクセスのみです。
- value_set は runtime に変動する match 集合です。
- `int<N>` / `bool` field は、flag 系を `bit<1>` で書く慣習で代替します。
- 名前参照 const / 式 const (`const bit<8> A = B + 1;`) は、vocab 内で計算が不要なため除外しています。
- mask / range match は DSL の `where` で代替します。

### 5.4 P4-16 が reject するのに p4lite が通すケースの監査

確認した結果、該当はありませんでした。

確認した観点は次のとおりです。

1. `header` field 型は `bit<N>` のみで、P4 でも合法です。
2. `const` の bit 幅は 1..64 です。P4 では上限がなく、p4lite で狭めただけです。
3. `parser` パラメータは `packet_in` / `out` のみで、P4 の direction の subset です。
4. `extract` 引数 `obj.extract(target.next)` は、P4 の header stack の `.next` プロパティと一致します。
5. `select` のキーの dotted path は、P4 では expression なので `a.b.c` も許容され、subset です。
6. `select` case の値は整数または `_` で、P4 の subset です。
7. キーワードの大文字小文字は P4 と同じ lowercase です。

### 5.5 動作確認

`pkg/kunai/protocols/*.p4` は、本物の p4c で `--parse-only` を通過するように CI (`.github/workflows/p4c-check.yml`) で検証しています。ローカルでは `make p4c-check` または `./scripts/p4c-check.sh` を使います。詳細は [`dsl-followups.md`](./dsl-followups.md) P0-4 を参照してください。

加えて `go test ./pkg/kunai/vocab/...` が `dslvocab.Bundled` 経由で全 `.p4` を 1 度パースしているので、Go test が通れば、全 vocab が p4lite subset (= P4-16 の strict subset) に収まることの二重確認になります。

### 5.6 将来の拡張余地

| 拡張 | 動機 | 工数感 |
|---|---|---|
| Annotation `@name(...)` 受理 (無視) | 公式 P4 例が貼り付けやすい | 小 (lexer に `@` 追加) |
| `#include` / `#define` / `#pragma` skip | 既存 P4 hdr ファイルから流用 | 小 (lexer 拡張) |
| Sized integer literal `Nw0xVal` | 公式 P4 風の見た目 | 小 |
| `0b` バイナリリテラル | bit field の意図が読みやすい | 微小 |
| `varbit<N>` field | TCP options など可変 header | 中 (codegen 連動) |
| `match_kind`, `range`, `mask` | より柔軟な select | 中 |
| `typedef` / `type` | 型 alias で DRY | 小〜中 |
| `value_set` | 動的 vocab の上手な扱い | 大 |

### 5.7 参考

- [P4-16 公式仕様 v1.2.5](https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html) (BNF は §G の Appendix: P4 grammar)
- [p4c parser grammar](https://github.com/p4lang/p4c/blob/main/frontends/parsers/p4/p4parser.ypp)

## 6. 可変長構造の分類と表現

ネットワークプロトコルの可変長部分には複数の形があります。kunai DSL では、どのパターンを chain として書かせ、どのパターンを wrapper の aux として表現するかを設計判断として明確にしています。本節では分類とその表現指針を述べます。

### 6.1 4 パターンの分類

実 protocol の可変長構造は、wire 形上 4 つの基本パターンに分類できます。

| # | パターン | 例 | 構造の特徴 |
|---|---|---|---|
| A | 全体繰り返し (層スタック) | VLAN, MPLS, QinQ | wire 上で同じ shape の header が back-to-back に並ぶ。各 entry が独立 |
| B | 拡張ヘッダ繰り返し | IPv6 ext, GTP-U ext header | wrapper の中に extension header が並ぶ。各 ext は次 type を field で持つ |
| C | wrapper + 内部項目列 | SRv6 segment list (16B 固定), TCP/IPv4 options (kind 依存可変) | 1 つの wrapper の中に items が並ぶ。entry 自体には dispatch 情報がない |
| D | wrapper + 条件付き単発 | GTP-U opt (E/S/PN flag gated) | wrapper の flag で有無が決まる、最大 1 回 |

これらの判別基準は wire 構造です。

- 外側に独立した header が並ぶ形 (A) なら chain です。
- wrapper の内側に sub-header が入っている形 (B/C/D) なら wrapper の aux です。

### 6.2 表現指針: chain vs aux

vocab 上の表現は 2 種類です。

#### chain protocol (パターン A)

独立した protocol を vocab で 1 つ宣言し、quantifier (`+` `*` `?` `{n,m}`) で repetition を表します。DSL 上は wire 順に並んだ別 layer として次のように書きます。

```
eth/vlan+/ipv4/tcp                ; VLAN tag (1 個以上)
eth/mpls+/ipv4/tcp                ; MPLS label stack
eth/qinq/vlan+/ipv4/tcp           ; QinQ (S-tag + C-tag stack)
```

vocab 側は `KUNAI_<SELF>_<PARENT>_<FIELD>` 系の dispatch const で、どこから始まりどこで終わるかを declare します。

#### wrapper + aux header (パターン B/C/D)

1 個の protocol が、primary header と 0 個以上の aux header を持つ形です。aux は parser block の `out` 引数として宣言し、parser の state machine がいつ extract するかを記述します。DSL 上は wrapper protocol の 1 layer として書き、内部の aux は dot path で次のようにアクセスします。

```
; パターン B: 拡張ヘッダ繰り返し
eth/ipv4/udp/gtp/ipv4/tcp where any(gtp.exts.ext_type == 0xc0)
eth/ipv4/udp/gtp/ipv4/tcp where gtp.exts.count >= 1
eth/ipv6/tcp where any(ipv6.exts.next_header == 44)              ; Fragment ext あり

; パターン C: wrapper + 内部項目列
eth/ipv6/srv6/tcp where srv6.segments[0].addr == fc00::1         ; final dest
eth/ipv6/srv6/tcp where srv6.segments[srv6.last_entry].addr == X ; first hop
eth/ipv6/srv6/tcp where any(srv6.segments.addr == fc00::1)       ; ∃
eth/ipv4/tcp where tcp.options.MSS.value == 1460                 ; TCP option (固定 size)
eth/ipv4/tcp where tcp.options.TS.tsval > 1000000

; パターン D: wrapper + 条件付き単発
eth/ipv4/udp/gtp/ipv4/tcp where gtp.opt.exists
eth/ipv4/udp/gtp/ipv4/tcp where gtp.opt.next_ext == 0
```

### 6.3 パターン C/D の判定基準: 中身か外か

VLAN や MPLS を eth の aux と呼ぶことはしません。理由は VLAN/MPLS の wire 構造にあります。

- VLAN tag は ethertype (0x8100) で type-of-next を持っており、外側に並ぶ存在です。
- MPLS label は s-bit で stack 終端を持っており、同様です。

これらは eth の中身ではなく、eth の後ろに並んだ別 protocol layer なので chain (パターン A) です。

一方、SRv6 の segment list は次の特徴を持ちます。

- SRH header の last_entry/segments_left field で長さが決まります。
- 各 segment は IPv6 アドレスのみで type-of-next を持ちません。
- segments だけ抜き出して別解釈することは不可能で、SRH header と segments は不可分の 1 セットです。

これは明確に SRH の中身であり、aux (パターン C) です。

GTP の opt も同様です。GTP header の E/S/PN flag で有無が決まるもので、独立 layer ではありません。

### 6.4 過去の設計検討と現方針

開発初期に `srv6_seg` を独立 chain protocol として切り出す案 (`eth/ipv6/srv6/srv6_seg+/tcp`) を実装しましたが、aux model に切り替えました。判断理由は次のとおりです。

1. wire 構造に対して不誠実です。`srv6/srv6_seg+` は srv6 の後ろに srv6_seg が連なる構造に読めますが、実際は SRH 1 個とその中の segment 列であり、構造が二段に分離して見えるのは misleading です。
2. ネスト SRH (SRH/SRH、Segment Routing over Segment Routing) と区別が困難です。chain として書くと `srv6/srv6_seg+/srv6/srv6_seg+/...` と書ける一方、それがネスト SRH なのか外側 SRH の segment 列の続きなのか、visually に判別できません。
3. 概念が重複します。chain mechanism と aux mechanism がリスト的な構造を 2 系統で扱うことになり、user にとって学ぶ概念が増えます。

aux model 採用後に user から見える概念は、次の 2 つです。

- chain protocol (`+` quantifier、`vlan+` のような外側スタック)
- wrapper + aux (`protocol.aux_name`、`srv6.segments[N]` のような内側構造)

この 2 つに整理されたことで、wire 構造との対応が一目瞭然になります。

### 6.5 vocab declaration mechanism (8 種)

§6.1 の wire パターン (A/B/C/D) に対し、vocab 著者が使える declaration mechanism は 8 種類あります。1 つの protocol が複数の mechanism を併用することも一般的です。例えば TCP は、mechanism 1 (`pkt.advance` template-A) で固定 trailer を確保しつつ、その中身は mechanism 7 (TLV options walk) で読みます。

| # | mechanism | declare 方法 | 対応 wire パターン | 例 protocol | codegen 入口 |
|---|---|---|---|---|---|
| 1 | pkt.advance trailer | parser block の skip-state で `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)` 1 行 | primary header の variable trailer | IPv4 (IHL × 4 - 20)、TCP (data_offset × 4 - 20) | `parser_trail.go::emitVariableTrail*` |
| 2 | chain self-loop | `<SELF>_CHAIN_END_<FIELD>` + `<SELF>_MAX_DEPTH` | A: 全体繰り返し | MPLS (s-bit)、VLAN+、QinQ | `bpfloop.go::chainEndCheck` |
| 3 | parser self-loop | parser block の state 自己 transition | B: 拡張ヘッダ繰り返し | IPv6 ext (`parse_ext` self-loop) | `parser_state.go` state graph + `parser_loop.go::emitSelfLoop` |
| 4 | aux header stack | `out h_t[N] name` + parser state | B/C: wrapper 内要素列 | SRv6 segments、GTP exts | `parser_state.go` + `codegen.go::emitDynamicStackAddress` |
| 5 | gated single aux | `out h_t name` + transition select で gating | D: 条件付き単発 | GTP opt (E/S/PN flag gated) | `parser_state.go` state graph |
| 6 | flag-triggered optional fields | `<SELF>_OPT_FLAGS_BYTE_OFFSET` + `<SELF>_OPT_TRIGGER_<NAME>` + `<SELF>_OPT_LEN_<NAME>` | D の集合体 (flag 群が固定 size optional を gating) | GRE (C/K/S → checksum/key/seq) | `codegen.go::emitFlagTriggers` |
| 7 | TLV options walk | parser block multi-state self-loop (`parse_options → parse_<name> → parse_options`) + per-option aux header (`tcp_opt_<name>_h`) | C の TLV variant | TCP options (MSS/WS/SACK_PERM/TS/SACK) | `parser_loop.go::emitMultiStateSelfLoop` (lifted slot-store prelude) + `where.go::genDynamicOffsetAuxLoad` |
| 8 | ParserCounter trailer walk | `extern ParserCounter { ... }` + `ParserCounter() pc;` + `pc.set(...)` / `pc.decrement(N)` + 1-key `select(pc.is_zero())` または 2-key `select(pc.is_zero(), pkt.lookahead<bit<8>>())` (TNA canonical) | byte-bounded walk (mechanism 1 の per-byte 版、mechanism 7 の terminator 兼用版) | IPv4 options (Router Alert)、dsltest 経由 synthetic 検証 | `parser_counter.go` + `parser_loop.go::emitMultiState{Counter,CounterKind}Dispatch` |

ユーザーが可変長と認識しがちな代表例 4 つの内訳は次のとおりです。

- TCP/IPv4 タイプは mechanism 1 (pkt.advance trailer) です。TCP はさらに mechanism 7 (TLV walk) を併用して中身を読みます。
- MPLS タイプは mechanism 2 (chain self-loop) です。
- SRv6 タイプは mechanism 4 (aux header stack) です。
- GTP タイプは mechanism 5 (gated single aux の `opt`) と mechanism 4 (aux stack の `exts`) を併用します。

これに加えて vocab 著者向けに、mechanism 3 (IPv6 ext のような異 type ext-header chain) と mechanism 6 (GRE のような flag-triggered optional) と mechanism 7 (TLV walk) が利用できます。

以下、各 mechanism の declare 方法を順に示します。mechanism 2 (chain self-loop) と mechanism 6 (flag-triggered) は const 宣言だけで表現でき、parser block は単一 state の trivial なもの (extract + accept) で済みます。残り (mechanism 1 pkt.advance / parser self-loop / aux / aux stack / gated aux / TLV walk / ParserCounter) は parser block の state machine で表現します。

以下の sub-section は、文書化の経緯から 1→2→3→5→4→7→6→8 の順に並んでいます。表の番号で目的の mechanism にジャンプして読むと効率的です。

#### Mechanism 1: pkt.advance trailer (TCP / IPv4 タイプ)

primary header の末尾に、長さ可変の trailer が付く形です。長さは header 内の field (IPv4 IHL、TCP data_offset) × scale で計算できます。parser block の skip-state で P4-16 標準の `pkt.advance` template A を 1 行 declare すれば、loader が field 位置 / mask / shift を自動導出して、codegen が長さ計算 + R4 advance + bound check を emit します。

```p4
// ipv4.p4
parser IPv4Parser(packet_in pkt, out ipv4_h hdr) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.version) {
            4:       skip_options;
            default: reject;
        }
    }
    state skip_options {
        pkt.advance(((bit<32>)(hdr.ihl - 5)) << 5);  // (ihl - 5) × 32 bit = (ihl - 5) × 4 byte
        transition accept;
    }
}
```

template は次のように解釈します。`pkt.advance(((bit<N>)(hdr.<F> - K)) << S)` を `(field × 2^(S-3) byte) - (K × 2^(S-3) byte)` の trailer 長と読みます。IHL < 5 のような `< 0` は、codegen の lower-bound check で loud reject します。trailer そのものには dot path で access できず、options 領域があることだけを把握している状態です。中身を読みたい場合は mechanism 7 (TLV walk) を併用します。

B-2 以前は `<SELF>_HDRLEN_BYTE_OFFSET / MASK / SHIFT / SCALE / BASE` の 5 const を手書きで宣言していました。これは header struct の field 位置と redundant で、struct を編集すると 5 const が気づかれないまま壊れる footgun でした。B-2 で parser block 経由に統一し、HDRLEN_* 系は loud reject になりました。

#### Mechanism 2: chain self-loop (MPLS タイプ)

同 shape の header が back-to-back に並ぶ形です。終了条件は、MPLS の S-bit のような header 内の終端 bit で次のように declare します。

```p4
// mpls.p4
const bit<1> MPLS_CHAIN_END_S    = 1;          // S-bit == 1 で stack 末尾
const bit<8> MPLS_MAX_DEPTH      = 8;          // verifier-safe loop 上限
```

DSL 上は `mpls+` quantifier で書きます。codegen は bpf_loop subprogram に展開し、各 iter で `<SELF>_CHAIN_END_<FIELD>` の field を読んで break 判定します。

#### Mechanism 3: parser self-loop (IPv6 ext タイプ)

parser block の state が、自己 transition で次の ext header に進む形です。各 ext header の type (next_header) が次の ext type を指す chain です。aux header の固定 reservation 数 (`out h_t[N]`) で、verifier-safe な loop 上限を次のように持たせます。

```p4
// ipv6.p4 (抜粋)
parser IPv6Parser(packet_in pkt, out ipv6_h hdr, out ipv6_ext_h[8] exts) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.next_header) {
            0, 43, 44, 50, 60, 135: parse_ext;  // ext header 系
            default: accept;                    // 上位 L4
        }
    }
    state parse_ext {
        pkt.extract(exts.next);
        transition select(/* exts.last.next_header */) {
            ...: parse_ext;                     // 自己 loop
            default: accept;
        }
    }
}
```

DSL では `any(ipv6.exts.next_header == 44)` のように、fragment 拡張ヘッダの存在判定などに使います。

#### Mechanism 5: gated single aux (GTP opt タイプ、パターン D)

```p4
// gtp.p4
header gtp_h     { bit<3> version; ... bit<1> e; bit<1> s; bit<1> pn; ... }
header gtp_opt_h { bit<16> seq; bit<8> npdu; bit<8> next_ext; }

parser GtpParser(packet_in pkt,
                   out gtp_h     gtp,
                   out gtp_opt_h opt) {
    state start {
        pkt.extract(gtp);
        transition select(gtp.e, gtp.s, gtp.pn) {
            (0,0,0): accept;            // opt 未抽出のまま
            default: parse_opt;
        }
    }
    state parse_opt {
        pkt.extract(opt);
        transition accept;
    }
}
```

DSL での `gtp.opt.exists` は、`parse_opt` state に到達したかを runtime で確かめます。`gtp.opt.next_ext` は、opt が extract された場合のみ field を読み、未抽出なら predicate 不一致になります。

#### Mechanism 4: aux header stack (SRv6 タイプ、パターン B/C)

P4 の header stack `H[N]` を使います。bundled SRv6 は注釈ゼロの element-driven walk です。ParserCounter をセグメント数 (`last_entry + 1`) で seed し、`consume_seg` で 1 要素ずつ push しながら counter を 1 減らします。`@kunai_layout` / `@kunai_stack_count` / `@kunai_variable_tail` は一切使いません。要素数も next-header 位置も、この walk の形から loader / codegen が導出します。

```p4
// srv6.p4
header srv6_h     { bit<8> next_header; ... bit<8> last_entry; ... }
header srv6_seg_h { bit<128> addr; }

// routing_type 4 は SRH を表す value-only const (phantom parent なので KUNAI_ 無し)
const bit<8> SRV6_ROUTING_TYPE = 4;

parser SRv6Parser(packet_in pkt,
                    out srv6_h        hdr,
                    out srv6_seg_h[8] segments) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        pc.set((bit<8>)(hdr.last_entry + 1));   // セグメント数 = last_entry + 1
        transition select(hdr.routing_type) {
            SRV6_ROUTING_TYPE: walk;
            default:           reject;
        }
    }
    state walk {
        transition select(pc.is_zero()) {
            true:  accept;
            false: consume_seg;
        }
    }
    state consume_seg {
        pkt.extract(segments.next);             // 16 byte を 1 個 push
        pc.decrement(1);                        // 1 要素ぶん減らす
        transition walk;
    }
}
```

`pc.set((bit<8>)(hdr.last_entry + 1))` の bare-cast add 形 (scale=1) と `pc.decrement(1)` の組が、この walk を element-driven にします。loader (`deriveStackCountsFromCounters`) は push + element-granular decrement を同じ state に見つけ、seed フィールド (`last_entry`) と addend (`+1`) から `any` / `all` の要素数を `last_entry + 1` と導出します。`@kunai_stack_count` は不要で、明示宣言があればそれが優先される仕組みは残しています。

stack の reservation 数 (上の例では 8) は、verifier-safe な loop 上限として codegen が利用します。DSL の `srv6.segments[N].addr` は `layer_entry + 8 (primary) + N × 16 + 0` の静的アドレス算出でロードされ、scratch 上の bytes を読みます。stack の base は `consume_seg` が push するため push state の layer-entry offset (= `sizeof(srv6_h)` = 8) から自然に決まり、`@kunai_layout` は不要です。

next-header 位置も同じ count から決まります。codegen は walk 収束後に R4 を `layer_entry + 8 + (last_entry+1)*16` へ再アンカーします。TLV を持たない SRH では segment list の末尾がそのまま next header になる (RFC 8754) という性質を使った再アンカーです。逆に TLV 付き SRH を chain で越えるのは非対応で、R4 が segment list の末尾で止まるため、末尾 TLV を持つ SRH の後ろに別レイヤを繋ぐ (`eth/ipv6/srv6/tcp` 等) と next header に届きません。TLV サポートは RFC 8754 Section 2 で optional なので規約準拠の制限です。segment 参照 (`srv6.segments[N]`、`any` / `all`) は末尾 TLV の有無に関わらず正しく動きます。

#### Mechanism 7: TLV options walk (TCP options タイプ、パターン C 可変)

各 option を kind ごとに独立 aux header として declare し、parser block の multi-state self-loop が kind dispatch + sibling extract で walk します。where 句から option の field を読むときは、parser machine が記録した per-packet オフセットを stack slot から引いて直接 LDX します。legacy の where-time 再 walk は B6 で削除済みです。

> 同じ TLV から複数 option を 1 つの `where` で問い合わせる場合 (`MSS.value == 1460 and WS.shift == 7` など) は、記録 slot を N 個持つと verifier が爆発するため、bit accumulator + forget で 1 本の bpf_loop に畳む別経路に乗ります。仕組みは [`dsl-multi-option-accumulator.md`](./dsl-multi-option-accumulator.md) を参照してください。

```p4
// tcp.p4
header tcp_h               { ... bit<4> data_offset; ... }
header tcp_opt_mss_h       { bit<8> kind; bit<8> length; bit<16> value; }
header tcp_opt_ws_h        { bit<8> kind; bit<8> length; bit<8>  shift; }
header tcp_opt_sack_perm_h { bit<8> kind; bit<8> length; }
header tcp_opt_ts_h        { bit<8> kind; bit<8> length; bit<32> tsval; bit<32> tsecr; }

const bit<8> TCP_PARSER_MAX_DEPTH = 32;

parser TcpParser(packet_in pkt,
                   out tcp_h               hdr,
                   out tcp_opt_mss_h       mss,
                   out tcp_opt_ws_h        ws,
                   out tcp_opt_sack_perm_h sack_perm,
                   out tcp_opt_ts_h        ts) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.data_offset) {
            5:       accept;
            default: parse_options;
        }
    }
    state parse_options {
        transition select(pkt.lookahead<bit<8>>()) {
            0:       accept;       // EOL
            1:       parse_nop;
            2:       parse_mss;
            3:       parse_ws;
            4:       parse_sack_perm;
            8:       parse_ts;
            default: parse_unknown_opt;
        }
    }
    state parse_nop          { pkt.advance(8);         transition parse_options; }
    state parse_mss          { pkt.extract(mss);       transition parse_options; }
    state parse_ws           { pkt.extract(ws);        transition parse_options; }
    state parse_sack_perm    { pkt.extract(sack_perm); transition parse_options; }
    state parse_ts           { pkt.extract(ts);        transition parse_options; }
    state parse_unknown_opt {
        pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3);
        transition parse_options;
    }
}
```

option の identity (kind 値) は parser block の `transition select` case label が pin し、wire size は `header tcp_opt_<name>_h` 宣言が pin します。`vocab.AuxLayout.DynamicKindByte` が loader で復元されるため、vocab に追加の `OPT_<NAME>_KIND/SIZE` const は不要です。

Codegen 経路では、`parse_options → parse_<kind> → parse_options` の cycle を `IsMultiStateLoopEntry` predicate (`pkg/kunai/vocab/parser_machine.go`) が検出し、`emitMultiStateSelfLoop` (`pkg/kunai/codegen/parser_loop.go`) が bpf_loop callback に下ろします。

callback の per-iter 構造 (Phase 2 retry 設計) は次のとおりです。

1. ctx slot から `R3 = current option offset` / `R4 = scratchStart` / `R5 = scratchEnd` を再 load します。
2. `JGT R3, ScratchBufSize-1, breakLabel` で R3 の上限を pin し、verifier が stack spill 越しに失う bound を取り戻します。
3. `R0 = R4 + R3 + 1; JGT R0, R5, breakLabel` で、次 1 byte の peek bound check を行います。
4. Lifted slot-store prelude として、kind byte を R1 に load し、where / capture が query した option ごとに `JNE R1, kindByte, .skip; StoreMem R2, slot, R3; .skip:` を flat に並べます。slot は main frame の per-LayerInstance アドレスで、callback からは `R2 + (slot - bpfLoopCtxOffsetSlot)` (`mainStackOffsetFromCb` helper) で reach します。
5. cascade dispatch を行います。kind 比較の後、各 case body で extract / advance と R3 store-back を実施します。

prelude を cascade の outside に置くのが重要です。per-iter の slot 状態は kind byte だけの関数になり、verifier が、どの case が走ったかとどの slot が変わったかの組み合わせを per-iter で track せずに済みます。これが 6.12+ の 1M-insn 限界に収まる根拠です。per-case slot store で実施した失敗パターンは、`dsl-followups.md` B-3 の 2026-05-04 試行記録に残してあります。

Demand-driven 割当では、codegen は `collectQueriedOptions(p)` (`pkg/kunai/codegen/option_demand.go`) で program 全体の where、各 layer の bracket predicate、各 capture を walk し、参照された (layer, option) ペアだけ slot を割り当てます。`where tcp.options.MSS.value == 1460` だけなら slot は 1 個です (per-layer × per-aux で最大 5 まで、`dynamicAuxMaxSlotsPerLayer` = TCP の queryable kind 数)。layer entry では `emitDynamicAuxSentinelInit` が各 slot を sentinel `-1` で zero-init します。extract されなかった option は sentinel のまま残り、where 評価で reject されます。

Where 評価では、`tcp.options.MSS.value == 1460` のような predicate は `genArithFieldLoad → dynamicOffsetSlotFor → genDynamicOffsetAuxLoad` (`pkg/kunai/codegen/where.go`) の経路をたどります。

1. slot を R3 に LDX します。値は MSS 先頭の absolute scratch offset、または sentinel です。
2. `JEq R3, sentinel, dslReject` で、option 不在時に predicate を false にします。
3. `foldOffsetIntoScalar(R5, R3, fieldByteOff)` で field 開始位置を scalar に載せます。
4. `boundedScalarLoad(R3, R0, R5, R1, size)` で実際の field bytes を read します。

合計 ~6 insn です。pre-Phase-2 の `genOptionLookupLoad` は 20 iter static unroll で ~200 insn だったので、桁が 1 つ減っています。

Vocab 著者の作業は、`header tcp_opt_<name>_h { ... }` を declare し、parser block の `transition select` case label に kind を書き、sibling state で `pkt.extract(<name>)` するだけです。`OPT_<NAME>_KIND/SIZE` 等の冗長 const は不要です。resolver は `tcp.options.MSS` の `MSS` を lower-case 化して `AuxLayouts["mss"]` を引き、`IsDynamicEligible` を assert します。

#### Mechanism 6: flag-triggered optional fields (GRE タイプ)

primary header の flag bit が、複数の固定 size optional field を gating する形です。GRE の C/K/S flag が checksum / key / sequence の有無を決めるのが代表例です。`OPT_FLAGS_BYTE_OFFSET` で flag byte の位置を、`OPT_TRIGGER_<NAME>` で各 flag の bit mask を、`OPT_LEN_<NAME>` で対応 optional field の byte size を次のように declare します。

```p4
// gre.p4 (抜粋)
const bit<8> GRE_OPT_FLAGS_BYTE_OFFSET = 0;
const bit<8> GRE_OPT_TRIGGER_C         = 0x80;   // checksum present
const bit<8> GRE_OPT_TRIGGER_K         = 0x20;   // key present
const bit<8> GRE_OPT_TRIGGER_S         = 0x10;   // sequence present
const bit<8> GRE_OPT_LEN_C             = 4;      // checksum field 4 byte
const bit<8> GRE_OPT_LEN_K             = 4;
const bit<8> GRE_OPT_LEN_S             = 4;
```

codegen は flag byte を読んで、各 trigger bit が立っていれば対応する LEN だけ R4 を advance する命令列を、`codegen.go::emitFlagTriggers` で順に emit します。parser block を書く必要はありません。NAME は uppercase の任意 token で、TRIGGER と LEN を NAME で対応付けます。

mechanism 5 (gated single aux) との違いは次のとおりです。

- 5 (gated aux) は aux header として field が見え、`gtp.opt.next_ext` で値を読めます。
- 6 (flag-triggered) は trailer 領域の確保のみで、optional field の値は現状読めません。GRE の checksum/key/sequence は、存在を検出して下流 ipv4/ipv6 への dispatch を正しく動かす目的で十分だからです。

#### Mechanism 8: ParserCounter trailer walk (Tofino TNA 互換)

mechanism 1 (pkt.advance trailer) と mechanism 7 (TLV walk) の両方には、R4 alignment 上の限界があります。

- mechanism 1 は trailer を 1 回の bulk advance で skip するため、中身を per-element に extract できず、TCP options 各 kind の位置を記録できません。
- mechanism 7 は kind dispatch で walk しますが、EOL kind が `accept` で R4 が trailer 中位置で停止します。TCP は terminal なので無害ですが、`tcp/<inner>` chain や IPv4 options walk のように R4 を trailer 末尾まで進めたい場合は align しません。

ParserCounter (Tofino TNA / P4-16 PSA の標準 extern) は、残り byte 数を per-iter で減らし、0 に達したら walk を終了するという counter-driven 終端を表現します。

```p4
// 合成 IPv4 vocab (実物は pkg/kunai/dsltest/parser_counter_test.go)
extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

const bit<8> IPV4_MAX_DEPTH = 11;     // 40-byte trailer / 4 bytes per iter + 1

parser IPv4Parser(packet_in pkt, out ipv4_h hdr) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        pc.set(((bit<8>)(hdr.ihl - 5)) << 5);   // bytes = (ihl - 5) × 4
        transition select(hdr.version, hdr.ihl) {
            (4, 5):  accept;       // IHL=5 fast path: trailer 0 bytes
            (4, _):  walk;
            default: reject;
        }
    }
    state walk {
        transition select(pc.is_zero()) {
            true:  accept;
            false: consume;
        }
    }
    state consume {
        pkt.advance(32);             // 4 bytes (IPv4 option word)
        pc.decrement(4);
        transition walk;
    }
}
```

設計判断は次のとおりです。

- counter unit は byte です。Tofino の 32-bit word 単位とは異なる BPF-native の選択です。`pc.set` の引数は byte count で、`pc.set(((bit<8>)(hdr.ihl - 5)) << 5)` は `(ihl-5) × 4 byte` を意味します。`pc.decrement(N)` の N も byte です。
- slot 確保は per-machine reused で、machine の生存期間中だけ意味を持ちます。`pkg/kunai/codegen/parser_counter.go` が、bpf_loop ctx と where-layer slot の間の gap 領域に最大 2 slot を配置します。layer をまたいで再利用されます。
- api compat の面では、`extern ParserCounter { ... }` 宣言は p4lite が opaque-skip するので、Tofino spec の method signature をそのまま書けます。upstream p4test の --parse-only に相当する `make p4c-check` も通ります。
- multi-state loop entry の認識では、`vocab.IsMultiStateLoopEntry` が 3 種の key 形を受理します。単 `SelectKeyLookahead{Bits=8}` は mechanism 7 の kind-byte dispatch のみ、単 `SelectKeyCounterIsZero` は counter 終端のみ、2-key tuple `(SelectKeyCounterIsZero, SelectKeyLookahead{Bits=8})` は counter 終端 + per-iter kind dispatch の TNA canonical 形です。tuple は順序固定で、reverse は `validateStateGraph` が `no lowering for` で reject します。codegen の `emitMultiStateDispatch` が、それぞれ `emitMultiStateCounterDispatch` (1-key)、`emitMultiStateCounterKindDispatch` (2-key)、kind-only cascade に dispatch します。

Codegen 経路は次のとおりです。

1. Slot init では、machine entry で `emitCounterSlotInit` (`emitFillStackSlots` 経由) が全 declared counter slot を 0 で初期化し、BPF verifier の uninitialized stack read を回避します。
2. `pc.set(...)` は、AdvanceField と同じ `lowerCastShiftSkip` 経由で `((header_byte & mask) >> shift) * scale - base` を scratchA に計算し、StoreMem で slot へ書き込みます。
3. `pc.decrement(N)` は `LoadMem slot → R5; Sub.Imm R5, N; StoreMem slot, R5` の 3 insn です。BPF は memory-form arith を持たないため、これが最小です。
4. `pc.is_zero()` select は、`LoadMem slot → R3; JEq.Imm R3, 0, trueLabel` の probe + 2-arm 分岐です。2-key tuple `(pc.is_zero(), pkt.lookahead<bit<8>>())` 形では、probe で counter==0 を `trueLandingLabel` に分岐させた後、kind byte を load して `(false, K)` cases の cascade (per-case JNE → sibling body → skip landing) を並べ、最後に `(false, _)` または `sel.Default` をフォールスルーし、tail に `trueLandingLabel` を置いて `(true, _)` body を emit します。kind-byte の load 位置 (R4+R3) は 1-key 形と同一なので、`emitMultiStateCallback` の prelude (slot-store cascade) は変更不要です。

mechanism 1 / 7 と相補的な点は次のとおりです。

| 軸 | 1 (advance trailer) | 7 (TLV walk) | 8 (ParserCounter) |
|---|---|---|---|
| trailer end alignment | ◎ (bulk advance) | × (EOL で中位置停止) | ◎ (counter exhaustion で末尾) |
| per-element extract | × (bulk skip のみ) | ◎ (kind ごと aux) | △ (counter walk 自体は extract なし、7 と併用) |

production vocab は mechanism 1 / 7 のままで、E2E 検証は `pkg/kunai/dsltest/parser_counter_test.go` の合成 IPv4 vocab を使います。検証ケースは、IHL=5 の fast path、IHL=6/7 (1-2 iter)、IHL=15 (10 iter、`IPV4_MAX_DEPTH = 11`) です。bundled 移行のスコープと動機は `dsl-followups.md` B-2 / B-5 を参照してください。

### 6.6 DSL access の体系

aux への access は dot path で統一しています。chain element も同じ accessor を共有します。

| 操作 | 構文 | 適用例 |
|---|---|---|
| 単発 aux のフィールド | `<proto>.<aux>.<field>` | `gtp.opt.next_ext == 0`, `tcp.options.MSS.value == 1460` |
| 単発 aux の存在 | `<proto>.<aux>.exists` | `gtp.opt.exists`, `tcp.options.SACK_PERM.exists` |
| stack/chain の index | `<proto>.<aux>[N].<field>` | `srv6.segments[0].addr == fc00::1` |
| stack/chain の動的 index | `<proto>.<aux>[<expr>].<field>` | `srv6.segments[srv6.last_entry].addr` |
| 集合 ∃ | `any(<expr>)` | `any(srv6.segments.addr == X)`, `any(vlan.id == 100)` |
| 集合 ∀ | `all(<expr>)` | `all(srv6.segments.addr in fc00::/16)` |
| 件数 | `<proto>.<aux>.count` | `srv6.segments.count >= 3` |

`any` / `all` は関数形です。bracket 形 `vlan+[id == 100]` は、∀ デフォルトを維持するため、`all(vlan.id == 100)` の syntax sugar として残します。

### 6.7 codegen 上の扱い (概要)

| 表現 | 実装 mechanism |
|---|---|
| 単発 aux への field 読み | parser machine の state graph から aux 抽出条件を逆算し、gating check + offset 計算 + field load を emit |
| stack aux への [N] index (静的) | parse-time に `0 <= N < cap` を check、runtime は parser の state graph から算出した offset で field load |
| stack aux への [parent.field] (動的) | runtime に bound check (`<expr> < count`) + dynamic offset 計算 |
| `any(P)` / `all(P)` | bpf_loop 経由で per-iter P 評価。any: 1 個目の match で R0=1 早期 break、all: 1 個目の miss で reject |
| `count` | wrapper の field 由来 (SRv6 の last_entry+1 等) または stack walk 結果 |

implementation 詳細は、`pkg/kunai/codegen/parser_state.go` の state graph emit ロジックと `parser_loop.go` の bpf_loop callback emit を参照してください。

## 7. 制限と将来拡張

詳細は [`dsl-followups.md`](./dsl-followups.md) を参照してください。本節では制約マップだけを簡潔に列挙します。

### 7.1 現状の MVP 制限

| 領域 | 制限 |
|---|---|
| Predicate | `field in [...]` は整数 alternatives 実装済 (F7) / IPv4/IPv6/MAC/CIDR alternatives は scope outside / `bit<>64` の field に対する `in` は未対応 (今のところ ≤64-bit のみ wired) / `field has FLAG` は F6 bitwise `&` で superseded (`tcp.flags & 0x12 == 0x12` で同等表現) |
| Where | 算術ネスト最大 16 段 (`maxArithDepth`、10b で 8→16 bump) / het-alt 後の where が alt member の field を直接参照 (`where ipv6.src == fe80::1`) は reject (alt 識別不能) / `in` は bracket predicate `[...]` 専用で、where 句では `==` の `or` chain で代替 (parser が targeted hint を返す) |
| Aux × literal | landed (B-3 commit 6547a42): IPv4/IPv6/MAC/CIDR literal を aux 経由で比較可能。例: `srv6.segments[0].addr == fc00::/16`、`where ipv4.options.RR.addrs[0].addr == 10.0.0.1` |
| Capture | `capture f1, f2` フィールド列 不可 / 量化 layer (`+`/`*`/`{n,m}`) を含む filter で `headers+N` 不可。het-alt 越えの capture は max-alt 上界丸めで動作 |
| Alternation | alt 数 2-4 (`altCountCap`) / heterogeneous size + diverged dispatch 対応済 (P3-12) / nested alt は resolver flatten (P3-13) / quantifier 付き内側 alt (`(a\|b)?`) は reject / 先頭不可 |
| Layer 数 | per-layer entry slot を要する filter は最大 7 layer (`whereLayerEntrySlotCap`、10b で 12→7 にトレードオフ縮小)。実用上の chain 深度 (深 5 layer = `eth/ipv4/udp/gtp/ipv4/tcp`) を上回る上限 |
| Parser machine (vocab 著者向け) | select key 幅 ≤8 bit / select key 本数 ≤3 / variable-trail scale は 2 冪のみ / self-loop 反復上限あり (vocab の `<SELF>_MAX_DEPTH` で declare) |
| Self-validation | parser-block 自検証 (`transition select(field) { v: accept; default: reject; }`) のみ。旧 SANITY const family は撤廃 (legacy 名は loud-fail で拒否) |
| Vocab | 1 protocol あたり最大 2 ラベル |
| Kernel | CI 実測: 6.1 / 6.6 / 6.12 / 6.18 / 7.0。`bpf_loop` 経路 (chain quantifier + parser self-loop) は 5.17+ 必須 (= 理論上の floor、CI 未実測)。fixed chain は更に古い kernel でも可 |

### 7.2 アーキテクチャ上動かない要件

以下は本 DSL の design choice 上動かないもので、いずれも user 要望が出てから別の design check が必要です。

- map references (`map["name"][key]`)
- L7 semantic parsing (DNS body / HTTP / TLS 内部)
- temporal conditions (時間軸条件)
- 自動 encap 推測

## 関連ドキュメント

- [`dsl-overview.md`](./dsl-overview.md): index
- [`dsl-usage.md`](./dsl-usage.md): ユーザー向け CLI ガイド
- [`dsl-grammar.md`](./dsl-grammar.md): formal EBNF + 例文
- [`dsl-followups.md`](./dsl-followups.md): 残作業
- [`dsl-benchmark.md`](./dsl-benchmark.md): ベンチ方法論
