# DSL 内部仕様

xdp-ninja DSL の **設計動機 / 全体アーキテクチャ / codegen ABI / vocab 著者ガイド / P4-16 互換性** を 1 本にまとめた内部資料。CLI 利用者向けは [`dsl-usage.md`](./dsl-usage.md)、文法定義は [`dsl-grammar.md`](./dsl-grammar.md) を参照。

**型 / 演算子 / 形式意味論** は [`dsl-types.md`](./dsl-types.md) (Part I + Part II) に分離。本書はそれと重ならないよう、resolver より下のレイヤ (vocab、codegen ABI、可変長構造) を中心に扱う。

## 目次

1. [設計動機](#1-設計動機)
2. [全体アーキテクチャ](#2-全体アーキテクチャ)
3. [Vocab 著者ガイド](#3-vocab-著者ガイド)
4. [Codegen ABI](#4-codegen-abi)
5. [P4-16 互換性](#5-p4-16-互換性)
6. [可変長構造の分類と表現](#6-可変長構造の分類と表現)
7. [制限と将来拡張](#7-制限と将来拡張)

---

## 1. 設計動機

### 1.1 背景

xdp-ninja は **non-invasive な XDP 観測ツール**。BPF trampoline (fentry / fexit) で本番 XDP プログラムにアタッチし、target を改変せずに pcap 取得する。

既存のフィルタ実装は cbpfc (Cloudflare の cBPF→eBPF transpiler) で tcpdump 構文を解釈する。しかし:

- **多段カプセル化を書きづらい**: GTP-U の extension chain、SRv6 の segment list、MPLS label stack、QinQ、L2/L3 VPN を tcpdump で書くのは事実上不可能 (cbpfc が L2 + L3 の絶対 offset しか扱えない)
- **operator 視点の表現力不足**: 「VXLAN の inner で TCP/443」のような直感的記述ができない
- **観測ホストの target XDP は改変不可**: Cilium / Katran / 5G UPF などは "operationally-sealed"

### 1.2 ゴール

- **多段カプセル化を「プロトコルスタックの形」で記述**: `eth/ipv4/udp/gtp/ipv4/tcp` のように
- **verifier-safe な BPF を吐く**: 全ループに静的上限、bounds check を codegen が emit
- **SRE / operator が読める**: P4 expert 限定にしない
- **target XDP に手を入れない**: 既存 fentry / fexit wrapper にそのまま乗る

### 1.3 設計判断

| 判断 | 理由 |
|---|---|
| **薄い user-facing DSL + 厚い vocab** | プロトコル知識は再利用可能な `.p4` ファイルに切り出す |
| **kernel 5.17+ (quantifier / parser self-loop あり) / さらに古くても可 (fixed chain)** | `bpf_loop` が必須。predicate は BPF_END で済むので BSWAP (6.6+) は不要 |
| **DSL がデフォルト、`--cbpf` opt-in** | DSL の surface が安定したので default 化、cbpfc パスは legacy fallback として残す (deprecation notice 付き) |
| **baked-in vocab** | `//go:embed *.p4` で `.p4` ファイル群を binary に同梱、deploy 時に外部依存ゼロ |
| **vocab は p4lite (P4-16 strict subset)** | p4c で parse 可能な範囲に留める (互換性は §5 参照) |
| **MVP は ラベル 2 段まで** | `@outer` / `@inner` の 2 段で VXLAN / GTP-U の典型ケースをカバー |
| **codegen は純 Go** | cilium/ebpf の `asm.Instructions` を直接組む、外部 toolchain 不要 |

### 1.4 明示的な除外項目

- **map references**: `map["name"][key]` を filter 内に書く機能。per-packet lookup overhead と zero-config 原則に抵触
- **L7 semantic parsing**: DNS body / HTTP header / TLS 内部。cooperation Tier 3 (将来) に持ち越し
- **temporal conditions**: 「直前 SYN から N 秒以内」等の時間軸条件
- **blind protocol auto-detection**: encap 型の heuristic 推測。明示的な layer chain 指定が要件

---

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
| Codegen | `pkg/kunai/codegen/` | `Gen(p, mode)` | IR → `Output{Main, Callbacks, Capture}` |
| Compile | `pkg/kunai/compile.go` | `Compile(expr, mode)` | 全部束ねる薄い wrapper |
| Load 統合 | `internal/program/program.go` | `compileFilter(expr, useDSL)` | DSL or cbpfc を選び runFilter wrapper に乗せる |
| CLI | `cmd/xdp-ninja/main.go` | `resolveFilterSyntax()` | DSL がデフォルト、`--cbpf` で legacy 経路 |

### 2.3 パッケージごとのツアー (依存順、leaf → root)

`pkg/kunai/` 配下は ~12,800 行 (test 除く)、10 パッケージ。**外から内へ**たどると依存方向が綺麗に取れる構造。leaf の `ast/` `ir/` `vocab/` から読むと積み上げが見える。

#### `ast/` (~560 行) — 純粋な型定義

`ast.go` が AST のルート型。`Filter` (= 1 つの DSL filter 式に対応)、その下に `Layer[]` / `WhereExpr` / `CaptureClause[]`。`Predicate` / `WhereExpr` / `CaptureClause` 等の各 Sum 型は `kinds.go` の enum (`PredKind`, `WhereKind`, `CaptureKind`, `ValueKind`, `Quantifier`, `CmpOp`, `ArithOp`) で識別される。

**読みどころ**:
- `ast.go` のパッケージ doc に `Unsupported string` フィールドの意図 — parser が受理した「これから codegen でやる予定」(PredIn/PredHas/CapFields) を明示マーク
- `value.go` — predicate 値の Sum 型 (`Int`, `V4 [4]byte`, `V6 [16]byte`, `MAC [6]byte`, `Prefix int`)

ロジックは無く、型の倉庫。

#### `lexer/` (~730 行) — 2 モード切替トークナイザ

`lexer.go` 本体、`scanvalue.go` が IPv4/IPv6/MAC のリテラル parser、`token.go` が token kind enum。

**核心 = 2 モード**:
- **structural mode** (`Lexer.Next()`) — `/`, `[`, `]`, `where`, `capture`, identifier 等の構文骨格
- **value mode** (`Lexer.NextValue()`) — `[field==10.0.0.1]` の `10.0.0.1` 部分。IPv4/IPv6/MAC が `/`, `:`, `.` を含むため structural の `/` (chain separator) と区別する必要がある

#### `parser/` (~1,310 行) — 再帰下降 + precedence climbing

`parser.go` がエントリ + 共通ヘルパ。文法部分は別ファイル:

- `layer.go` — layer chain (`/`)、quantifier (`?+*{n,m}`)、alternation (`(a|b)`)
- `predicate.go` — `[field op value]`、bit-slice `[lo:hi]` index 含む
- `where.go` — `where` 節。precedence climbing。bool atom / `Bool == Bool` / LHS network literal 対称化 / 負数 literal 対応
- `capture.go` — `capture all/headers/headers+N/<label>+N/proto+N/absolute N`

#### `vocab/` + `vocab/p4lite/` (~3,100 行)

2 階層構成:

- **`vocab/p4lite/`** — `.p4` ファイル (P4-16 strict subset) を AST 化。再帰下降。受理する構文の境界は `conformance_test.go` で pin (= subset の正規定義)
- **`vocab/`** — p4lite AST → `ProtocolSpec`。`loader.go::Load` がエントリ。`classifyConsts` が **正規表現** で const 名を分類:
  - `reField` (`<SELF>_<PARENT>_<FIELD>`)
  - `reChainEnd` (`<SELF>_CHAIN_END_<FIELD>`)
  - `reMaxDepth` (`<SELF>_MAX_DEPTH`)
  - + NoCheck (`<SELF>_<PARENT>_NO_CHECK`)
  - + Self-validating dispatch (parser-block 自検査)
- **`vocab/parser_machine.go`** — aux header layout / gating / stack capacity を `parser_machine` block から抽出

#### `dslvocab/` (~30 行) — bundled vocab の cache wrapper

`Bundled()` のみ。`protocols/*.p4` を `//go:embed`、`vocab.Load` 結果を `sync.Once` でキャッシュ。

#### `ir/` (~340 行) — vocab 解決済の中間表現

`Program` → `LayerInstance[]` (vocab 参照済) + `Condition` (where) + `CaptureInfo`。AST と似ているが:

- AST `Layer.ProtoName: string` → IR `LayerInstance.Spec: *vocab.ProtocolSpec`
- AST `Predicate.Field.Path: []string` → IR `Predicate.Field: *FieldRef{Layer, Field, Aux, Slice}` (具体 binding)
- AST `Layer.Alternatives` → IR `Alternation: []*LayerInstance` (展開済)

`FieldRef.Slice` で bit-slice、`FieldRef.EffectiveBits()` で slice-aware bits。

#### `resolve/` (~1,600 行) — AST + vocab → IR + 型システム

- `resolve.go::Resolve` / `ResolveWithOptions` — エントリ。`Options.StrictArithLint` で F1 lint pass を opt-in
- `layer.go::resolveLayer` — protocol 名 → vocab spec、dispatch const 探索、alternation の親子整合性
- `predicate.go::resolveBracketPredicate` — value type 分類、field 範囲チェック (slice 含む)
- `where.go` — field path bind、bool atom / aux exists / quantifier 経路
- `capture.go` — `headers+N` の長さ静的計算
- **`typing.go`** — 型システム本体: `checkArithCondition` / `checkBracketIntFit` / `checkLiteralWidthShape` / `attachSlice` / `detachTrailingSlice` / `tryDesugarMultiLDXSliceCmp` / `splitSliceIntoLDXChunks` / `lintArithCondition` (F1)
- **`typing_errors.go`** — 型エラー専用 helper。`typing_errors_test.go` で [`dsl-types.md §8`](./dsl-types.md#8-型エラー一覧) catalog との drift を pin

**読みどころ**:
- `layer.go::selectAltParentDispatch` — alternation の uniform dispatch 制約 enforce
- `typing.go::tryDesugarMultiLDXSliceCmp` — F12 mid-width slice cmp の AND/OR-chain desugar
- `typing.go::attachSlice` — bit-slice の field-aware バリデーション

#### `codegen/` (~5,080 行、最大) — IR → `asm.Instructions`

ファイル構成 (読む順):

1. **`codegen.go::Gen`** — 全体の骨格 + 共通 helper (slice 用 `applySliceToOffset` / `slicePostAdjust` / `nextLDXSize`、anchor 三種 `layerAnchorFor` / `absAnchor` / `slotAnchor` / `emitFieldLoad`、per-layer entry slot allocator `whereLayerEntrySlot`)。**パッケージ doc が読みどころ最上位**。ABI (R0/R1/R2/R4 の役割、`offsetBase` 概念、`dslReject` / `filter_result` ラベル、`KunaiStackTop` / `ScratchBufSize` の sizing 契約) はここに集約 → §4 codegen ABI 参照
2. **`caps.go`** — host 提供の `Capabilities` (Action map、ActionFetcher、`StrictArithLint`) と `ActionFetcher` interface
3. **`dispatch.go`** — Field / NoCheck / SelfValidating の dispatch 検査 emit (Sanity family は撤廃済、parser-block 自検証に統合 — §3.2 / §5 参照)
4. **`predicate.go`** — predicate codegen。整数 / IPv4 / IPv6 / MAC / CIDR、`==` / `!=` / ordered。F3 IPv6 ordered cmp (`emitIPv6OrderedCmp`)、F7 整数 in (`emitInPredicate`)、bit-slice 適用も含む。`multiWordRoute` ヘルパで `==` と `!=` を統一
5. **`chain.go`** — `{n,m}` で `m≤4` の静的アンロール
6. **`bpfloop.go`** — `+/*/{n,m>4}` の bpf_loop emit。bpf2bpf subprogram + BTF func_info。`*` (whole-chain skip) は `emitPeekedIterZero` で parent dispatch peek
7. **`alternation.go`** — alt の sequence 展開 (P3-12 で per-alt body emit + matched flag、P3-13 で nested alt の resolver flatten 対応)
8. **`where.go`** — where 節 (or / and / not / arith / action atom / bool atom / bool eq / quantifier any-all)。**het-alt 後の field addressing** (`layerAnchorFor` で abs / slot anchor を出し分け、PR-A/B 由来)。F4 Int<128> arith pipeline (`genArithCompare128` / `genArith128FieldOpConst` / `genArith128FieldOpField` / `genArithField128Load`、ABI-clean な stack-bridged carry/borrow)、F6 bitwise ALU 統合、F10 BoolEq の `genConditionAsBool`、F13 slice の `emitSliceShiftMask`、TLV-walk option access (`genDynamicOffsetAuxLoad` — parser-machine が記録した dynamic offset slot から absolute scratch offset を読み出して field を取得)
10. **`capture.go`** — `headers+N` の長さ algo

#### `compile.go` (~50 行) — 全部束ねる薄い entry

`Compile(expr, caps)` が:

1. `dslvocab.Bundled()` → vocab map
2. `parser.Parse(expr, ...)` → `Filter` (AST)
3. `resolve.ResolveWithOptions(filter, vocab, caps.Action, opts)` → `Program` (IR)
4. `codegen.Gen(prog, caps)` → `Output`

数行のパイプライン。各段の入口点を確認できる。

### 2.4 「ここを押さえると一気にわかる」キー概念

レビュー時にここを抑えていれば 70% 把握できる:

1. **runFilter ABI** (`codegen/codegen.go` パッケージ doc)
   入: R0==scratch_start, R1==scratch_end, R9==pkt_len。出: R2=={0,1}。R6-R8 callee-saved 禁忌。R4==offsetBase は codegen 専用。これが分からないと codegen はどこも読めない (詳細は §4)

2. **Vocab dispatch 命名規約** (`vocab/loader.go::classifyConsts`)
   `<SELF>_<PARENT>_<FIELD>` 等の正規表現マッチで const の意味を決める。文書化された規約の **唯一の実装箇所**

3. **2 モード lexer** (`lexer/lexer.go`)
   `[` 内では `NextValue()`、それ以外では `Next()`。これを知らずに lexer を読むと混乱する

4. **AST → IR の 1 段** (`resolve/resolve.go::Resolve`)
   parser が「proto 名と field 名の string」を作るだけ → resolve が vocab ポインタに bind、dispatch const を選び、ラベルを ambiguity check する。**resolve が型安全性の防壁** — typing.go の入口でもある

5. **byteSwap trick + offsetBase** (`codegen/codegen.go::byteSwap`, `loadFromOffset`)
   全 codegen がこの 2 つに乗る。読み解けば predicate / dispatch / chain は全部素直

### 2.5 レビュー時のチェックリスト

`pkg/kunai/` 配下を review するときの推奨観点:

- [ ] **AST の各 Sum 型が完備か**: `ast/kinds.go` の enum ごとに parser が全 variant を作っているか、resolve / codegen で漏れがないか
- [ ] **`Unsupported string` の伝達**: parser が立てたフラグが resolve / codegen まで届いているか (verifier 通過まで届かない → silently 動く → バグ)
- [ ] **2 モード lexer の境界**: `[` `]` `==` `!=` の前後でモード切替が破綻していないか
- [ ] **vocab regex の貪欲性**: `<SELF>_CHAIN_END_<FIELD>` が `<SELF>_<PARENT>_<FIELD>` に紛れ込まないか (実装は `reChainEnd` を `reField` より先に試す配置で対処済)
- [ ] **resolve の error path 網羅**: bad vocab / 同名 protocol / alt size mismatch / ラベル ambiguity / 型エラー (`typing_errors.go`) の各エラーが出るか
- [ ] **codegen の register clobber**: R6-R8 を一切触っていないか、bpf_loop callback では R6-R9 全部触っていないか
- [ ] **byteSwap の方向**: 入力が BE (network) で出力が LE (immediate) になっているか、逆にしていないか
- [ ] **bpf_loop callback の BTF**: `bpfloop.go::genCallback` で func_info を attach しているか
- [ ] **bit-slice の post-adjust**: non-aligned slice が `emitSliceShiftMask` 経由で正しい shift+mask を emit しているか
- [ ] **Test の網羅性**: 各 codegen path に対応する verifier load test (`internal/program/load_dsl_test.go::dslEntryExprs`) があるか + 型 helper が `resolve/typing_test.go` で unit テストされているか

---

## 3. Vocab 著者ガイド

新プロトコルを DSL に追加する手順。`pkg/kunai/protocols/<name>.p4` を 1 ファイル足し、規約どおりの const を書けば codegen がそのまま走る。

### 3.1 ファイル配置

- 1 プロトコル = 1 ファイル: `pkg/kunai/protocols/<lowercase-name>.p4`
- ファイル名 (拡張子除く) が DSL でレイヤを書くときの protocol 名。例: `mpls.p4` → `eth/mpls/ipv4`
- バンドルは `embed.go` の `//go:embed *.p4` で取り込まれるので、ファイルを置けばリビルドだけで読み込まれる

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

ルール:
- Primary header 名は `<protoname>_h` (上記なら `mpls_h`)。これがマッチしないと vocab loader が reject
- フィールドは `bit<N> name;` の繰り返し。`N` は 1..2048
- 全フィールドの bit 合計は **8 の倍数** (header total が byte-aligned)
- フィールド名は lowercase + underscore + 数字

補助 header (オプション解析用など) も同ファイルに書ける。codegen には primary だけが渡る。

#### Const 宣言 (dispatch + メタデータ)

const は **名前で意味が決まる** 。

| パターン | 意味 |
|---|---|
| `<SELF>_<PARENT>_<FIELD>` | 親 protocol の `field` がこの値のときに自分 (SELF) として展開 |
| `<SELF>_<PARENT>_NO_CHECK` | 検査せず blind cast (ユーザの記述順を信じる) |
| `<SELF>_MAX_DEPTH` | bpf_loop chain (`+`/`*`/`{n,m>4}`) のループ上限。未指定なら codegen 既定 (8) |
| `<SELF>_CHAIN_END_<FIELD>` | chain 終了条件 (例: MPLS s-bit が 1 で終端) |

`<SELF>` はファイル名 (uppercase)、`<PARENT>` は親 protocol 名 (uppercase)。 親に Field/NoCheck も持たないが子が parser block で自己検証する場合 (例: ipv4 の `transition select(hdr.version) { 4: accept; default: reject; }`) は **vocab const 不要**。 resolver が `DispatchSelfValidating` を合成する。 詳細は §3.3。

**Field dispatch (一番よく使う)**:

```p4
const bit<16> IPV4_ETH_ETHERTYPE  = 0x0800;
const bit<16> IPV4_VLAN_ETHERTYPE = 0x0800;
```

`ipv4` は eth または vlan 経由で来るとき、親の `ethertype` が `0x0800`。
- ビット幅は親フィールドの幅と一致 (`ethertype` は 16 bit なので `bit<16>`)
- 値は親フィールド幅に収まる整数
- field 名は親 header の field 名 (lowercase) と完全一致

**Self-validating parser (旧 SANITY 機構の置き換え)**:

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

親 (mpls / gtp / vxlan inner 等) に次プロトコルを示す field が無くても、 子の parser block が `transition select(<primary-field>) { ...; default: reject; }` を持っていれば、 resolver が `DispatchSelfValidating` を合成して chain を許可する。 boundary では何も emit せず、 parser machine の transition select が実行時に reject する。

- 旧 `<SELF>_<PARENT>_SANITY_<TYPE>` / `<SELF>_SANITY_<TYPE>` const family は撤廃された (legacy 名で declare すると vocab loader が error で reject)
- self-validation は標準 P4-16 構文のみで表現するので vocab が self-contained に。 srv6 の `transition select(routing_type) { 4: accept; default: reject; }` と同 idiom
- ipv4 + IHL trailing のように parser machine + HDRLEN_* が同居しても codegen が両方を順番に消化するため OK (`validateLayoutExclusivity` は両立を許可)
- 親が Field/NoCheck/SelfValidating のいずれの dispatch も持たない場合は resolver が `no dispatch constant for ...` で reject

**NoCheck dispatch**:

```p4
const bool ETH_MPLS_NO_CHECK = true;
const bool MPLS_MPLS_NO_CHECK = true;
```

親と自分の境界に検査機構が無い (EoMPLS, VXLAN inner Ethernet など)。ユーザが one-liner で順序を明示することで境界を表現。
- `bool` 型必須。`= true` のみ有効。`false` は宣言禁止
- chain (`mpls+` 等) で iter 1+ の self-dispatch にも使える

**MAX_DEPTH**:

```p4
const bit<8> MPLS_MAX_DEPTH = 8;
```

bpf_loop で最大何回イテレーションするか。未宣言なら既定 8、上限 64。

**CHAIN_END**:

```p4
const bit<1> MPLS_CHAIN_END_S = 1;
```

chain 中、SELF の `s` field が `1` のとき chain を終了。MPLS の bottom-of-stack ビットがこの典型。

#### Parser 宣言 (シンタックスチェックのみ)

```p4
parser MplsParser(packet_in pkt, out mpls_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
```

p4lite はこのセクションを **シンタックスチェックのみ** に使う (codegen は header だけを読む)。`extract` + `transition accept` の最小形を書いておけば良い。複雑な state マシンを書いても無視される。

### 3.3 どの dispatch type を選ぶか

優先順位は **Field(parent) > NoCheck(parent) > SelfValidating (子の parser block が自己検証)**。 const ベースの形 (Field / NoCheck) が parser-block 自己検証より優先される。

判断フロー:

1. 親 protocol に「次プロトコルを示すフィールド」があるか?
   - ある → **Field**: `<SELF>_<PARENT>_<FIELD> = <value>`
2. 子の primary header に識別可能な field があるか? (例: IPv4 / IPv6 の version、 SRv6 の routing_type)
   - ある → **parser block で自己検証** (推奨): `transition select(hdr.<field>) { <ok>: accept; default: reject; }`。 vocab const は不要
3. どちらも無い (encapsulation の Ethernet inner など)
   - **NO_CHECK**: `<SELF>_<PARENT>_NO_CHECK = true`

### 3.4 Self-dispatch (chain 用)

`<SELF>_<SELF>_*` は chain (`+`/`*`/`{n,m}`) のときに iter 1+ で読まれる。

- VLAN: `VLAN_VLAN_ETHERTYPE = 0x8100` — inner VLAN は外側の ethertype が再び 0x8100 になることで識別
- MPLS: `MPLS_MPLS_NO_CHECK = true` — label 区切りは無いので blind chain

self-dispatch が無いプロトコルは `+` / `*` / `{n,m}` で chain できない (= 静的に固定回数しか展開できない)。

### 3.5 サンプル: 新しい encapsulation を追加する

仮想プロトコル `foo` (4 byte header, ipv4 を貫通する VXLAN-like) を足したい場合:

```p4
// pkg/kunai/protocols/foo.p4
header foo_h {
    bit<8>  version;
    bit<8>  flags;
    bit<16> reserved;
}

// foo は UDP の dport==4444 で識別
const bit<16> FOO_UDP_DPORT = 4444;

parser FooParser(packet_in pkt, out foo_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
```

別ファイル `eth.p4` 側に:

```p4
const bool ETH_FOO_NO_CHECK = true;
```

を追加。これで DSL から `eth/ipv4/udp[dport==4444]/foo/eth/ipv4/tcp` が書ける。

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

`internal/program/load_dsl_test.go` の `dslEntryExprs` に新プロトコルのケースを足すと、後の回帰防止になる。

### 3.7 デバッグ (典型エラー)

**vocab loader エラー**:
```
foo.p4: const "FOO_BAR_BAZ_QUX" does not match <SELF>_{<PARENT>_<FIELD>|<PARENT>_NO_CHECK|MAX_DEPTH|CHAIN_END_<FIELD>}
```
const 名がパターンに一致していない。`<SELF>_` を抜かしている / parent 名のスペル違い、等が典型。

```
foo.p4: const "FOO_BAR_SANITY_NIBBLE" uses the SANITY family, which has been removed — declare a parser-block `transition select(<field>) { ...; default: reject; }` to self-validate the protocol instead
```
旧 SANITY const family は撤廃された。 parser block で `transition select(<primary-field>) { <ok>: accept; default: reject; }` を書けば同じ意味になる (例は ipv4.p4)。

```
foo.p4: missing primary header "foo_h"
```
primary header の名前が `<filename>_h` になっていない。

**resolver エラー**:
```
no dispatch constant for "foo" under "udp" (declare FOO_UDP_<FIELD|SANITY_<TYPE>|NO_CHECK> in foo.p4, or have foo.p4 self-validate via a parser-block `transition select(...) { ...; default: reject; }`)
```
DSL `eth/ipv4/udp/foo` を書いたが、`foo.p4` に `FOO_UDP_*` (Field / NoCheck) も無く、 parser block での自己検証 (`transition select(<primary-field>) { ...; default: reject; }`) も無い。 どちらかを宣言する。

```
alternation alts disagree on dispatch for "tcp": "TCP_IPV4_PROTOCOL" vs "TCP_IPV6_NEXT_HEADER"
```
alt group 後の layer に対して、各 alt の dispatch const が型/値/フィールドで揃わない。MVP では同じ field offset + value を要求する。

**codegen エラー**:
```
chained "foo" has no self-dispatch const (declare FOO_FOO_<FIELD|SANITY_<TYPE>|NO_CHECK> in foo.p4)
```
`foo+` / `foo*` / `foo{n,m>1}` を書いたが、`foo.p4` に `FOO_FOO_*` self-dispatch が無い。

**parser machine 固有の制約** (codegen が `ErrNotImplemented` で reject):

| エラー | 意味 | 対処 |
|---|---|---|
| `select key is N bits; MVP supports up to 8` | `transition select(...)` の鍵が 1 byte 超 | 1 byte field に分けるか、複数 select に分割 |
| `variable-trail select with N keys exceeds stash slots` | tuple-select の鍵が 3 本超 | tuple を分解 |
| `variable-trail scale N is not a power of two` | variable-length trail の scale が非 2 冪 | vocab 側で 2 冪に丸めるか、cap 直書きを検討 |
| `parser machine self-loop depth N exceeds cap M` | self-loop の反復上限超過 | vocab に `<SELF>_MAX_DEPTH = N` で上限 declare (デフォルト 8、最大 64) |

これらは現状 §7.1 の MVP 制限表 (Parser machine 行) でも追跡。新 vocab 著者が引っかかった場合の最初の確認箇所。

### 3.8 設計上の心構え

1. **NO_CHECK は最後の手段**。Field/Sanity で識別できるなら必ずそれを使う。NO_CHECK は user の記述順だけが頼り = 間違うと誤読する
2. **MAX_DEPTH は実利用上限ではなく安全弁**。MPLS なら現実は 4-8 段だが、verifier に喰わせる loop 上限として一桁を選ぶ
3. **Field の値は byte-swap なし** で書く。codegen 側で network-order に直す。`ETHERTYPE = 0x0800` (IPv4) のように直感どおりに書ける
4. **Sanity NIBBLE のフィールド** は header 先頭 1 nibble (= 4 bit) を切り出した値を比較する。`bit<4>` 必須

---

## 4. Codegen ABI

DSL output が既存の runFilter wrapper にどう乗るか。**コードを読む前にここを抑える** こと。詳細実装は `pkg/kunai/codegen/codegen.go` のパッケージ doc。

### 4.1 レジスタ規約

| Register | 役割 |
|---|---|
| **R0** | scratch buffer 先頭 (in: wrapper が先読みしておいた packet bytes) |
| **R1** | scratch buffer 末尾 (in: bounds check 用) |
| **R2** | filter result (out: 1==accept / 0==reject) |
| **R3** / **R5** | 自由に clobber 可 (working)。**ただし R5 は alt-diverged dispatch (P3-12) で `matchedAltReg` に流用される** — alt block が match した alt index を R5 に書き、直後の layer dispatch が `JNE R5, i` で per-alt 分岐する。alt block 入口から次 layer dispatch 完了までの区間で R5 を別用途に潰してはいけない (`pkg/kunai/codegen/alternation.go::matchedAltReg`) |
| **R4** | **offsetBase**: 現 layer の scratch buffer 内開始位置 (codegen 専用) |
| **R6-R8** | host 占有 (callee-saved from kunai's view、kunai は読み書き禁忌)。xdp-ninja wrapper では xdp_buff / data / data_end を保持。**注**: filter 後に走る `captureWithXdpOutput` (`internal/program/program.go`) が R6 を使うので、kunai が clobber すると capture 出力先 ctx が壊れる |
| **R9** | packet length (in: wrapper が事前計算)。**read-only**: filter 後に `captureWithXdpOutput` が `Mov R3, R9` で `MaxCapLen` を計算するパスがある (per-CPU map にコピーする bytes 長)。kunai が R9 に書くと capture 長が silent truncation する。`TestZeroCapsIsHostAgnostic` が R6-R8 / shallow stack を pin する一方、R9 への write も同じ違反として扱う必要がある (Int<128> dual-half compare で見落とした履歴あり、commit `b6d5e7f` 後に修正) |
| **R10** | stack pointer |

**Stack 占有** (詳細は `codegen.go` パッケージ doc の `KunaiStackTop` 周辺):
- kunai 占有: arith spill `[-56..-184]` (`maxArithDepth = 16` slot × 8 byte、 10b で 8 → 16 bump)、bpf_loop ctx `[-208..-176]` (4 slot: `bpfLoopCtxOffsetSlot=-208` / `…ScratchStartSlot=-200` / `…ScratchEndSlot=-192` / `…LayerEntrySlot=-184`)、per-layer entry slot `[-224..-224-8N]` (`whereLayerEntrySlot`、 PR-A/B 由来、 het-alt 後の where / capture が runtime offset を読むのに使用、`whereLayerEntrySlotCap = 7` 上限 = 56 byte)、dynamic aux offset slot `[-280..-512]` (`dynamicAuxOffsetSlot(layerPos, slotIdx)`、 TLV-walk callback の lifted prelude が record、 demand walker が割り当てた option 数だけ消費、`dynamicAuxMaxSlotsPerLayer = 5` × `whereLayerEntrySlotCap = 7` 上限 = 280 byte cap、 realistic vocab で TCP options (1 layer × 1〜5 slot = 8〜40 byte) が最大)
- host 占有: `(KunaiStackTop, 0)` = `(-56, 0)` の任意の slot。xdp-ninja wrapper は `-48` で tracing args ptr、`-12..-8` で metadata
- 境界定数: `pkg/kunai/codegen.KunaiStackTop = int16(-56)` — kunai がここより浅いオフセットを書くことは無い (regression test `TestZeroCapsIsHostAgnostic` で守る)
- scratch buffer サイズ: `pkg/kunai/codegen.ScratchBufSize = 512` byte。host wrapper はこの prefix を per-CPU scratch buffer に materialise してから kunai filter に jump する。新 protocol を vocab に足すときは `sum(per-protocol max trail) + sum(fixed primary headers) ≤ ScratchBufSize` が成立するか検証 (codegen.go パッケージ doc の "sizing contract")

### 4.2 制御フロー

成功時: R2==1 → `Ja filter_result` → wrapper の最終分岐に戻る
失敗時: `Ja dsl_reject` → R2==0 → fall through → `filter_result`

### 4.3 layer の emit 単位

各 layer は以下のステップ:

1. **bounds check**: `R3 = R0 + R4 + hs; R3 > R1 → dsl_reject`
2. **dispatch check**: 親の field を読んで const と比較 (Field) / なし (NoCheck) / parser-block 自検証 (SelfValidating — Sanity family の置換)
3. **predicate emit**: layer のフィールド条件を AND で連鎖
4. (`NeedsRuntimeOffset` 設定時) **per-layer entry slot 書き出し**: `Store R4 → fp[whereLayerEntrySlot(LayerPos)]` — het-alt 後の where/capture/option-walk が runtime offset を読むため
5. **R4 進める**: `Add R4, hs`
6. **HDRLEN 末尾消費** (`emitPrimaryVariableTail`): IPv4 IHL / TCP data_offset の trailing bytes を R4 に加算
7. **flag-triggered sub-header advance** (`emitFlagTriggers`): GRE C/K/S 等の flag-gated 4B sub-header を per-flag に R4 advance

### 4.4 chain (`+` / `*` / `{n,m}`)

`m≤4` は静的アンロール (chain.go)、それ以上は bpf_loop 経由 (bpfloop.go)。`*` (whole-chain skip) は `emitPeekedIterZero` で parent dispatch を peek し、不一致なら chain 全体を skip。

bpf_loop callback は **bpf2bpf subprogram** として emit、BTF `func_info` を `internal/program` 側 wrapper で attach。callback 内では:
- R6-R9 禁忌 (verifier 制約)
- ABI: R1==index, R2==ctx
- ctx struct (stack 上、4 slot 全て u64): `{offset, scratchStart, scratchEnd, layerEntry}` (各 8 byte)。base offset = `bpfLoopCtxBaseOffset = -208` (10b で `maxArithDepth` 8 → 16 bump に伴い -64 シフト)、各 slot 定数は `bpfloop.go::bpfLoopCtx*Slot`

### 4.5 alternation (`(a|b|c)`)

各 alt を sequence 展開。**P3-12 / P3-13 で MVP 制約は大幅に緩和**:

- alt 数 2-4 (`altCountCap`)
- ✅ heterogeneous header size 対応 (per-alt body emit + inline advance、`(ipv4|ipv6)` で 20 vs 40 byte が動く)
- ✅ alt 後の layer の **diverged dispatch** 対応 (`AltConsts` per-alt、`matchedAltReg=R5` で per-alt JNE 分岐)
- ✅ ネスト alt は resolver で **flatten** (`((a|b)|(c|d))` → `(a|b|c|d)`、quantifier 付き内側 alt を除く)
- 先頭 layer 不可 (parent dispatch が無い)
- 内側 alt に quantifier (`(a|b)?`): 意味が違うので reject

### 4.6 where 節

短絡評価:
- AND の左辺 false → dsl_reject
- OR の左辺 true → `Ja or_done` (右辺スキップ)

NOT は inner success label を作って `Ja failLabel` で反転。

算術: tree walk で R3 に結果を残す契約、stack に左オペランドを退避。**16 段ネストまで** (`maxArithDepth = 16`、 10b で 8 → 16 bump、 stack 再配置で `whereLayerEntrySlotBase = -224` / `dynamicAuxOffsetSlotBase = -280` に連鎖シフト、 `whereLayerEntrySlotCap = 7`)。

**het-alt 後の field addressing**: resolver の `markRuntimeOffsetLayers` が het-alt より後ろの layer を `NeedsRuntimeOffset = true` でマーク。codegen は `layerAnchorFor` でその layer の field load を **abs anchor (R0+静的 prefix)** ではなく **slot anchor (R10[whereLayerEntrySlot] + R0)** で emit。det-alt の無い filter は完全 fast path を維持 (slot 経路ゼロ、命令数増加なし)。詳細は `codegen.go::layerAnchor` 周辺と `where.go::layerAnchorFor`。

action atom (`action == NAME`): codegen は `caps.ActionFetcher.EmitFetch(R3)` を呼んで R3 に action u32 をロードする命令列を取得し、続けて `JNE R3, caps.Action[NAME], dsl_reject` を emit。**XDP fexit ABI** (`pkg/kunai/host/xdp.FexitFetcher`) は `stack[-48] → args[1]` の 2 段 LDX を返す既定実装。`caps.Action == nil` のときは resolver が atom を拒否 (host が action 値を提供できない)。tc clsact / userspace target は `pkg/kunai/host/<name>/` で独自の fetcher を実装すれば再利用可能 — kunai コアは host 知識を持たない。

### 4.7 capture 節

`headers+N` の N は静的計算 (chain を含む filter ではコンパイル時に長さ確定不能 → reject)。`captureWithXdpOutput(eventsFD, isFexit, maxCapLen)` の `maxCapLen` 引数として wrapper に渡す。per-capture `where` は filter 全体の `where` と AND 合成。

### 4.8 byte-swap trick

eBPF の LDX は x86 上 little-endian で読む。packet bytes は network order (BE)。runtime BSwap を avoid するため、**codegen 時に定数を byte-swap して LE 形式で immediate に埋める**。`==` / `!=` の単純比較が 1 命令で済む。ordered 比較 (`<`, `>` 等) は意味的に LE にできないので runtime BSwap を入れる。

---

## 5. P4-16 互換性

`pkg/kunai/vocab/p4lite/` は xdp-ninja の vocab loader が `.p4` ファイルを読むための **P4-16 の限定サブセット** パーサ。

実装ファイル:
- `lexer.go` (319 行) — トークナイザ + キーワード認識
- `parser.go` (589 行) — recursive descent
- `types.go` (136 行) — AST 型

**結論**: p4lite は P4-16 の **strict subset** (P4-16 仕様の範囲内に収まっている)。p4c が parse できる範囲だが、明示的な reject keyword (action / table / control / apply / extern) は p4lite で弾く。

### 5.1 サマリ表

| 領域 | P4-16 | p4lite | 評価 |
|---|---|---|---|
| Top-level decl | header / struct / header_union / enum / error / match_kind / typedef / type / extern / action / table / control / parser / package / instantiation / const | header / const / parser | strict subset |
| Header field 型 | bool / error / match_kind / `bit<N>` / `int<N>` / `varbit<N>` / typedef'd / struct nest / header stack | `bit<N>` のみ | strict subset |
| Const 型 | 任意 typeRef + 任意 expression | `bit<N>` (1..64) + `bool`、整数リテラルのみ | strict subset |
| Parser パラメータ direction | in / out / inout / 無指定 | `packet_in` / `out` のみ | strict subset (architecture 依存) |
| Parser local element | const / var / instantiation / value_set | 無し | strict subset |
| Parser statement | assignment / method call / direct application / block / conditional / const / var / empty | `obj.extract(target)` / `obj.extract(target.next)` のみ | strict subset |
| Transition | accept / reject / state name / select | 同左 | full ✓ |
| Select case keyset | 整数 / default / `_` / mask (`val &&& mask`) / range (`a..b`) / 名前参照 / tuple | 整数 / `_` / default / tuple | mask & range 未対応 |
| 整数リテラル | 10進 / 0x hex / 0o oct / 0b bin / sized (`4w0xff`, `8s10`) | 10進 / 0x hex のみ | bin / oct / sized 未対応 |
| Annotation (`@name`) | 全所に書ける | 一切受けない | strict subset |
| コメント | `//` / `/* */` | 同左 | full ✓ |

### 5.2 p4lite が拒否するもの

`vocab/p4lite/lexer.go:134` の `rejectedKeywords` で **明示的に reject**:
- `action`, `table`, `control`, `apply`, `extern`

これらが書かれた `.p4` ファイルを読むと `p4lite does not support "..."` エラー。

これ以外の P4-16 上位宣言 (`struct`, `header_union`, `enum`, `error`, `match_kind`, `typedef`, `type`, `package`) は明示 reject 対象ではないが、トップレベルで `header` / `const` / `parser` 以外のキーワードに遭遇すると `expected 'header', 'const', or 'parser'` エラーで弾かれる。

### 5.3 P4-16 で valid だが p4lite が reject するもの

すべて **vocab 用途で意味を持たない** と判断して除外:

- `action`, `table`, `control`, `apply` — match-action パイプライン定義。kernel verifier に通る eBPF を直接吐く xdp-ninja では使わない
- `extern` — 外部関数宣言。codegen は固定の eBPF パターンを emit するので呼び出す extern が無い
- `varbit<N>`, header stacks 内宣言 — 動的長 header / オプション解析。今は scratch 256B 内の静的フィールドアクセスのみ
- value_set — runtime に変動する match 集合
- `int<N>` / `bool` field — flag 系は `bit<1>` で書く慣習で代替
- 名前参照 const / 式 const (`const bit<8> A = B + 1;`) — vocab 内で計算は不要
- mask / range match — DSL の `where` で代替

### 5.4 P4-16 が reject するのに p4lite が通すケースの監査

確認結果: **無し**。

確認した観点:
1. `header` field 型は `bit<N>` のみ — P4 でも合法
2. `const` の bit 幅 1..64 — P4 では上限なし、p4lite で狭めただけ
3. `parser` パラメータ `packet_in` / `out` のみ — P4 の direction の subset
4. `extract` 引数 `obj.extract(target.next)` — P4 の header stack の `.next` プロパティと一致
5. `select` のキーに dotted path — P4 では expression なので `a.b.c` も許容、subset
6. `select` case の値は整数 or `_` — P4 の subset
7. キーワードの大小: P4 と同じ lowercase

### 5.5 動作確認

`pkg/kunai/protocols/*.p4` は **本物の p4c で `--parse-only` 通過**するように CI で検証している (`.github/workflows/p4c-check.yml`、ローカルは `make p4c-check` または `./scripts/p4c-check.sh`)。詳細は [`dsl-followups.md`](./dsl-followups.md) P0-4 を参照。

加えて `go test ./pkg/kunai/vocab/...` が `dslvocab.Bundled` 経由で全 `.p4` を 1 度パースしているので、Go test が緑 = 「全 vocab が p4lite subset (= P4-16 の strict subset) に収まる」の二重確認になる。

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

- [P4-16 公式仕様 v1.2.5](https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html) (BNF: §G "Appendix: P4 grammar")
- [p4c parser grammar](https://github.com/p4lang/p4c/blob/main/frontends/parsers/p4/p4parser.ypp)

---

## 6. 可変長構造の分類と表現

ネットワークプロトコルの可変長部分は形が複数ある。kunai DSL では **どのパターンを chain として書かせ、どのパターンを wrapper の aux として表現するか** を設計判断として明確にしている。本節は分類とその表現指針を述べる。

### 6.1 4 パターンの分類

実 protocol の可変長構造は wire 形上 4 つの基本パターンに分類できる。

| # | パターン | 例 | 構造の特徴 |
|---|---|---|---|
| **A** | 全体繰り返し (層スタック) | VLAN, MPLS, QinQ | wire 上で同じ shape の header が back-to-back に並ぶ。各 entry が独立 |
| **B** | 拡張ヘッダ繰り返し | IPv6 ext, GTP-U ext header | wrapper の中に extension header が並ぶ。各 ext は次 type を field で持つ |
| **C** | wrapper + 内部項目列 | SRv6 segment list (16B 固定), TCP/IPv4 options (kind 依存可変) | 1 つの wrapper の中に items が並ぶ。entry 自体には dispatch 情報がない |
| **D** | wrapper + 条件付き単発 | GTP-U opt (E/S/PN flag gated) | wrapper の flag で有無が決まる、最大 1 回 |

これらの **判別基準は wire 構造**:
- 「外側に独立した header が並ぶ」(A) なら chain
- 「wrapper の内側に sub-header が入っている」(B/C/D) なら wrapper の aux

### 6.2 表現指針: chain vs aux

vocab 上の表現は 2 種類:

#### chain protocol (パターン A)

独立した protocol を vocab で 1 つ宣言、quantifier (`+` `*` `?` `{n,m}`) で repetition を表す。DSL 上は wire 順に並んだ別 layer として書く:

```
eth/vlan+/ipv4/tcp                ; VLAN tag (1 個以上)
eth/mpls+/ipv4/tcp                ; MPLS label stack
eth/qinq/vlan+/ipv4/tcp           ; QinQ (S-tag + C-tag stack)
```

vocab 側は `<SELF>_<PARENT>_<FIELD>` 系の dispatch const で「どこから始まるか / どこで終わるか」を declare する。

#### wrapper + aux header (パターン B/C/D)

1 個の protocol が **primary header + 0 個以上の aux header** を持つ形。aux は parser block の `out` 引数として宣言、parser の state machine が「いつ extract するか」を記述する。DSL 上は wrapper protocol の 1 layer として書き、内部の aux は dot path でアクセス:

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

### 6.3 パターン C/D の判定基準: 「中身か外か」

「VLAN は eth の aux」「MPLS は eth の aux」と呼ぶことはしない。理由は VLAN/MPLS の wire 構造:

- VLAN tag は ethertype (0x8100) で type-of-next を持っている = 外側に「並ぶ」存在
- MPLS label は s-bit で stack 終端を持っている = 同上

これらは「eth の中身」ではない。「eth の後ろに並んだ別 protocol layer」なので chain (パターン A)。

一方、SRv6 の segment list は:

- SRH header の last_entry/segments_left field で長さが決まる
- 各 segment は IPv6 アドレスのみで type-of-next を持たない
- SRH header と segments は不可分の 1 セット (segments だけ抜き出して別解釈は不可能)

これは明確に「SRH の中身」=>aux (パターン C)。

GTP の opt も同じ: GTP header の E/S/PN flag で有無が決まる、独立 layer ではない。

### 6.4 過去の設計検討と現方針

開発初期に `srv6_seg` を独立 chain protocol として切り出す案 (`eth/ipv6/srv6/srv6_seg+/tcp`) を実装したが、aux model に切り替えた。判断理由:

1. **wire 構造に対して不誠実**: `srv6/srv6_seg+` は「srv6 → srv6_seg → srv6_seg → ...」と読める。実際は SRH 1 個 + その中の segment 列であり、構造が二段に分離して見えるのは misleading
2. **ネスト SRH (= SRH/SRH、Segment Routing over Segment Routing) と区別困難**: chain として書くと `srv6/srv6_seg+/srv6/srv6_seg+/...` と書ける一方、それが「ネスト SRH」なのか「外側 SRH の segment 列の続き」なのか visually 不明瞭
3. **概念の重複**: chain mechanism と aux mechanism が「リスト的なもの」を 2 系統で扱うことになり、user にとって学ぶ概念が増える

(Y) aux model 採用後は user が見える概念が:
- **chain protocol** (`+` quantifier、`vlan+` のような外側スタック)
- **wrapper + aux** (`protocol.aux_name`、`srv6.segments[N]` のような内側構造)

の 2 つに整理され、wire 構造との対応が一目瞭然になる。

### 6.5 vocab declaration mechanism (8 種)

§6.1 の wire パターン (A/B/C/D) に対し、vocab 著者が使える declaration mechanism は 8 種類ある。**1 つの protocol が複数 mechanism を併用する**ことも普通 (TCP は HDRLEN_* で trailer を確保しつつ、その中身は TLV options walk 経路で読む、など)。

| # | mechanism | declare 方法 | 対応 wire パターン | 例 protocol | codegen 入口 |
|---|---|---|---|---|---|
| **1** | **pkt.advance trailer** | parser block の skip-state で `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)` 1 行 | primary header の variable trailer | IPv4 (IHL × 4 - 20)、TCP (data_offset × 4 - 20) | `parser_machine.go::emitVariableTrail*` |
| **2** | **chain self-loop** | `<SELF>_CHAIN_END_<FIELD>` + `<SELF>_MAX_DEPTH` | A: 全体繰り返し | MPLS (s-bit)、VLAN+、QinQ | `bpfloop.go::chainEndCheck` |
| **3** | **parser self-loop** | parser block の state 自己 transition | B: 拡張ヘッダ繰り返し | IPv6 ext (`parse_ext` self-loop) | `parser_machine.go` state graph |
| **4** | **aux header stack** | `out h_t[N] name` + parser state | B/C: wrapper 内要素列 | SRv6 segments、GTP exts | `parser_machine.go` + `emitDynamicStackAddress` |
| **5** | **gated single aux** | `out h_t name` + transition select で gating | D: 条件付き単発 | GTP opt (E/S/PN flag gated) | `parser_machine.go` state graph |
| **6** | **flag-triggered optional fields** | `<SELF>_OPT_FLAGS_BYTE_OFFSET` + `<SELF>_OPT_TRIGGER_<NAME>` + `<SELF>_OPT_LEN_<NAME>` | D の集合体 (flag 群が固定 size optional を gating) | GRE (C/K/S → checksum/key/seq) | `parser_machine.go::emitOptFlags*` |
| **7** | **TLV options walk** | parser block multi-state self-loop (`parse_options → parse_<name> → parse_options`) + per-option aux header (`tcp_opt_<name>_h`) | C の TLV variant | TCP options (MSS/WS/SACK_PERM/TS) | `parser_machine.go::emitMultiStateSelfLoop` (lifted slot-store prelude) + `where.go::genDynamicOffsetAuxLoad` |
| **8** | **ParserCounter trailer walk** | `extern ParserCounter { ... }` + `ParserCounter() pc;` + `pc.set(...)` / `pc.decrement(N)` + 1-key `select(pc.is_zero())` または 2-key `select(pc.is_zero(), pkt.lookahead<bit<8>>())` (TNA canonical) | byte-bounded walk (mechanism 1 の per-byte 版、mechanism 7 の terminator 兼用版) | (合成 IPv4 で dsltest 経由検証、bundled 採用は B-2 で予定) | `parser_counter.go` + `parser_machine.go::emitMultiState{Counter,CounterKind}Dispatch` |

ユーザーが「可変長」と認識しがちな代表例 4 つの内訳:

- **TCP/IPv4 タイプ** = mechanism 1 (pkt.advance trailer)。TCP はさらに mechanism 7 (TLV walk) を併用して中身を読む
- **MPLS タイプ** = mechanism 2 (chain self-loop)
- **SRv6 タイプ** = mechanism 4 (aux header stack)
- **GTP タイプ** = mechanism 5 (gated single aux: `opt`) + mechanism 4 (aux stack: `exts`) の両用い

これに加えて vocab 著者向けに mechanism 3 (IPv6 ext のような異 type ext-header chain) と mechanism 6 (GRE のような flag-triggered optional) と mechanism 7 (TLV walk) が利用できる。

以下、各 mechanism を順に declare 方法で示す。**mechanism 7 (TLV walk) と mechanism 6 (flag-triggered) は const 宣言だけで自動生成され、parser block を書く必要はない**。残り (mechanism 1 pkt.advance / chain / parser self-loop / aux / aux stack / gated aux) は parser block + state machine で表現する。

(以下の sub-section は文書化の歴史上 1→2→3→5→4→7→6 の順に並んでいる。表の番号で目的の mechanism にジャンプして読むのが楽。)

#### Mechanism 1: pkt.advance trailer (TCP / IPv4 タイプ)

primary header の **末尾に長さ可変の trailer** が付く形。長さは header 内の field (IPv4 IHL、TCP data_offset) × scale で計算できる。parser block の skip-state で P4-16 標準の `pkt.advance` template A を 1 行 declare すれば、loader が field 位置 / mask / shift を自動導出して codegen が長さ計算 + R4 advance + bound check を emit する。

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

template の解釈: `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)` を `(field × 2^(S-3) byte) - (K × 2^(S-3) byte)` の trailer 長と読む。`< 0` (IHL < 5 等) は codegen の lower-bound check で loud reject。trailer **そのもの**には dot path で access できない (=「options 領域があることだけ知ってる」状態)。中身を読みたい場合は mechanism 7 (TLV walk) を併用する。

(B-2 以前は `<SELF>_HDRLEN_BYTE_OFFSET / MASK / SHIFT / SCALE / BASE` の 5 const を手書きで宣言してた。これは header struct の field 位置と redundant で、struct を編集すると 5 const がサイレント壊れる footgun だった。B-2 で parser block 経由に統一、HDRLEN_* 系は loud reject。)

#### Mechanism 2: chain self-loop (MPLS タイプ)

同 shape の header が back-to-back に並ぶ。終了条件は header 内の終端 bit (MPLS の S-bit) で declare する:

```p4
// mpls.p4
const bit<1> MPLS_CHAIN_END_S    = 1;          // S-bit == 1 で stack 末尾
const bit<8> MPLS_MAX_DEPTH      = 8;          // verifier-safe loop 上限
```

DSL 上は `mpls+` quantifier。codegen は bpf_loop subprogram に展開し、各 iter で `<SELF>_CHAIN_END_<FIELD>` の field を読んで break 判定する。

#### Mechanism 3: parser self-loop (IPv6 ext タイプ)

parser block の state が自己 transition で次 ext header に進む形。各 ext header の type (next_header) が次の ext type を指す chain。aux header の固定 reservation 数 (`out h_t[N]`) で verifier-safe な loop 上限を持たせる:

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

DSL では `any(ipv6.exts.next_header == 44)` で fragment 拡張ヘッダの存在判定など。

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

DSL での `gtp.opt.exists` は「`parse_opt` state に到達したか」を runtime で確かめる。`gtp.opt.next_ext` は「opt が extract された場合のみ field 読み、未抽出なら predicate 不一致」。

#### Mechanism 4: aux header stack (SRv6 タイプ、パターン B/C)

P4 の header stack `H[N]` を使う:

```p4
// srv6.p4
header srv6_h     { bit<8> next_header; ... bit<8> last_entry; ... }
header srv6_seg_h { bit<128> addr; }

parser SRv6Parser(packet_in pkt,
                    out srv6_h        hdr,
                    out srv6_seg_h[8] segments) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.routing_type) {
            4:       parse_segments;
            default: reject;
        }
    }
    state parse_segments {
        pkt.extract(segments.next);
        transition select(/* iter < hdr.last_entry+1 を表す */) {
            ...: parse_segments;
            ...: accept;
        }
    }
}
```

stack の reservation 数 (上の例では 8) は **verifier-safe な loop 上限** として codegen が利用する。実 packet では `hdr.last_entry+1` 個まで使われる。

#### Mechanism 7: TLV options walk (TCP options タイプ、パターン C 可変)

各 option を kind ごとに独立 aux header として declare、parser block の multi-state self-loop が kind dispatch + sibling extract で walk する。where 句から option の field を読むときは parser machine が記録した per-packet オフセットを stack slot から引いて直接 LDX する (legacy の where-time 再 walk は B6 で削除済み)。

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

option の identity (kind 値) は parser block の `transition select` case label が pin、wire size は `header tcp_opt_<name>_h` 宣言が pin する。vocab に追加の `OPT_<NAME>_KIND/SIZE` const は不要 (`vocab.AuxLayout.DynamicKindByte` が loader で復元される)。

**Codegen 経路**: `parse_options → parse_<kind> → parse_options` の cycle を `IsMultiStateLoopEntry` predicate (`pkg/kunai/vocab/parser_machine.go`) が検出し、`emitMultiStateSelfLoop` (`pkg/kunai/codegen/parser_machine.go`) が bpf_loop callback に下ろす。

callback の **per-iter 構造** (Phase 2 retry 設計):

1. ctx slot から `R3 = current option offset` / `R4 = scratchStart` / `R5 = scratchEnd` を再 load
2. `JGT R3, ScratchBufSize-1, breakLabel` で R3 の上限を pin (verifier が stack spill 越しに失う bound を取り戻す)
3. `R0 = R4 + R3 + 1; JGT R0, R5, breakLabel` で次 1 byte の peek bound check
4. **Lifted slot-store prelude** — kind byte を R1 に load し、where / capture が query した option ごとに `JNE R1, kindByte, .skip; StoreMem R2, slot, R3; .skip:` を flat に並べる。slot は main frame の per-LayerInstance アドレス、callback からは `R2 + (slot - bpfLoopCtxOffsetSlot)` で reach (`mainStackOffsetFromCb` helper)
5. cascade dispatch (kind 比較 → 各 case body で extract / advance + R3 store-back)

prelude を **cascade の outside** に置くのが重要。per-iter の slot 状態は kind byte だけの関数になり、verifier が「どの case が走ったか × どの slot が変わったか」の組み合わせを per-iter で track せずに済む。これが 6.12+ の 1M-insn 限界に収まる根拠 (per-case slot store でやった失敗パターンは `dsl-followups.md` B-3 の 2026-05-04 試行記録に残してある)。

**Demand-driven 割当**: codegen は `collectQueriedOptions(p)` (`pkg/kunai/codegen/option_demand.go`) で program 全体の where / 各 layer の bracket predicate / 各 capture を walk し、参照された (layer, option) ペアだけ slot を割り当てる。`where tcp.options.MSS.value == 1460` だけなら slot は 1 個 (per-layer × per-aux で最大 4 まで、`dynamicAuxMaxSlotsPerLayer` = TCP の queryable kind 数)。layer entry で各 slot を sentinel `-1` で zero-init (`emitDynamicAuxSentinelInit`) — extract されなかった option は sentinel のまま残り、where 評価で reject される。

**Where 評価**: `tcp.options.MSS.value == 1460` のような predicate は `genArithFieldLoad → dynamicOffsetSlotFor → genDynamicOffsetAuxLoad` (`pkg/kunai/codegen/where.go`) 経路:

1. slot を LDX → R3 (= absolute scratch offset of MSS の先頭、または sentinel)
2. `JEq R3, sentinel, dslReject` (option 不在で predicate false)
3. `foldOffsetIntoScalar(R5, R3, fieldByteOff)` で field 開始位置を scalar に載せる
4. `boundedScalarLoad(R3, R0, R5, R1, size)` で実際の field bytes を read

合計 ~6 insn。pre-Phase-2 の `genOptionLookupLoad` は ~200 insn (20 iter static unroll) だったので一桁減。

**Vocab 著者の手間**: `header tcp_opt_<name>_h { ... }` を declare し、parser block の `transition select` case label に kind を書き、sibling state で `pkt.extract(<name>)` するだけ。`OPT_<NAME>_KIND/SIZE` 等の冗長 const は不要。resolver は `tcp.options.MSS` の `MSS` を lower-case 化して `AuxLayouts["mss"]` を引き、`IsDynamicEligible` を assert する。

#### Mechanism 6: flag-triggered optional fields (GRE タイプ)

primary header の **flag bit が複数の固定 size optional field を gating** する形。GRE の C/K/S flag が checksum / key / sequence の有無を決めるのが代表例。`OPT_FLAGS_BYTE_OFFSET` で flag byte の位置、`OPT_TRIGGER_<NAME>` で各 flag の bit mask、`OPT_LEN_<NAME>` で対応 optional field の byte size を declare する:

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

codegen が flag byte を読んで、各 trigger bit が立っていれば対応 LEN だけ R4 を advance する命令列を順に emit する (`parser_machine.go::emitOptFlags*`)。HDRLEN_* と同様、parser block を書く必要はない。NAME は uppercase の任意 token で、TRIGGER と LEN を NAME で対応付ける。

mechanism 5 (gated single aux) との違い:

- **5 (gated aux)** は **aux header として field が見える** (`gtp.opt.next_ext` で値読みできる)
- **6 (flag-triggered)** は **trailer 領域確保のみ** で、optional field の **値は読めない** (現状)。GRE の checksum/key/sequence は「存在を検出して下流 ipv4/ipv6 への dispatch を正しく動かす」目的で十分だから

#### Mechanism 8: ParserCounter trailer walk (Tofino TNA 互換)

mechanism 1 (pkt.advance trailer) と mechanism 7 (TLV walk) の両方には R4 alignment 上の限界がある:

- **mechanism 1**: trailer を 1 回の bulk advance で skip する。中身を per-element に extract できない (= TCP options 各 kind の位置を記録できない)
- **mechanism 7**: kind dispatch で walk するが EOL kind が `accept` で R4 が trailer 中位置で停止する。TCP は terminal なので無害だが、`tcp/<inner>` chain や IPv4 options walk のように R4 を trailer 末尾まで進めたい場合は align しない

**ParserCounter** (Tofino TNA / P4-16 PSA の標準 extern) は「残り byte 数を per-iter で減らし、0 に達したら walk 終了」という counter-driven 終端を表現する:

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

**設計判断**:

- **counter unit = byte**: BPF-native (Tofino の 32-bit word 単位とは異なる)。`pc.set` の引数は byte count (`pc.set(((bit<8>)(hdr.ihl - 5)) << 5)` で `(ihl-5) × 4 byte`)、`pc.decrement(N)` の N も byte
- **slot 確保**: per-machine reused (=「machine の生存期間中だけ意味を持つ」)。`pkg/kunai/codegen/parser_counter.go` が bpf_loop ctx と where-layer slot の間の gap 領域に最大 2 slot 配置する。layer 跨ぎで再利用される
- **api compat**: `extern ParserCounter { ... }` 宣言は p4lite が opaque-skip するので Tofino spec の method signature をそのまま書ける。`make p4c-check` (= upstream p4test --parse-only) も通る
- **multi-state loop entry の認識**: `vocab.IsMultiStateLoopEntry` が 3 種の key 形を受理する: 単 `SelectKeyLookahead{Bits=8}` (mechanism 7、kind-byte dispatch のみ)、単 `SelectKeyCounterIsZero` (counter 終端のみ)、2-key tuple `(SelectKeyCounterIsZero, SelectKeyLookahead{Bits=8})` (counter 終端 + per-iter kind dispatch、TNA canonical 形)。tuple は順序固定で reverse は `validateStateGraph` が "no lowering for" で reject。codegen `emitMultiStateDispatch` がそれぞれ `emitMultiStateCounterDispatch` (1-key)、`emitMultiStateCounterKindDispatch` (2-key)、kind-only cascade に dispatch する

**Codegen 経路**:

1. **Slot init**: machine entry で全 declared counter slot を 0 で初期化 (`emitCounterSlotInit`、`emitFillStackSlots` 経由)。BPF verifier の "uninitialized stack read" を回避
2. **`pc.set(...)`**: AdvanceField と同じ `lowerCastShiftSkip` 経由で `((header_byte & mask) >> shift) * scale - base` を scratchA に計算、StoreMem で slot へ
3. **`pc.decrement(N)`**: `LoadMem slot → R5; Sub.Imm R5, N; StoreMem slot, R5` の 3 insn (BPF は memory-form arith を持たないので最小)
4. **`pc.is_zero()` select**: `LoadMem slot → R3; JEq.Imm R3, 0, trueLabel` の probe + 2-arm 分岐。2-key tuple `(pc.is_zero(), pkt.lookahead<bit<8>>())` 形では、probe で counter==0 を `trueLandingLabel` に分岐させた後、kind byte を load して `(false, K)` cases の cascade (per-case JNE → sibling body → skip landing)、最後に `(false, _)` または `sel.Default` をフォールスルー、tail に `trueLandingLabel` を置いて `(true, _)` body を emit。kind-byte の load 位置 (R4+R3) は 1-key 形と同一なので `emitMultiStateCallback` の prelude (slot-store cascade) は変更不要

**mechanism 1 / 7 と相補的な点**:

| 軸 | 1 (advance trailer) | 7 (TLV walk) | 8 (ParserCounter) |
|---|---|---|---|
| trailer end alignment | ◎ (bulk advance) | × (EOL で中位置停止) | ◎ (counter exhaustion で末尾) |
| per-element extract | × (bulk skip のみ) | ◎ (kind ごと aux) | △ (counter walk 自体は extract なし、7 と併用) |

production vocab は mechanism 1 / 7 のままで、E2E 検証は `pkg/kunai/dsltest/parser_counter_test.go` の合成 IPv4 vocab を使う (IHL=5 fast path、IHL=6/7 (1-2 iter)、IHL=15 (10 iter = `IPV4_MAX_DEPTH = 11`))。bundled 移行のスコープ・動機は `dsl-followups.md` B-2 / B-5 を参照。

### 6.6 DSL access の体系

aux への access は **dot path で統一**。chain element も同じ accessor を共有する:

| 操作 | 構文 | 適用例 |
|---|---|---|
| 単発 aux のフィールド | `<proto>.<aux>.<field>` | `gtp.opt.next_ext == 0`, `tcp.options.MSS.value == 1460` |
| 単発 aux の存在 | `<proto>.<aux>.exists` | `gtp.opt.exists`, `tcp.options.SACK_PERM.exists` |
| stack/chain の index | `<proto>.<aux>[N].<field>` | `srv6.segments[0].addr == fc00::1` |
| stack/chain の動的 index | `<proto>.<aux>[<expr>].<field>` | `srv6.segments[srv6.last_entry].addr` |
| 集合 ∃ | `any(<expr>)` | `any(srv6.segments.addr == X)`, `any(vlan.id == 100)` |
| 集合 ∀ | `all(<expr>)` | `all(srv6.segments.addr in fc00::/16)` |
| 件数 | `<proto>.<aux>.count` | `srv6.segments.count >= 3` |

`any` / `all` は関数形。bracket 形 `vlan+[id == 100]` は `all(vlan.id == 100)` の syntax sugar として残す (∀ デフォルト維持)。

### 6.7 codegen 上の扱い (概要)

| 表現 | 実装 mechanism |
|---|---|
| 単発 aux への field 読み | parser machine の state graph から「aux 抽出条件」を逆算し、gating check + offset 計算 + field load を emit |
| stack aux への [N] index (静的) | parse-time に `0 <= N < cap` を check、runtime は parser の state graph から算出した offset で field load |
| stack aux への [parent.field] (動的) | runtime に bound check (`<expr> < count`) + dynamic offset 計算 |
| `any(P)` / `all(P)` | bpf_loop 経由で per-iter P 評価。any: 1 個目の match で R0=1 早期 break、all: 1 個目の miss で reject |
| `count` | wrapper の field 由来 (SRv6 の last_entry+1 等) または stack walk 結果 |

implementation 詳細は `pkg/kunai/codegen/parser_machine.go` の state graph emit ロジックを参照。

---

## 7. 制限と将来拡張

詳細は [`dsl-followups.md`](./dsl-followups.md) を参照。本節は制約マップだけ簡潔に列挙。

### 7.1 現状の MVP 制限

| 領域 | 制限 |
|---|---|
| Predicate | `field in [...]` ✅ 整数 alternatives 実装済 (F7) / IPv4/IPv6/MAC/CIDR alternatives は scope outside / `bit<>64` の field に対する `in` は未対応 (今のところ ≤64-bit のみ wired) / `field has FLAG` ⏸ F6 bitwise `&` で superseded (`tcp.flags & 0x12 == 0x12` で同等表現) |
| Where | 算術ネスト最大 4 段 (`maxArithDepth`) / het-alt 後の where が alt member の field を直接参照 (`where ipv6.src == fe80::1`) は reject (alt 識別不能) / `in` は **bracket predicate `[...]` 専用**、where 句では `==` の `or` chain で代替 (parser が targeted hint を返す) |
| Aux × literal | aux header field の値比較は **整数 literal のみ** ✅。IPv4/IPv6/MAC/CIDR literal を aux 経由で比較するパスは `ErrNotImplemented` (例: `srv6.segments[0].addr == fc00::/16`)。followups B-3 で追跡 |
| Capture | `capture f1, f2` フィールド列 不可 / 量化 layer (`+`/`*`/`{n,m}`) を含む filter で `headers+N` 不可。het-alt 越えの capture は max-alt 上界丸めで動作 |
| Alternation | alt 数 2-4 (`altCountCap`) / ✅ heterogeneous size + diverged dispatch 対応 (P3-12) / ✅ nested alt は resolver flatten (P3-13) / quantifier 付き内側 alt (`(a\|b)?`) は reject / 先頭不可 |
| Layer 数 | per-layer entry slot を要する filter は最大 12 layer (`whereLayerEntrySlotCap`)。実用上の chain 深度 (深 6 layer) を充分上回る上限 |
| Parser machine (vocab 著者向け) | select key 幅 ≤8 bit / select key 本数 ≤3 / variable-trail scale は 2 冪のみ / self-loop 反復上限あり (vocab の `<SELF>_MAX_DEPTH` で declare) |
| Self-validation | parser-block 自検証 (`transition select(field) { v: accept; default: reject; }`) のみ。旧 SANITY const family は撤廃 (legacy 名は loud-fail で拒否) |
| Vocab | 1 protocol あたり最大 2 ラベル |
| Kernel | quantifier / parser self-loop あり: 5.17+ (`bpf_loop` 必須) / fixed chain のみ: さらに古くても可 |

### 7.2 アーキテクチャ上動かない要件

以下は本 DSL の design choice 上「動かない」もので、いずれも user 要望が出てから別 design check が必要:

- map references (`map["name"][key]`)
- L7 semantic parsing (DNS body / HTTP / TLS 内部)
- temporal conditions (時間軸条件)
- 自動 encap 推測

---

## 関連ドキュメント

- [`dsl-overview.md`](./dsl-overview.md) — index
- [`dsl-usage.md`](./dsl-usage.md) — ユーザー向け CLI ガイド
- [`dsl-grammar.md`](./dsl-grammar.md) — formal EBNF + 例文
- [`dsl-followups.md`](./dsl-followups.md) — 残作業
- [`dsl-benchmark.md`](./dsl-benchmark.md) — ベンチ方法論
