# DSL 仕様: 構文・型・意味論

DSL filter 式の抽象構文 / 静的型付け / 操作的意味論を一冊にまとめた言語仕様書です。本ドキュメントは仕様、すなわち resolver / codegen が実装すべきルール集であり、現実装の挙動描写ではありません。どこまで現 codegen が対応するかという実装ステージングは §9 を参照してください。

`dsl-grammar.md` が parser の受理する表記である具象構文を、本書が抽象構文 + 型 + 意味を、`dsl-internals.md` が実装アーキテクチャ + パッケージツアー + codegen ABI + vocab 開発ガイドを扱います。3 者の関係は概ね EBNF (concrete) → AST (abstract syntax) → 型付け規則 → 操作的意味論という対応です。

## 目次

### Part I. 型システム (実装済)

1. [はじめに](#1-はじめに)
2. [表記規約](#2-表記規約)
3. [型 τ](#3-型-τ)
4. [リテラル](#4-リテラル)
5. [暗黙変換と widening](#5-暗黙変換と-widening)
6. [演算](#6-演算)
7. [値域チェック (fit check)](#7-値域チェック-fit-check)
8. [型エラー一覧](#8-型エラー一覧)
9. [実装ステージング](#9-実装ステージング)
10. [関連ドキュメント](#10-関連ドキュメント)

### Part II. 形式仕様 (構文論 + 操作的意味論)

11. [抽象構文](#11-抽象構文)
12. [型付け規則 (Typing Judgments)](#12-型付け規則-typing-judgments)
13. [操作的意味論 (Operational Semantics)](#13-操作的意味論-operational-semantics)
14. [p4lite parser machine の意味論](#14-p4lite-parser-machine-の意味論)
15. [実装との対応 (Soundness sketch)](#15-実装との対応-soundness-sketch)

## 1. はじめに

### 1.1 動機

DSL は parser / resolver / codegen の 3 段で構成されますが、resolver は従来、フィールドが declare 済みか、dispatch が解決可能かといった構造的検査しか行っておらず、値の型と幅に関する検査には次のような穴がありました。

- bracket predicate `[dport == 99999]` には fit check があり、16bit field に収まらない 99999 を reject していました。
- where 算術 `tcp.dport > 99999` は未検査で、暗黙ゼロ拡張で通っていました。
- `tcp.dport == ipv4.ttl` (16bit vs 8bit) のような異幅 cmp が無警告で通っていました。
- `gtp.opt.exists + 1` のような kind 違反が arith に紛れ込む余地がありました。

本書はこの穴を塞ぐため、全 expression に明示的な型と coercion ルールを与えます。実装は resolver で `static reject` を発火させる形です。

### 1.2 スコープ

- 対象は DSL filter 式の全構造で、layer chain / predicate / where / capture を含みます。
- p4lite vocab 言語 (`.p4` ファイル) は別 type 系のため対象外です。本書は vocab で declare された field の bit 幅を入力として使います。
- Part II の追加後は、reduction や packet 上の評価規則といった操作的意味論も §13 / §14 で形式化済みです。

### 1.3 目的の優先順位

1. 誤用を早期に検出します。typo / 異幅混在 / kind 違反を resolver で reject します。
2. 直感を保存します。tcpdump 風の式 (`tcp.dport == 443`) は今までどおり通ります。
3. uniform な拡張性を保ちます。IPv4 / IPv6 / MAC を別 kind ではなく `Int<N>` に吸収して構造を単純化します。

## 2. 表記規約

| 記号 | 意味 |
|---|---|
| `e : τ` | 式 e は型 τ を持つ |
| `Γ ⊢ e : τ` | 環境 Γ (vocab + label table) のもとで e の型は τ |
| `τ₁ ⊓ τ₂` | 2 つの型の greatest common type (widening 結果) |
| `v ⤳ Int<N>` | 値 v が Int<N> に narrow される (fit check 付) |
| `Int<N>` | N bit unsigned integer 型 (1 ≤ N ≤ 128) |
| `2ⁿ` | 2 の n 乗 |

EBNF は `dsl-grammar.md` の表記をそのまま流用します。

## 3. 型 τ

### 3.1 型の集合

```
τ ::= Int<N>          N ∈ {1, 2, ..., 128}
    | CIDR4
    | CIDR6
    | Bool
    | Action
```

各型の役割は次のとおりです。

| 型 | 役割 | 由来 |
|---|---|---|
| `Int<N>` | 整数値全般 (フィールド値、リテラル narrow 後、算術結果) | vocab の `bit<N>` field 宣言 |
| `CIDR4` | IPv4 subnet (range として使用) | リテラル `<addr>/<prefix>` (AF=4) |
| `CIDR6` | IPv6 subnet | 同 (AF=6) |
| `Bool` | 真偽値 | cmp 結果 / `<aux>.exists` / quantifier 結果 / Bool literal |
| `Action` | XDP action 等の symbolic 値 | `XDP_DROP` 等の literal |

### 3.2 IPv4 / IPv6 / MAC は型ではなく shaped Int<N>

IPv4 / IPv6 / MAC は独立した型ではなく、Int<N> の特定 width として扱います。

| 概念 | 型 |
|---|---|
| IPv4 アドレス値 | `Int<32>` |
| IPv6 アドレス値 | `Int<128>` |
| MAC アドレス値 | `Int<48>` |

リテラル parser は `ValIPv4` / `ValIPv6` / `ValMAC` を識別しますが、型システム上は単なる Int<N> です。識別情報はエラーメッセージなどの診断用途にのみ使います。

これにより次の利点があります。

- Int<32> 同士なので、`ipv4.dst < 10.0.0.10` のような ordered cmp が自然に書けます。
- Int<48> 同士なので、`eth.src + 1 == eth.dst` のような MAC 算術も書けます。
- IPv4 とは Int<32> である、MAC とは Int<48> であると説明し直せて、type 系の sort 数が減ります。

### 3.3 Subtyping

subtype 関係は持ちません。`Int<8> ⊑ Int<16>` のような暗黙ワイドニングは subtype ではなく、§5 の explicit な widening 演算として表現します。これにより次の効果があります。

- 異幅 cmp が暗黙に通る事故を意図的な widening に置き換えます。
- subtype 探索が要らないため、型推論が単純になります。
- 将来 `(bit<32>) tcp.dport` のような explicit cast 構文を入れる余地を残します。

### 3.4 Bit-slice

field の特定 bit 範囲は、次の bit-slice 構文で取り出します。

```
field[lo:hi]                    ; half-open bit range, lo inclusive / hi exclusive
                                ; bit 0 = network-order MSB (IETF 規約)
                                ; result type = Int<hi - lo>
```

例を示します。

| 式 | 結果型 | 意味 |
|---|---|---|
| `ipv6.src[0:32]` | `Int<32>` | IPv6 アドレスの先頭 4 octets (= `/32` prefix を数値化) |
| `ipv6.src[96:128]` | `Int<32>` | 末尾 4 octets (IPv6 → IPv4 互換アドレス検査などに) |
| `ipv6.src[64:128]` | `Int<64>` | 下位半分 (subnet identifier + interface ID) |
| `ipv4.dst[0:8]` | `Int<8>` | IPv4 アドレスの最上位 octet (Class A の network 番号など) |

結果幅と用途のマトリクス (§9.1) は次のとおりです。

| 範囲 | cmp (`==`/`!=`) | arith binop / bitwise | non-aligned 端点 |
|---|---|---|---|
| `≤ 64` | ✅ single LDX | ✅ single register | ✅ codegen で `pow2 ≥ cover` LDX → bswap → shift+mask |
| `(64, 128]` | ✅ resolver desugar (LDX-aligned chunks の AND/OR-chain、例: `[0:96]` → `[0:64]` AND `[64:96]`) | ❌ single register に乗らないため未対応 | ❌ byte-aligned 端点必須 |

`!=` の chain は OR で、`==` は AND でつなぎます。endpoint が 64bit 境界を跨ぐ場合は両端が byte-aligned であることが要件で、sub-byte 跨ぎ + 64+ bit は scope 外です。

型ルールは次のとおりです。

```
[T-FieldSlice]
Γ ⊢ field(f) : Int<W>     0 ≤ lo < hi ≤ W
─────────────────────────────────────────
Γ ⊢ field(f)[lo:hi] : Int<hi - lo>
```

意味論は次のとおりです。

```
⟨field(f)[lo:hi], σ⟩ ⇓_P n
  where n = (load(f, σ, P) の bit lo..hi-1 を host order で連結した値)
```

bracket predicate と where 算術の双方で使用できます。

```
eth/ipv6[src[0:32]==0x20010db8]/tcp                        # bracket
where ipv6.src[64:128] == ipv6.dst[64:128]                  # where-arith
where (ipv6.src[0:32] & 0xff000000) != 0                    # arith / bitwise と組合せ
```

実装は `lexer/lexer.go` の TokColon、`parser/predicate.go::tryParseIndexExpr` の slice 分岐、`resolve/typing.go::detachTrailingSlice` + `attachSlice`、`codegen/codegen.go::applySliceToOffset` です。

## 4. リテラル

### 4.1 整数リテラル

| 表記 | 例 |
|---|---|
| 10進 | `443`, `1024` |
| 16進 (`0x` prefix) | `0xff`, `0xc0a80101` |
| 負数 (`-` prefix) | `-1`, `-128` |

parser-time の値域は `[-2⁶³, 2⁶⁴)` です。これを超える数値リテラルは parser でエラーになります。

`-1` のような負数は、2's complement で文脈型 `Int<N>` に narrow されます。たとえば `Int<16>` 文脈では `-1` ⤳ `0xffff` となります。

### 4.2 IPv4 リテラル

```
ipv4 := octet '.' octet '.' octet '.' octet
octet := 0..255
```

例: `10.0.0.1`, `192.168.1.1`

parser-time 制約は次のとおりです。

- 各 octet が 0..255 の範囲内である必要があります。
- `010.0.0.1` のような zero-prefix octet は reject します。
- `10.0.0.1.` のような trailing dot は reject します。

型は `Int<32>` です。詳細は §3.2 を参照してください。

### 4.3 IPv6 リテラル

RFC 4291 形式に準拠します。

```
ipv6 := full-form | shortened-form | ipv4-mapped-form
```

例: `fe80::1`, `2001:db8::1`, `::ffff:1.2.3.4`

parser-time 制約は次のとおりです。

- RFC 4291 に準拠します。
- zone id (`%eth0`) は packet bytes に乗らないため拒否します。
- bracket form (`[fe80::1]`) は URL 表記との混同を避けるため拒否します。

型は `Int<128>` です。

### 4.4 MAC リテラル

```
mac := octet ':' octet ':' octet ':' octet ':' octet ':' octet   (hex)
```

例: `aa:bb:cc:dd:ee:ff`, `AA:BB:CC:DD:EE:FF`

parser-time 制約は次のとおりです。

- colon 区切り 6 octet のみを受理します。
- 大文字小文字はどちらも許容します。
- dash 区切り (`aa-bb-..`) と Cisco dot 形式 (`aabb.ccdd.eeff`) は拒否します。この決定は確定です。

型は `Int<48>` です。

### 4.4.1 MAC 表記の単一化に関する決定事項

実用上、MAC アドレスには 3 つの慣習表記が流通しています。IEEE / ifconfig / ip-link で使われる colon (`aa:bb:cc:dd:ee:ff`)、Windows や一部 syslog で使われる dash (`aa-bb-cc-dd-ee-ff`)、Cisco IOS で使われる Cisco dot (`aabb.ccdd.eeff`) です。本書はこのうち colon のみを受理します。理由は次のとおりです。

1. lexer の値モード曖昧性を回避するためです。Cisco dot 形式は `aabb.ccdd.eeff` のように `.` を区切り文字に使います。一方、IPv4 リテラルも `.` 区切り (`10.0.0.1`) です。同一トークン内で `.` を 2 用途に分けると、classifier が `aabb.ccdd.eeff` と `10.0.0.1.5` (= 5 oct なので即 reject されますが、先読みコストが要ります) を区別できず、正規表現ベースで解いてもエッジケースが残ります。
2. dash 形式は構造的に value-byte を使うためです。§4.1 のとおり、`-` は値モードで負数 literal の prefix として既に役割を持ちます。`-aa-bb-..` のような頭から `-` で始まる token を MAC として扱おうとすると、負数判定と衝突します。
3. canonical form を統一するためです。1 つの形式に絞ることで、filter 文字列を比較・キャッシュ・diff する処理が単純化されます。
4. 必要なら IDE / wrapper レイヤで変換できるためです。dash / dot 表記を colon に正規化するのは 1 行の置換なので、library 利用者の責務として外側に出します。

このため §4.4 の reject は最終決定であり、follow-up として再検討する予定はありません。

### 4.5 CIDR リテラル

```
cidr4 := ipv4 '/' prefix4   (prefix4: 0..32)
cidr6 := ipv6 '/' prefix6   (prefix6: 0..128)
```

例: `10.0.0.0/24`, `fe80::/64`

parser-time 制約は次のとおりです。

- prefix は AF ごとの範囲内 (`/0`〜`/32` または `/0`〜`/128`) に収まる必要があります。
- host bits 非ゼロは reject します。たとえば `10.0.0.5/24` は reject し、`10.0.0.0/24` を要求します。
  - エラーメッセージでは `network would be 10.0.0.0/24` + `(suggestion: 10.0.0.5/32 for the single host)` のように誘導します。
- 全アドレスに match する `/0` と、host match の `/32` / `/128` は許容します。

型は `CIDR4` / `CIDR6` です。

### 4.6 Bool リテラル

```
bool-lit := 'true' | 'false'
```

型は `Bool` です。

constant folding が可能で、`where true` ≡ `where` 省略、`where false` ≡ 全 reject が成り立ちます。

### 4.7 Action リテラル

upper-case ident で、次の形式です。

```
action-lit := upper-case-ident
```

例: `XDP_DROP`, `XDP_PASS`, `XDP_TX`, `XDP_REDIRECT`, `XDP_ABORTED`

resolver-time 制約は次のとおりです。

- `caps.Lang.Action` map に登録された ident のみ valid です。
- `XDP_FOO` のような登録外 ident は resolver で reject します。

型は `Action` です。

## 5. 暗黙変換と widening

リテラルや異幅整数の比較・演算で発火する暗黙変換ルールを定義します。

### 5.1 リテラルの principal-typing

整数リテラル `v` は parse 直後には型を持たない値として扱います。利用文脈で必要な型が決まったときに、その型に narrow されます。この narrow が値域チェックに相当します。

具体的には次のとおりです。

| 文脈 | narrow 先 | 動作 |
|---|---|---|
| `Int<N>` field との cmp | `Int<N>` | `v` を Int<N> に narrow、fit check (§7) |
| `Int<N>` field との arith | `Int<N>` | 同上 |
| Bool 文脈 (`where v`) | `Bool` | `v != 0` として coerce (§5.4) |
| 単独 `where v` (literal-Bool fold) | `Bool` | `true` / `false` に fold |

注意点として、`UInt` のような専用型を spec 上は導入しません。リテラルは値であって型ではない、と扱います。これは Go の untyped constant に近い設計です。

### 5.2 整数 widening (`Int<N>` × `Int<M>`)

cmp / arith の二項演算で異幅整数が出会ったときは、次のようになります。

```
Int<N> ⊓ Int<M> = Int<max(N, M)>           (zero-extension で短い方を拡張)
```

例を示します。

- `tcp.dport (Int<16>) == ipv4.ttl (Int<8>)` → 両者を `Int<16>` に lift して比較します。上位バイトには 0 が入ります。
- `eth.src (Int<48>) < 0xaabbccddeeff (literal)` → literal を `Int<48>` に narrow し、ordered cmp を `Int<48>` で行います。
- `ipv6.src (Int<128>) == ipv4.dst (Int<32>)` → Int<32> を zero-extend して `Int<128>` に lift します。

DSL の整数はすべて unsigned のため、符号拡張は行いません。

### 5.3 widening の適用範囲

widening は比較演算の両 operand、および算術演算の operand 同士で発火します。算術の結果型は §6.1 のとおり `Int<max(N, M)>` です。

### 5.4 `Int<N>` → `Bool` coercion (Bool 文脈)

Bool が要求される文脈で `Int<N>` 値が現れたときは、C 風の non-zero check として次のように coerce します。

```
v ∈ Int<N> → (v != 0) ∈ Bool         (Bool 要求文脈で発火)
```

Bool 要求文脈は次のとおりです。

- `where atom` (`where tcp.syn`)
- `not` の operand (`not tcp.syn`)
- `and` / `or` の operand (`tcp.syn and tcp.ack`)
- `any(...)` / `all(...)` の inner expression
- `Bool == Bool` / `Bool != Bool` の operand (片方が Bool のとき他方も Bool に coerce)

例を示します。

| 式 | 解釈 |
|---|---|
| `where tcp.syn` | `tcp.syn != 0` (Int<1> → Bool) |
| `where ipv4.ttl` | `ipv4.ttl != 0` (実質 always true、tautology だが型 OK) |
| `where tcp.dport - 80` | `(tcp.dport - 80) != 0` ≡ `tcp.dport != 80` |
| `where 0` | `false` (literal-Bool fold) |
| `where 1` | `true` (literal-Bool fold) |

逆方向 (Bool → Int) の coercion は行いません。`true + 1` のような書き方は型エラーです。

### 5.5 明示 cast 構文

導入しません。follow-up F2 (§9.4) として登録済みで、将来的に必要になったら検討します。

## 6. 演算

### 6.1 算術演算 (`+`, `-`, `*`, `/`, `%`, `&`, `|`, `^`, `<<`, `>>`)

operand 制約は次のとおりです。

- リテラル narrow を含め、両 operand とも `Int<N>` である必要があります。
- `Bool`, `Action`, `CIDR4`, `CIDR6` は禁止で、型エラーになります。

結果型は `Int<max(N, M)>` で、modulo `2^max(N, M)` の silent wrap です。

concrete syntax の binding 強さを表す precedence は次のとおりです。

| precedence | 演算子 |
|---|---|
| 高 | `*` `/` `%` `&` `<<` `>>` (mul-class) |
| 低 | `+` `-` `\|` `^` (add-class) |

bitwise op は通常の C と同様に `&` を mul-class、`|`/`^` を add-class に置きます。これにより `tcp.flags & 0x12 == 0x12` は `(tcp.flags & 0x12) == 0x12` と読まれます。

例を示します。

| 式 | 結果型 | 値 (例) |
|---|---|---|
| `tcp.dport + 1` | `Int<16>` mod 2¹⁶ | dport=65535 のとき結果 0 (wrap) |
| `tcp.dport + ipv4.ttl` | `Int<16>` (widen) | |
| `ipv6.src + 1` | `Int<128>` mod 2¹²⁸ | (`field op const` の codegen は実装済、ただし verifier-load は staged。§9 参照) |
| `ipv4.total_length - 20` | `Int<16>` mod 2¹⁶ | total=10 のとき結果 65526 (wrap) |
| `tcp.window * 2` | `Int<16>` mod 2¹⁶ | overflow は silent wrap |
| `tcp.flags & 0x12` | `Int<9>` (TCP flags は 9 bit) | bitwise AND |
| `tcp.dport >> 4` | `Int<16>` | logical right shift |

static な `/0` `%0` は、RHS が literal `0` のとき resolver で reject します。

runtime の `/0` `%0` は、BPF 既定の結果 0 を意味論として codify します。`tcp.dport / ipv4.ttl` で TTL=0 だったとき、結果は 0 になります。

shift 量について、`<<` / `>>` の RHS は `[0, 64)` 以内の static literal を推奨します。範囲外は静的 reject にはせず、BPF 定義の masked shift 挙動に従います。

### 6.2 比較演算 (`==`, `!=`, `<`, `≤`, `>`, `≥`)

#### Typing matrix

| LHS | RHS | `==` `!=` | `<` `≤` `>` `≥` |
|---|---|---|---|
| `Int<N>` | `Int<M>` | ✅ widen to `Int<max(N,M)>` (codegen ≤128。bracket は dual-LDX、where-arith は F3 ordered + F4 eq/ne) | ✅ 同左 |
| `Int<N>` | literal `v` | ✅ `v ⤳ Int<N>` (fit check, codegen ≤128) | ✅ 同左 |
| literal `v` | `Int<N>` | ✅ 対称 | ✅ 対称 |
| literal `v` | literal `w` | ✅ コンパイル時 fold | ✅ 同左 |
| `Int<32>` | `CIDR4` | ✅ subnet membership | ❌ |
| `Int<128>` | `CIDR6` | ✅ subnet membership | ❌ |
| `Int<N>` (N≠32, ≠128) | `CIDR4` / `CIDR6` | ❌ width mismatch | ❌ |
| `Action` | `Action` literal | ✅ | ❌ |
| `Action` literal | `Action` | ✅ 対称 | ❌ |
| `Bool` | `Bool` | ✅ iff / xor | ❌ |
| `CIDR4/6` | `CIDR4/6` | ❌ | ❌ |
| 異 kind (`Int<32>` × `CIDR6`、`Int<N>` × `Action` 等) | | ❌ | ❌ |

#### LHS / RHS 対称性

すべての比較演算は operand を入れ替えても等価です。例を示します。

- `tcp.dport == 443` ≡ `443 == tcp.dport`
- `ipv4.dst == 10.0.0.0/24` ≡ `10.0.0.0/24 == ipv4.dst`
- `tcp.dport < 1024` ≡ `1024 > tcp.dport` のように、ordered cmp は op を反転します。

parser は LHS / RHS どちらにも literal を許容します。

### 6.3 論理演算 (`not`, `and`, `or`)

operand は `Bool` のみです。Int<N> → Bool の coercion 経由で Int<N> が出てくることは許容されます。

```
not  : Bool → Bool
and  : Bool × Bool → Bool
or   : Bool × Bool → Bool
```

短絡評価があります。and は左が false のとき右をスキップし、or は左が true のとき右をスキップします。

### 6.4 CIDR membership

```
== : Int<32> × CIDR4 → Bool       (Int<32> ∈ CIDR4)
== : Int<128> × CIDR6 → Bool      (Int<128> ∈ CIDR6)
!= : 同上の否定
```

§6.2 のとおり、ordered cmp は不可です。CIDR の境界相対比較は `Int<N>` の `<` `>` で次のように書きます。

- range の境界を明示して `ipv4.dst >= 10.0.0.0 and ipv4.dst <= 10.0.0.255` と書きます。

### 6.5 quantifier (`any`, `all`)

```
any : Bool → Bool         (∃ over aux header stack)
all : Bool → Bool         (∀ over aux header stack)
```

inner expression は stack reference を 1 つだけ含む Bool 式です。stack reference の数が 0 または 2 以上の場合は parser-time error になります。

空 stack の場合は次のようになります。
- `any({}) = false`
- `all({}) = true`

詳細は `dsl-grammar.md §1.4` を参照してください。

## 7. 値域チェック (fit check)

### 7.1 概要

リテラル narrow が起きるすべての場面で、値が target 幅に収まるか確認します。

### 7.2 fit check が発火する場面

| 場面 | 例 |
|---|---|
| Bracket predicate | `tcp[dport == 443]` |
| Where literal cmp | `tcp.dport == 443` |
| Where arith cmp | `tcp.dport + 1 > 1000` |
| Arith binop operand | `tcp.dport + 99999` |
| 対称形 (LHS literal) | `443 == tcp.dport` |
| Bool 文脈の literal | `where 0` (= `false`) |

### 7.3 fit の判定基準

`Int<N>` への narrow は、値域 `[-2^(N-1), 2^N)` に収まる必要があります。

- 非負側の上限は `2^N` (= unsigned max + 1) です。
- 負側の下限は `-2^(N-1)` (= signed min) です。

つまり `-1` は全 bit が 1 の値として任意の N で許容されます。`-129` は signed range `[-128, 256)` から外れるため `Int<8>` には収まりませんが、`Int<9>` 以上なら許容されます。

例を示します。

| literal | target | 結果 |
|---|---|---|
| `443` | `Int<16>` | ✅ (443 < 65536) |
| `99999` | `Int<16>` | ❌ (99999 ≥ 65536) |
| `-1` | `Int<8>` | ✅ (`-1 ⤳ 0xff`) |
| `-129` | `Int<8>` | ❌ (`-129 < -128`) |
| `-129` | `Int<16>` | ✅ (`-129 ⤳ 0xff7f`) |

### 7.4 階層 (parse-time / resolve-time)

| Check | タイミング | 場所 |
|---|---|---|
| 整数 literal 値域 (`[-2⁶³, 2⁶⁴)`) | parse-time | lexer / parser |
| IPv4 octet 0..255 | parse-time | parser |
| MAC octet 数 / 形式 | parse-time | parser |
| IPv6 RFC 4291 形式 | parse-time | parser |
| CIDR prefix 範囲 / host bits ゼロ | parse-time | parser |
| `Int<N>` への narrow fit | resolve-time | resolver typing pass |
| width-shape mismatch (kind 違反) | resolve-time | resolver typing pass |
| Action ident keyset 登録 | resolve-time | resolver |

### 7.5 width-shape mismatch (kind 違反)

literal の暗黙幅と field の幅が異なるときに reject します。

| 例 | 結果 |
|---|---|
| `tcp.dport == 10.0.0.1` | ❌ IPv4 literal は Int<32>、tcp.dport は Int<16> → width mismatch |
| `ipv4.dst == fe80::1` | ❌ IPv6 literal は Int<128>、ipv4.dst は Int<32> → width mismatch |
| `tcp.dport == aa:bb:cc:dd:ee:ff` | ❌ MAC literal は Int<48>、tcp.dport は Int<16> → width mismatch |
| `ipv4.dst == fe80::/64` | ❌ CIDR6 (Int<128> 用)、ipv4.dst は Int<32> → AF mismatch |
| `tcp.dport == XDP_DROP` | ❌ Action と Int<16> → kind mismatch |

補足すると、§3.2 で IP/MAC を Int<N> に吸収したので同幅であれば OK とも書けますが、リテラル parser が識別している kind 情報 (IPv4 / IPv6 / MAC) を使って、`IPv4 literal cannot be compared with bit<16> field tcp.dport (IPv4 requires bit<32>)` のようなより親切なエラーメッセージを出します。

## 8. 型エラー一覧

resolver / parser が出すエラーメッセージのカタログです。すべて `<position> ` プレフィックス付きで、末尾ピリオドはありません。

### 8.1 fit check 系

実装の helper (`resolve/typing_errors.go`) と一致します。`resolve/typing_errors_test.go` で drift を検知します。

```
value 99999 does not fit in 16-bit field tcp.dport                       # bracket / where literal cmp (errFitInField)
value 99999 does not fit in bit<16> (in arithmetic context)              # where 算術 (errFitInArith)
integer literal 99999999999999999999999 exceeds the supported range [-2^63, 2^64)   # parser-level
```

### 8.2 width / shape mismatch

```
IPv4 address literal needs a bit<32> field; tcp.dport is bit<16>         # errLiteralFieldShape
IPv6 address literal needs a bit<128> field; ipv4.dst is bit<32>
MAC address literal needs a bit<48> field; tcp.dport is bit<16>
IPv4 CIDR literal needs a bit<32> field; tcp.dport is bit<16>
IPv6 CIDR literal needs a bit<128> field; ipv4.dst is bit<32>
```

### 8.3 operator 適用エラー

```
ordered comparison < not allowed for Bool (Bool supports only == and !=)                                 # parser & resolver
ordered comparison < not allowed for CIDR (CIDR supports only == and !=)                                 # resolver (errOrderedNotAllowed)
ordered comparison < not allowed for address (address supports only == and !=)                           # resolver (network literal)
```

parser は LHS-literal / Bool 経路で早期に reject し、resolver は IR boundary で defense in depth として再 reject します。

### 8.4 coercion / kind mismatch

Spec 上は禁止ですが、現 parser/AST が Bool/Action/CIDR を arith node の operand に出せない構造のため、明示エラーは発生しません。D8 一元化 (`resolve/typing.go`) で operand-kind の resolver-side reject 自体は実装しましたが、parser/AST 構造上 unreachable な経路なので catalog には行が立ちません。

### 8.5 CIDR 専用

```
CIDR "10.0.0.5/24" has host bits set; network would be 10.0.0.0/24 (suggestion: 10.0.0.0/24 for the subnet, or 10.0.0.5/32 for the single host)   # lexer
CIDR "10.0.0.0/33": invalid CIDR address: ...                                         # net.ParseCIDR 由来
```

### 8.6 Action 専用

```
unknown action "XDP_FOO" (host accepts 5 symbols)                                     # errUnknownActionLiteral
action can only be compared with a symbolic action literal; got integer 1
```

### 8.7 division / modulo

```
division by zero                                                                       # errStaticDivZero
modulo by zero
```

### 8.7a overflow / underflow 疑い (F1: opt-in `StrictArithLint`)

`codegen.Capabilities.StrictArithLint` を有効にすると、保守的に検出した overflow / underflow パターンを resolver が型エラーとして次のように reject します。

```
arith may overflow: <expr> can exceed Int<N> max value (use a wider field or guard)    # errArithOverflowSuspect
arith may underflow: <expr> can fall below 0 (RHS may exceed LHS)                       # errArithUnderflowSuspect
```

検出パターンは false-positive を避けるため保守的で、次のとおりです。
- `field + field` / `field * field` で結果が Int<max(N,M)> をはみ出し得るパターン
- `field - field` で RHS ≥ LHS となる可能性があるパターン

`field + const` などの一般パターンは pass します。

### 8.8 codegen 未実装 (resolver は OK、codegen で reject)

`ErrNotImplemented` の wrapped reason として現れます。spec §9.1 で段階展開している分は次のとおりです。

```
dsl codegen is not yet fully implemented: value V exceeds int32 immediate range — staged Int<N>>32 cmp (dsl-types.md §9.1, F3)
```

## 9. 実装ステージング

### 9.1 codegen サポート範囲

型システムは uniform に書かれていますが、codegen の実装は次のように段階的に展開します。

| 操作 | N ≤ 64 | 64 < N ≤ 128 |
|---|---|---|
| `==`, `!=` | ✅ 既存 (single load) | ✅ 既存 (dual load。IPv6 cmp 経路 / F4) |
| `<`, `≤`, `>`, `≥` | ✅ 既存 | ✅ bracket / where-arith 両方実装 (F3、`emitIPv6OrderedCmp` + `genArithCompare128` ordered branch、register-pair lex compare) |
| `+`, `-` | ✅ 既存 | ✅ where 経路で完全実装 (F4。`field op const`、`field op field` 両方、stack-bridged carry / borrow) |
| `*` | ✅ 既存 | ❌ 廃止 (F11 bit-slice で代替) |
| `/`, `%` | ✅ 既存 | ⏳ 当面実装しない (software loop、需要薄) |
| bit-slice `field[lo:hi]` | ✅ 任意 bit 範囲 (single LDX + bswap + shift+mask、F11/F13) | ✅ byte-aligned 端点に限り cmp 可 (F12 で resolver desugar) |

未実装分は codegen が `ErrNotImplemented` を返します。型では well-typed、codegen で `not yet implemented` という分離です。

Literal narrow (§4.1 / §7.3) について、負数を 2's complement で uint64 化したものを含む整数リテラルは、codegen の最終 emit 直前に対象 field の幅 N でマスクされます。`tcp.dport == -1` ⇒ 比較 immediate = `0xffff` (Int<16> narrow) となります。これにより signed-extended 値が int32 immediate 範囲に収まります。実装は bracket predicate 用 (`codegen/predicate.go::emitIntPredicate`) と where arith cmp 用 (`codegen/where.go::genArithWithBits`、target bits は両 operand の field 最大幅から計算) の 2 箇所です。

### 9.2 段階展開の意図

- 型仕様は uniform で書くため、drift しません。
- 実装は需要に応じて codegen を追加する PR を出すだけで、型仕様は不変です。
- ユーザーには型 OK だが実装待ちであることを素直に伝えます。

### 9.3 実装履歴メモ

`feat/p4_based_dsl` ブランチで DSL コンパイラを 0 から立ち上げ、その上に本書の型システム + 形式仕様を載せました。最終的に次の 6 つの章別 commit に整理して land しました。

| commit | 章 |
|---|---|
| `1ba5b8d7` | feat(dsl): kunai DSL compiler (scaffolding through multi-protocol vocab) |
| `ca45e1a4` | feat(dsl): aux header system (gating, stacks, dynamic indices, option walk) |
| `4e997249` | refactor(dsl): vocab maintenance (self-validating dispatch + p4c interop) |
| `2fc3120d` | feat(dsl): static type system + formal spec (PR-1 ~ D8) ← 本書 Part I + Part II |
| `69e65376` | feat(dsl): F1-F13 follow-up landings ← §9.4 全 follow-up |
| `9e180f54` | chore(dsl): branch review polish (P0 nil-refs + unit tests + doc sync) |

各 commit の body には子機能の内訳とヘルパ関数名・テスト名が並ぶので、`git log --format=full feat/p4_based_dsl ^main` で章別の落とし込みを追えます。本書の D0-D10 各決定がどう実装に降りたかは `2fc3120d` および `69e65376` を参照してください。

pre-squash backup として、161 commit の細かい history を `pre-squash-backup` tag に保存しています。必要なら `git log pre-squash-backup` で個別 commit 単位の追跡が可能です。

### 9.4 follow-up 項目

`dsl-followups.md` に登録される後続作業のうち、本書の決定に直接由来するものは次のとおりです。

| # | 項目 | 由来 |
|---|---|---|
| F1 | overflow lint mode ✅ 完了 (`resolve.Options.StrictArithLint` opt-in、`codegen.Capabilities.StrictArithLint` 経由で host が選択)。検出パターンは保守的: `field + field` / `field * field` の overflow、`field - field` で RHS ≥ LHS の underflow を error 化。`field + const` などの一般パターンは false-positive を避けるため pass | §6.1 silent wrap への安全網 |
| F2 | 明示 cast 構文 (`(bit<32>) tcp.dport`) ⏸ 仕様で導入しないと決定 (§5.5)。F1 の overflow ケアの代替手段が必要になったら再検討 | §5.5 |
| F3 | `Int<128>` ordered cmp の codegen ✅ bracket / where-arith 両方完了。bracket は `emitIPv6OrderedCmp`、where-arith は `genArithCompare128` の ordered branch で同じ lex compare ロジックを共有 (high half decision + low half fall-through、`highHalfJumps` / `lowHalfMissJump` を流用) | §9.1 |
| F4 | `Int<128>` arith binop (`+`, `-`) の codegen ✅ 完了。`field == field` / `field op const == field` / `field op field == field` の全形が verifier-load 通過。旧版が `field op const` で permission denied になっていたのは emit が R6/R7 (host-callee-saved) を使い ABI 違反していたため。現在は const-relative carry detect (R5+const 後 `R5 < const` で wrap 判定、orig 保存不要) と stack-bridged の field+field shape で R6-R8 完全不使用。実装は `genArith128FieldOpConst` / `genArith128FieldOpField` で分岐 | §9.1 |
| F5 | `Int<128>` arith binop (`*`) の codegen ❌ 廃止 (= スコープから外す)。代替として bit-slice 構文 `field[lo:hi]` を導入 (下記参照)。実用上 IPv6 同士の乗算は使い道がなく、bit-slice の方が prefix/suffix 比較で広く使えるため | §9.1 |
| F11 | bit-slice `field[lo:hi]` ✅ MVP 完了。bracket predicate / where-arith 両方で使用可 | dsl-types.md §3.4 |
| F12 | bit-slice の (64, 128) 中間 width cmp ✅ 完了 (resolver で AND/OR-chain に desugar、`tryDesugarMultiLDXSliceCmp`) | F11 の延長 |
| F13 | bit-slice の non-aligned 範囲 (`[3:9]`, `[4:12]` など) ✅ 完了 (codegen で pow2-cover load → bswap → shift+mask、`emitSliceShiftMask`)。≤ 64bit 内なら任意の bit 範囲を抽出可 | F11 の延長 |
| F6 | bitwise op (`&`, `|`, `^`, `<<`, `>>`) ✅ 完了。precedence: `&` `<<` `>>` は mul/div 級、`|` `^` は add/sub 級 | DSL 機能拡張 (TCP flag check 等で需要) |
| F7 | `field in [...]` 実装 ✅ 整数 alternatives は完了 (`emitInPredicate`)、IPv4/IPv6/MAC/CIDR alternatives は MVP scope 外 | 既存 dead syntax の有効化 |
| F8 | `field has FLAG` 専用 codegen ⏸ superseded。F6 の bitwise `&` で同等表現 (`tcp.flags & 0x12 == 0x12`) が書けるので独自 emit は不要と判断。resolver は引き続き `PredHas` を `Unsupported` 扱い (使うと `ErrNotImplemented`) で、ユーザーには bitwise 形式を促す形になっている。vocab 側に flag 定数を declare するのは vocab 著者の自由 | F6 で代替 |
| F9 | `flow.*` dead syntax 削除 ✅ 完了 | 整理 |
| F10 | `Bool == Bool` precision-preserving codegen ✅ 完了 | `genConditionAsBool` で各 operand を {0, 1} に評価して register に置き、scratch slot 経由で比較。per-packet operand 評価は 1 回ずつ |

## 10. 関連ドキュメント

- [`dsl-overview.md`](./dsl-overview.md) (index)
- [`dsl-grammar.md`](./dsl-grammar.md) (formal EBNF + 例文。本書の具象構文側)
- [`dsl-internals.md`](./dsl-internals.md) (内部実装ノート、ABI、vocab 開発ガイド)
- [`dsl-usage.md`](./dsl-usage.md) (エンドユーザー向け CLI ガイド)
- [`dsl-followups.md`](./dsl-followups.md) (残課題リスト。F1-F13 / 完了状態 / 未着手項目)

# Part II. 形式仕様 (構文論 + 操作的意味論)

Part I は、どこに何の check を入れるかという実装者向け実用仕様でした。Part II は言語仕様としての形式定義であり、抽象構文・型付け規則・操作的意味論を judgment 形式で書き下します。verifier 通過 ⇒ spec 通り動くという codegen の正当性を、将来 lemma として証明したいときの土台になります。

実装が Part II と乖離した場合は、コードか Part II のどちらかが間違っています。両者を同期しているのが Part I の実装ステージング §9 と §15 です。

## 11. 抽象構文

`dsl-grammar.md` は、parser が受理する EBNF である具象構文を扱います。本節は、AST node の inductive 定義である抽象構文を表します。具象 → 抽象の対応は parser (`pkg/kunai/parser/`) の責務です。

### 11.1 表記

メタ変数は次のとおりです。

| 記号 | 意味 |
|---|---|
| `F` | filter (フィルタ式の根) |
| `L` | layer (chain の 1 要素) |
| `q` | quantifier |
| `π` | bracket predicate |
| `w` | where 式 (Bool 値) |
| `e` | arith 式 (Int 値) |
| `c` | capture clause |
| `f` | field reference |
| `v` | リテラル値 |
| `op_c` | 比較演算子 |
| `op_a` | 算術演算子 |
| `p` | protocol 名 (vocab で declare) |
| `ℓ` | label |

### 11.2 inductive 定義

```
F  ::= ⟨L̄, w?, c̄⟩                                         filter

L  ::= proto(p, ℓ?, q, π̄)                                  単一 protocol layer
     | alt(L̄)                                              alternation (同サイズ)

q  ::= 1 | ? | + | * | {n,m}                               quantifier (n,m ∈ ℕ)

π  ::= cmp(f, op_c, v)                                     bracket cmp predicate
     | in(f, v̄)                                            v̄ ∈ Int_lit* (F7、整数 alternatives のみ)
     (`has` は §6 bitwise `&` で superseded — F6/F8 参照)

w  ::= or(w, w) | and(w, w) | not(w)
     | atom_arith(e, op_c, e)                              算術 cmp
     | atom_lit_cmp(f, op_c, v_net)                        ⨯ 順序対称: literal は LHS / RHS どちら可
     | atom_action(a)                                      action == XDP_*
     | atom_quant(κ, w)                                    κ ∈ {any, all}
     | atom_bool_lit(b)                                    b ∈ {true, false}
     | atom_bool_exists(f_aux)                             aux 抽出済みか
     | atom_bool_eq(w, op_eq, w)                           Bool == Bool / != Bool

e  ::= const(n)                                            n ∈ Z, untyped (narrow in context)
     | field(f)                                            FieldRef
     | binop(op_a, e, e)

c  ::= cap(spec, w?)                                       spec ::= all | headers | headers+N | label+N | proto+N | absolute(N) | layer-target | fields(f̄)

op_c ::= == | != | < | ≤ | > | ≥
op_a ::= + | − | * | / | % | & | \| | ^ | << | >>
op_eq ::= == | !=

f  ::= ident                                               primary field
     | ident.ident                                         <aux>.<field> or @<label>.<field>
     | ident[idx].ident                                    aux stack static index
     | ident[f].ident                                      aux stack dynamic index (parent field)
     | ident.options.IDENT.ident                           option lookup
     | ident.exists                                        aux extract bool

v  ::= int_lit(n)                                          n ∈ [−2⁶³, 2⁶⁴)
     | range_lit(lo, hi)                                   N..M, predicate-only (codegen staged)
     | ipv4_lit | ipv6_lit | mac_lit                       fixed-width Int<32> / Int<128> / Int<48>
     | cidr_lit(af, prefix)                                af ∈ {4, 6}
     | bool_lit(b)
     | action_lit(a)                                       a ∈ caps.Lang.Action ∪ XDP_*
     | ident_lit(name)                                     bare identifier (action keyword carrier; resolver narrows)
     | string_lit(s)                                       MVP-unsupported, parser-only

a  ::= XDP_PASS | XDP_DROP | XDP_TX | XDP_REDIRECT | XDP_ABORTED  (host-supplied)
```

`L̄` 等の overline は 0 個以上の繰り返しを表します。`?` は optional を表します。

capture spec 対応表 (concrete syntax → AST `CaptureKind`) は次のとおりです。

| spec 形 | AST kind | 備考 |
|---|---|---|
| `all` | `CapAll` | scratch buffer 全部 |
| `headers` | `CapHeaders` | chain 末尾までの header 累積 |
| `headers+N` | `CapHeadersPlus` | 上記 + N byte |
| `label+N` / `proto+N` / `layer-target` | `CapToLayer` (`Extra=N`) | 対象 layer まで + N byte |
| `absolute(N)` | `CapAbsolute` | chain 構造に依存しない静的 N byte |
| `fields(f̄)` | `CapFields` | 個別 field 列挙、MVP-unsupported |

### 11.3 環境 Γ

型付けと意味論で参照する環境は次のとおりです。

```
Γ = ⟨V, Λ, Σ, Caps⟩

V    : Vocabulary           — proto 名 → ProtocolSpec (vocab で declare された field 幅・aux header 構造)
Λ    : Label  → LayerInst   — 解決済 label-to-layer binding
Σ    : Stack  → AuxSpec     — aux header stack の declared 形 (capacity 等)
Caps : Action → Int<32>     — host が許容する action keyset
```

resolver は構文木 + Γ を入力に取り、抽象構文の subset である IR と型情報を出力します。

## 12. 型付け規則 (Typing Judgments)

判断の形式は `Γ ⊢ e : τ` で、環境 Γ のもとで e の型が τ であることを表します。

### 12.1 値・式

```
[T-IntLit]                                  [T-FieldPrim]
v ∈ [−2⁶³, 2⁶⁴)                            f は protocol p の N-bit primary field
─────────────────                          ─────────────────────────────────────
Γ ⊢ const(v) : Int<·>                      Γ ⊢ field(f) : Int<N>

(untyped — context 文脈で N を決定)


[T-FieldAux]                                [T-FieldStackStatic]
f は aux header h の N-bit field           f は stack s の i番目 entry の N-bit field
h ∈ p の aux extract、p ∈ chain            i ∈ [0, capacity(s))
────────────────────────────────────       ─────────────────────────────────────
Γ ⊢ field(p.h.f) : Int<N>                  Γ ⊢ field(p.s[i].f) : Int<N>


[T-IPv4Lit]   [T-IPv6Lit]   [T-MACLit]    [T-CIDR4Lit]               [T-CIDR6Lit]
ipv4_lit       ipv6_lit       mac_lit      cidr_lit(4, k)             cidr_lit(6, k)
─────────────  ─────────────  ──────────   ─────────────────          ─────────────────
: Int<32>      : Int<128>     : Int<48>    : CIDR4                    : CIDR6


[T-BoolLit]                       [T-ActionLit]
b ∈ {true, false}                 a ∈ Caps
─────────────────                ──────────────
Γ ⊢ bool_lit(b) : Bool           Γ ⊢ action_lit(a) : Action
```

### 12.2 算術

```
[T-ArithBin]
Γ ⊢ e₁ : Int<N>     Γ ⊢ e₂ : Int<M>
op_a ∈ {+, −, *, /, %, &, |, ^, <<, >>}
op_a = / または % のとき e₂ ≠ const(0)             ; 静的 div-zero reject (§6.1)
──────────────────────────────────────────────
Γ ⊢ binop(op_a, e₁, e₂) : Int<max(N, M)>           ; mod 2^max wrap (bitwise / shift も同じ結果型)
```

bitwise / shift 演算 (`&`, `|`, `^`, `<<`, `>>`) も算術と同じ widening / wrap 規則に従います。`<<` / `>>` の RHS は概念的にスカラーの shift 量であって、型計算上は他の二項演算と同じ扱いですが、§6.1 末尾のとおり実用上は static literal を推奨します。

literal narrow では、`Γ ⊢ e₁ : Int<·>` のとき、cmp 相手 field の幅か算術 binop の他方の幅という surrounding context から N を決定し、fit-check (§7) を通します。

### 12.3 比較

```
[T-CmpEq-Int]
Γ ⊢ e₁ : Int<N>     Γ ⊢ e₂ : Int<M>     op_c ∈ {==, !=}
─────────────────────────────────────────────────────
Γ ⊢ cmp(e₁, op_c, e₂) : Bool                                   ; widening to Int<max(N,M)>


[T-CmpOrd-Int]
Γ ⊢ e₁ : Int<N>     Γ ⊢ e₂ : Int<M>     op_c ∈ {<, ≤, >, ≥}
─────────────────────────────────────────────────────
Γ ⊢ cmp(e₁, op_c, e₂) : Bool                                   ; codegen max(N,M) ≤ 128 (F3 で bracket / where-arith 両方)


[T-CmpCIDR4]                                  [T-CmpCIDR6]
Γ ⊢ e : Int<32>    op_c ∈ {==, !=}            Γ ⊢ e : Int<128>    op_c ∈ {==, !=}
──────────────────────────────────             ──────────────────────────────────
Γ ⊢ cmp(e, op_c, cidr_lit(4,k)) : Bool        Γ ⊢ cmp(e, op_c, cidr_lit(6,k)) : Bool

(対称: literal が LHS でも RHS でも同 type、§6.2)


[T-CmpAction]
Γ ⊢ a : Action     op_c ∈ {==, !=}
─────────────────────────────────
Γ ⊢ cmp(action_keyword, op_c, a) : Bool
```

`CIDR/Action/Bool` に対する順序付き cmp は rule が存在しないため、型エラーになります。

### 12.4 Bool atom と論理結合

```
[T-Where-Bool-Decay]
Γ ⊢ e : Int<N>
─────────────────────────────────                  ; "Bool 文脈" で Int<N> が現れたら != 0 として coerce
Γ ⊢ atom_arith(e, !=, const(0)) : Bool


[T-Where-BoolLit]                  [T-Where-Exists]
b ∈ {true, false}                  f_aux は aux ref (`<proto>.<aux>` shape)
──────────────────                ─────────────────────────────────────
Γ ⊢ atom_bool_lit(b) : Bool       Γ ⊢ atom_bool_exists(f_aux) : Bool


[T-Where-BoolEq]
Γ ⊢ w₁ : Bool     Γ ⊢ w₂ : Bool     op_eq ∈ {==, !=}
─────────────────────────────────────────────────
Γ ⊢ atom_bool_eq(w₁, op_eq, w₂) : Bool


[T-And] [T-Or]                          [T-Not]
Γ ⊢ w₁ : Bool    Γ ⊢ w₂ : Bool          Γ ⊢ w : Bool
────────────────────────────────       ─────────────────
Γ ⊢ and(w₁, w₂) : Bool                 Γ ⊢ not(w) : Bool
Γ ⊢ or(w₁, w₂) : Bool


[T-Quant]
Γ, x : aux-stack(s) ⊢ w : Bool         w 内で stack s への index-less 参照が exactly 1 個
κ ∈ {any, all}                         (= iteration variable)
──────────────────────────────────
Γ ⊢ atom_quant(κ, w) : Bool
```

### 12.5 Filter 全体

```
[T-Layer]
proto(p, ℓ?, q, π̄):
  p ∈ V
  q が許容される文脈 (chain の頭 + parser machine による extract 可能性)
  ∀ π ∈ π̄. Γ ⊢ π : Predicate-of-p
─────────────────────────────────────────
Γ ⊢ proto(p, ℓ?, q, π̄) : LayerOK


[T-LayerAlt]
∀ L ∈ L̄. Γ ⊢ L : LayerOK
∀ L, L' ∈ L̄. byte_size(L) = byte_size(L')        (uniform-size 制約)
────────────────────────────────────────────────
Γ ⊢ alt(L̄) : LayerOK


[T-Filter]
Γ ⊢ L̄ : LayerOK*
Γ ⊢ w? : Bool     (w が在る場合)
∀ c ∈ c̄. Γ ⊢ c : CaptureOK
─────────────────────────────────────────
Γ ⊢ ⟨L̄, w?, c̄⟩ : FilterOK
```

## 13. 操作的意味論 (Operational Semantics)

big-step (`⇓`) 形式で filter 評価を定義します。1 packet ごとに `accept` / `reject` を判定します。

### 13.1 状態と判断

```
σ = ⟨π, α, Λ⟩
  π : ℕ                                       cursor (バイト offset、初期 0)
  α : (LayerInst × AuxName) ⇀ AuxView         aux 抽出記録 (extract 済 aux のオフセット + bytes)
  Λ : Label → LayerInst                       label-to-instance binding (chain 解決中に拡張)

P : Packet                                    bytes (immutable)

判断:
  ⟨L̄, σ⟩ ⇓_P σ' ✓                            chain 全体が成功、終状態 σ'
  ⟨L̄, σ⟩ ⇓_P ✗                                 chain どこかで失敗
  ⟨w, σ⟩ ⇓_P b                                where 式は b ∈ Bool に評価
  ⟨e, σ⟩ ⇓_P n                                arith 式は n ∈ Int に評価
  ⟨F, P⟩ ⇓ accept(α, Λ, captures) | reject     filter 全体の最終判断
```

### 13.2 Filter 全体

```
[E-Filter-Accept]
⟨L̄, ⟨0, ∅, ∅⟩⟩ ⇓_P ⟨π', α', Λ'⟩ ✓
w が空、または ⟨w, ⟨π', α', Λ'⟩⟩ ⇓_P true
captures = eval-captures(c̄, ⟨π', α', Λ'⟩, P)
─────────────────────────────────────────────
⟨⟨L̄, w?, c̄⟩, P⟩ ⇓ accept(α', Λ', captures)


[E-Filter-Reject-Chain]                        [E-Filter-Reject-Where]
⟨L̄, ⟨0, ∅, ∅⟩⟩ ⇓_P ✗                          chain は ✓ だが ⟨w, σ⟩ ⇓_P false
─────────────────                              ────────────────────────────
⟨F, P⟩ ⇓ reject                                ⟨F, P⟩ ⇓ reject
```

### 13.3 Layer chain

```
[E-Chain-Empty]
─────────────────
⟨ε, σ⟩ ⇓_P σ ✓


[E-Chain-Cons]
⟨L, σ⟩ ⇓_P σ' ✓        ⟨L̄, σ'⟩ ⇓_P σ'' ✓
────────────────────────────────────────────
⟨L · L̄, σ⟩ ⇓_P σ'' ✓


[E-Chain-Fail]
⟨L, σ⟩ ⇓_P ✗
─────────────────
⟨L · L̄, σ⟩ ⇓_P ✗
```

### 13.4 単一 layer (proto, q = 1)

```
[E-Layer-Proto-1]
L = proto(p, ℓ?, 1, π̄)
π + |p_header| ≤ |P|
parent_dispatch(p, ⟨π, α, Λ⟩, P) = ok          ; 親 layer の dispatch const から p を導出可
inst = layer-instance-of(p, π)
α' = aux-extract(p, π, P, α)                  ; §14 parser machine で aux 抽出
π' = π + total_bytes(p, P, π)                 ; primary header + extracted aux のサイズ合計
Λ' = Λ ⊕ {ℓ ↦ inst}                           ; label が在れば bind
∀ ρ ∈ π̄. ⟨ρ, ⟨π', α', Λ'⟩⟩ ⇓_P true           ; bracket predicate がすべて成立
─────────────────────────────────────────────
⟨L, ⟨π, α, Λ⟩⟩ ⇓_P ⟨π', α', Λ'⟩ ✓


[E-Layer-Proto-1-Fail-Bounds]                 [E-Layer-Proto-1-Fail-Disp]
π + |p_header| > |P|                          parent_dispatch(p, σ, P) = mismatch
─────────────────                             ─────────────────────────────────
⟨L, σ⟩ ⇓_P ✗                                  ⟨L, σ⟩ ⇓_P ✗

[E-Layer-Proto-1-Fail-Pred]
∃ ρ ∈ π̄. ⟨ρ, σ'⟩ ⇓_P false
─────────────────────────────
⟨L, σ⟩ ⇓_P ✗
```

### 13.5 Quantifier

quantifier `q` に対して、`L(q)` の reduction を q-iteration が成功したかどうかで定義します。`L(1)` は §13.4 のとおりです。それ以外は反復 + 上下限の制約で定義します。

```
[E-Quant-Optional]                            ; q = ?
proto(p, ?, π̄) は最大 1 回:
  case A:  ⟨L(1), σ⟩ ⇓_P σ' ✓                ⇒  ⟨L(?), σ⟩ ⇓_P σ' ✓
  case B:  parent_dispatch(p, σ, P) = miss   ⇒  ⟨L(?), σ⟩ ⇓_P σ ✓        ; skip


[E-Quant-Range-Step {n,m}]                    ; q = {n,m},  n ≤ m
σ_0 = σ
∀ i ∈ [0, k).  ⟨L(1), σ_i⟩ ⇓_P σ_{i+1} ✓
i = k で extract 失敗 (parent_dispatch miss / bounds 越え) または k = m で停止
n ≤ k ≤ m
─────────────────────────────────────────────
⟨L({n,m}), σ⟩ ⇓_P σ_k ✓


[E-Quant-Range-Fail {n,m}]
上記の k < n
─────────────────
⟨L({n,m}), σ⟩ ⇓_P ✗


[E-Quant-Plus]    ≡  L({1, m_chain})            ; m_chain は chain bound 由来の上限
[E-Quant-Star]    ≡  L({0, m_chain})
```

ここで `m_chain` は、vocab + chain 全体形の静的 chain 解析から導かれる iteration 上限です。実装は `pkg/kunai/codegen/` の `chainCap` 計算で同等です。

実装対応としては、`+` / `*` / `{n,m>4}` は `pkg/kunai/codegen/loop_*.go` で `bpf_loop` + bpf2bpf callback として emit し、`{n,m≤4}` は静的に unroll します。

### 13.6 Capture 評価

`eval-captures` は層解決後の chain 状態 ⟨π', α', Λ'⟩ から、各 capture clause を per-clause なバイト範囲に解決します。

```
captures : list of (offset_start, offset_end, view)
  view ⊆ P[offset_start..offset_end]

eval-captures(c̄, σ, P) = [eval-cap(c, σ, P) | c ∈ c̄, gate(c, σ) = true]

gate(cap(spec, ε),  σ)         = true
gate(cap(spec, w),  σ)         = ⟨w, σ⟩ ⇓_P true             ; per-capture where 句

eval-cap(cap(all, _), σ, P)             = (0, |P|, P)
eval-cap(cap(headers, _), σ, P)         = (0, π_now, P[..π_now])              ; π_now = chain 終了時の cursor
eval-cap(cap(headers+N, _), σ, P)       = (0, min(π_now + N, |P|), …)
eval-cap(cap(label+N, _), σ, P)         = (off(Λ[label]), min(off(...) + |label_layer| + N, |P|), …)
eval-cap(cap(proto+N, _), σ, P)         = (off(layer_of(proto)), …)
eval-cap(cap(absolute(N), _), σ, P)     = (0, min(N, |P|), …)
eval-cap(cap(layer-target,_), σ, P)     = layer-instance のバイト範囲
```

実装対応としては、`pkg/kunai/codegen/capture.go` が `eval-captures` を BPF instruction に展開し、perf event に view を載せます。

### 13.7 Bracket predicate

```
[E-Pred-Cmp]
⟨field(f), σ⟩ ⇓_P n_f
v_n = lift(v) : Int<N>                       ; v が int_lit / ipv4_lit / ... の場合の数値化
op_c(n_f, v_n) = b
─────────────────────────────────────────────
⟨cmp(f, op_c, v), σ⟩ ⇓_P b
```

### 13.8 Where 式

```
[E-W-And]                                     [E-W-Or]
⟨w₁, σ⟩ ⇓_P b₁    ⟨w₂, σ⟩ ⇓_P b₂              ⟨w₁, σ⟩ ⇓_P b₁    ⟨w₂, σ⟩ ⇓_P b₂
b = b₁ ∧ b₂                                   b = b₁ ∨ b₂
─────────────────────────                     ─────────────────────────
⟨and(w₁, w₂), σ⟩ ⇓_P b                       ⟨or(w₁, w₂), σ⟩ ⇓_P b


[E-W-Not]                                     [E-W-Arith]
⟨w, σ⟩ ⇓_P b                                  ⟨e₁, σ⟩ ⇓_P n₁    ⟨e₂, σ⟩ ⇓_P n₂
─────────────────                             op_c(n₁, n₂) = b
⟨not(w), σ⟩ ⇓_P ¬b                            ────────────────────────────────
                                              ⟨atom_arith(e₁, op_c, e₂), σ⟩ ⇓_P b


[E-W-LitCmp]                                  [E-W-Action]
⟨field(f), σ⟩ ⇓_P n                          a_actual = host-action-of(σ)        ; fexit のみ
v_n = lift(v_net)                            op_c(a_actual, a) = b
op_c(n, v_n) = b                             ────────────────────────────────
─────────────────────────                    ⟨atom_action(action == a), σ⟩ ⇓_P b
⟨atom_lit_cmp(f, op_c, v_net), σ⟩ ⇓_P b


[E-W-BoolLit]                                 [E-W-Exists]
                                              (LayerInst × AuxName) ∈ dom(α)
─────────────────────────────                 ─────────────────────────
⟨atom_bool_lit(b), σ⟩ ⇓_P b                   ⟨atom_bool_exists(f_aux), σ⟩ ⇓_P true

                                              (LayerInst × AuxName) ∉ dom(α)
                                              ─────────────────────────
                                              ⟨atom_bool_exists(f_aux), σ⟩ ⇓_P false


[E-W-BoolEq-iff]                              [E-W-BoolEq-xor]
⟨w₁, σ⟩ ⇓_P b₁    ⟨w₂, σ⟩ ⇓_P b₂              ⟨w₁, σ⟩ ⇓_P b₁    ⟨w₂, σ⟩ ⇓_P b₂
─────────────────────────────                 ─────────────────────────────
⟨atom_bool_eq(w₁, ==, w₂), σ⟩ ⇓_P (b₁ ↔ b₂)   ⟨atom_bool_eq(w₁, !=, w₂), σ⟩ ⇓_P (b₁ ⊕ b₂)


[E-W-Any]                                     [E-W-All]
∃ i ∈ [0, count(stack(σ))).                  ∀ i ∈ [0, count(stack(σ))).
  ⟨w[x ↦ stack[i]], σ⟩ ⇓_P true                ⟨w[x ↦ stack[i]], σ⟩ ⇓_P true
─────────────────────────────                ─────────────────────────────
⟨any(w), σ⟩ ⇓_P true                         ⟨all(w), σ⟩ ⇓_P true
                                             
(空 stack のとき: any ⇓ false, all ⇓ true)
```

### 13.9 算術評価

```
[E-A-Const]                          [E-A-Field]
                                     load(f, σ, P) = n                   ; aux 抽出済を含む field load
─────────────────────                ───────────────────────
⟨const(n), σ⟩ ⇓_P n                  ⟨field(f), σ⟩ ⇓_P n


[E-A-BinOp]
⟨e₁, σ⟩ ⇓_P n₁    ⟨e₂, σ⟩ ⇓_P n₂
op_a ∈ {+, −, *}: r = (n₁ op_a n₂) mod 2^max(width(e₁), width(e₂))
op_a = /:  r = n₂ ≠ 0 ? ⌊n₁ / n₂⌋ : 0                                    ; 動的 0 → 0 (BPF 既定)
op_a = %:  r = n₂ ≠ 0 ? n₁ mod n₂ : 0
──────────────────────────────────────────────
⟨binop(op_a, e₁, e₂), σ⟩ ⇓_P r
```

## 14. p4lite parser machine の意味論

aux header の extract semantics を定義します。`pkg/kunai/protocols/*.p4` の `parser` block を small-step machine として解釈します。

### 14.1 状態

```
ψ = ⟨s, π, α⟩
  s : StateName        現在の parser state (`start`、ユーザ定義状態、`accept`、`reject`)
  π : ℕ                cursor (proto layer 内の相対 offset)
  α : AuxView record   抽出済 aux の蓄積 (拡張中)
```

`accept` / `reject` は terminal です。

### 14.2 step 規則

```
[P-Extract]
state s の statement: extract(h)
π + |h| ≤ |proto bytes|
view = ⟨π, P[π..π+|h|]⟩
α' = α ⊕ {h ↦ view}
π' = π + |h|
─────────────────────────────────────
⟨s_extract, π, α⟩ → ⟨s_next, π', α'⟩


[P-Extract-Stack]
state s の statement: extract(stack.next)
|stack| < capacity(stack)
view = ⟨π, P[π..π+|h|]⟩
α' = α ⊕ {stack[k] ↦ view}        ; k = current count
π' = π + |h|
─────────────────────────────────────
⟨s, π, α⟩ → ⟨s_loop_or_next, π', α'⟩

[P-Extract-Stack-Full]
|stack| = capacity(stack)
─────────────────────────
⟨s, π, α⟩ → ⟨reject⟩


[P-Trans-Direct]
state s の transition: transition s'
─────────────────────
⟨s, π, α⟩ → ⟨s', π, α⟩


[P-Trans-Select]
state s の transition: transition select(k) { v_i: s_i; default: s_d }
k_value = eval-key(k, α)                ; §14.3
∃ i. v_i = k_value
─────────────────────────
⟨s, π, α⟩ → ⟨s_i, π, α⟩

(マッチしないとき: ⟨s_d, π, α⟩;  default 句が不在で全 v_i miss なら → ⟨reject⟩)


[P-Trans-Accept]                       [P-Trans-Reject]
state s の transition: accept           state s の transition: reject
─────────────────────                   ─────────────────────
⟨s, π, α⟩ → ⟨accept, π, α⟩              ⟨s, π, α⟩ → ⟨reject⟩
```

### 14.3 select-key 評価

`transition select(k) { ... }` の鍵 `k` は p4lite の制限 expression で、次の最大 2 種です。

```
k ::= field_name                      ; 直前に extract した primary header の field
    | field_name & const              ; bit-mask 適用 (例: gtp.flags & 0xE0)

eval-key(k, α) =
  case field_name:
    α[current_header] = ⟨_, bytes⟩
    return interpret_field(bytes, field_name)        ; ネットワークバイトオーダで unsigned int
  case field_name & const:
    return eval-key(field_name, α) AND const         ; ビット単位 AND
```

`current_header` は extract block 内で直前に `extract()` した header に bound されています。p4lite parser は extract と transition の順序を強制するため、select-key は常にちょうど抽出された header の field を指します。

実装対応としては、`pkg/kunai/vocab/p4lite/parser.go` が select expression を AST に格納し、`pkg/kunai/codegen/parser_select.go` がこれを `R3 = mem[π + field_offset]` + 必要なら `R3 &= const` に展開します。

### 14.4 layer 全体での aux 抽出

`[E-Layer-Proto-1]` における `aux-extract(p, π, P, α)` は、`start → accept` (または `reject`) までの transitive closure として次のように定義されます。

```
aux-extract(p, π, P, α) = α' such that ⟨start, 0, α⟩ →* ⟨accept, π_final, α'⟩  (proto bytes 内 relative)
                        = ⊥ if →* ⟨reject⟩
```

`⊥` (reject) は親 layer の `[E-Layer-Proto-1-Fail-Pred]` 系統の失敗にマップされます。

## 15. 実装との対応 (Soundness sketch)

### 15.1 各実装ステージ ↔ 形式仕様

| 実装ステージ | パッケージ | 対応する formal section |
|---|---|---|
| 具象構文 → AST | `pkg/kunai/parser/`、`pkg/kunai/lexer/` | §11 抽象構文 |
| AST → IR + 型検査 | `pkg/kunai/resolve/` | §12 型付け規則 |
| IR → eBPF instructions | `pkg/kunai/codegen/` | §13、§14 操作的意味論 |
| vocab parser block 解釈 | `pkg/kunai/vocab/p4lite/` | §14 parser machine |

### 15.2 Soundness conjecture (codegen の正当性)

Compile が成功した filter F は任意の packet P に対して spec の意味論と同じ判断を返す、という主張を次のように定式化します。

```
∀ F, P.  Γ ⊢ F : FilterOK   ∧   kunai.Compile(F) = (insns, _, nil)
       ⇒ run(insns, P) ↓ accept(α, Λ, captures)  iff  ⟨F, P⟩ ⇓ accept(α, Λ, captures)
       ⇒ run(insns, P) ↓ reject                  iff  ⟨F, P⟩ ⇓ reject
```

ここで `run(insns, P)` は、kernel BPF verifier に通った `insns` を XDP として実行した結果です。

このうち実装が保証する範囲は次のとおりです。

1. Type soundness (resolver) は、`Γ ⊢ F : FilterOK` ⇒ resolver は IR を生成してエラーを返さない、という保証です。実装としては `resolve/typing.go` で fit-check / div-zero を含むすべての §12 rule を網羅的に走らせます。現状は完全実装です。不足ケースは型エラーとして reject されるべきで、見逃しがあれば spec バグまたは実装バグです。
2. Codegen soundness (BPF instructions) は、well-typed IR ⇒ 等価な命令列、という保証です。実装は `codegen/` 配下のテーブル駆動 emit です。現状は §9.1 のとおり Int<128> 系の一部演算 (乗算 / 除算 / 剰余) が未実装または廃止で、型は OK でも `ErrNotImplemented` になり得ます。Soundness は emit に成功した命令列について成立します。
3. Verifier 通過性は、emit された命令列が kernel BPF verifier に通る、という性質です。形式的保証はありませんが、`internal/program/load_dsl_test.go` を 5 kernel matrix で実行する回帰 test で経験的に検証しています。

完全な lemma-style 証明は将来課題です。本書の主目的は、証明できる土台を spec として固定することです。

### 15.3 Proof sketch (各 sub-claim の方針)

完全な機械証明は、Coq / Agda などの形式メタ言語の選定も含めて将来課題ですが、人間レベルの sketch を共有しておきます。

#### Type soundness (resolver、構造帰納)

resolver は AST を root から再帰的に walk します。各 §12 rule に対応する resolver の関数は次のとおりです。

| §12 rule | resolver 実装 |
|---|---|
| T-FieldPrim / T-FieldAux | `resolve/where.go::resolveQualifiedField` |
| T-IntLit + narrow | `resolve/typing.go::checkArithExpr` |
| T-CmpEq-Int / T-CmpOrd-Int | `resolve/typing.go::checkArithCondition` (経由で `arithCmpTargetBits`) |
| T-CmpCIDR4 / T-CmpCIDR6 | `resolve/typing.go::checkLiteralWidthShape` (旧名: `validateLiteralFieldType`) |
| T-Where-Bool-Decay | parser で WAtomArith に書き換え (parseCmpOrBoolAtom) |
| T-And / T-Or / T-Not | `resolve/where.go::resolveWhere` の `WAnd / WOr / WNot` 分岐 |
| T-Quant | `resolve/where.go::findQuantTarget` |

帰納仮説は、各部分式が well-typed なら resolver は対応する IR ノードを返してエラーを出さない、というものです。

帰納ステップは、各 rule で前提の typing が成立 ⇒ resolver の関数は前提の構造を expect ⇒ IR を返すか既知のエラーパスに入る、という流れです。

D8 一元化 (commit `0f353cd1`) と Bool ordered cmp resolver reject (commit `d87caff9`) で、§12 の rule は resolver 側で全網羅されました。残るギャップは、構造的に IR に出てこない、parser 側で先に reject される経路のみです。§15.4 punch list では Type soundness 行を ✅ 完了に更新済みです。

#### Codegen soundness (operational simulation)

codegen は IR ノードを `asm.Instructions` に展開します。サブクレームは次のとおりです。

> 各 IR ノード `n` について、§13 で定義された `⇓` の reduction が `gen(n, ...)` の emit する命令列を実行した場合の結果と一致します。

これは operational simulation lemma と呼ぶ形で、次のように表せます。

```
∀ n, σ.  ⟨n, σ⟩ ⇓_P b   ⟹   ∃ σ_bpf'.  bpf-step*(insns(n), σ_bpf(σ)) = σ_bpf'(σ, b)
```

ここで `σ_bpf` は packet σ を BPF レジスタ + stack 状態に encode する操作です。詳細は `pkg/kunai/codegen/codegen.go` の package doc に書かれた ABI 契約 (R0=data, R1=data_end, KunaiStackTop など) を参照してください。

代表的なサブ lemma は次のとおりです。

- arith binop の simulation では、`binop(+, e₁, e₂) ⇓ n₁ + n₂ mod 2^w` ⟺ `gen(...)` が emit する `add R3, R5` (BPF 64bit add) の結果が一致します。
- cmp simulation では、`cmp(e, ==, v) ⇓ b` ⟺ emit された `JEq R3, imm, label` の routing (jump 先 == fallthrough のとき b=true) が一致します。
- chain step simulation では、`[E-Layer-Proto-1]` の `π' = π + total_bytes` ⟺ emit される `add R4, |hdr|` (`R4` が cursor) が対応します。

これら全部を機械的に証明したい場合は、BPF 命令を非解釈関数で encode する SMT で行う手がありますが、本プロジェクトでは verifier 通過 + dsltest による packet test という経験的検証に依存します。

#### Verifier acceptance (帰納的構造)

BPF verifier の通過性は kernel に委ねられますが、kunai は次の構造的制約を遵守します。

1. Stack 使用量は KunaiStackTop 以下に収めます。これは `pkg/kunai/codegen/codegen.go` のパッケージ doc で固定しています。
2. Loop bound について、静的 unroll は constant で、`bpf_loop` には引数の上限を const として渡します。
3. Pointer arithmetic については、`R0 ≤ R4 ≤ R1` を毎 step 維持します。chain emit が bounds check を入れます。
4. Register lifetime については、caller-saved (R1-R5) の保持は relevant block 内のみです。

これらを保ちつつ insns 列が verifier に通れば、insns が実行できるという operational soundness の前提条件は満たされます。

### 15.4 残タスク

| 項目 | 状態 |
|---|---|
| Type soundness の §12 rule 全網羅 (D8 一元化) | ✅ 完了 (resolve/typing.go + typing_errors.go に集約、ordered cmp on Bool/network literal の resolver-side defense in depth も完備) |
| Codegen soundness の lemma-style 証明 | 未着手 (sketch のみ) |
| Verifier acceptance の formal property | 未着手 (経験的検証のみ) |
| Mechanical proof framework 選定 | 未着手 |

#### 既知の verifier corner case

経験的検証で発見済みの、型 OK / Compile 成功 / kernel verifier reject となるケースは次のとおりです。

- `where false` のケースは ✅ 解決済みで、実装は `codegen.go::isConstantFalseCondition` です。filter top-level の where が constant-false に評価されるとき、Gen は layer chain emit を skip して、minimal always-reject program (R2=0 → filter_result) のみ返します。これにより、chain bounds check の side effect が unreachable な accept tail と組み合わさって verifier 側 liveness 検査に引っかかる事態を回避します。dslEntryExprs にも復帰済みです。
