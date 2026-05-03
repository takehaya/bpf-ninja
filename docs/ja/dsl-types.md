# DSL 仕様: 構文・型・意味論

DSL filter 式の **抽象構文 / 静的型付け / 操作的意味論** を一冊にまとめた言語仕様書。本ドキュメントは仕様 (= resolver / codegen が実装すべきルール集) であり、現実装の挙動描写ではない。実装ステージング (どこまで現 codegen が対応するか) は §9 を参照。

`dsl-grammar.md` が「具象構文 (parser が食う表記)」、本書が「**抽象構文 + 型 + 意味**」、`dsl-internals.md` が「実装アーキテクチャ + パッケージツアー + codegen ABI + vocab 著者ガイド」。3 者の関係は概ね EBNF (concrete) → AST (abstract syntax) → 型付け規則 → 操作的意味論。

---

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

---

## 1. はじめに

### 1.1 動機

DSL は parser / resolver / codegen の 3 段で構成されるが、resolver は従来「フィールドが declare 済みか」「dispatch が解決可能か」など **構造的検査**しか行っておらず、**値の型と幅**に関する検査は穴が多かった:

- bracket predicate `[dport == 99999]` は fit check 済 (16bit field に 99999 入らない → reject)
- where 算術 `tcp.dport > 99999` は **未検査** (暗黙ゼロ拡張で通っていた)
- `tcp.dport == ipv4.ttl` (16bit vs 8bit) のような **異幅 cmp** が無警告で通っていた
- `gtp.opt.exists + 1` のような **kind 違反** が arith に紛れ込みうる

本書はこの穴を塞ぐため、**全 expression に明示的な型と coercion ルール**を与える。実装は resolver で `static reject` を発火させる形。

### 1.2 スコープ

- **対象**: DSL filter 式の全構造 — layer chain / predicate / where / capture
- **対象外**: p4lite vocab 言語 (`.p4` ファイル) は別 type 系。本書は vocab で declare された field の bit 幅を入力として使う
- **対象** (Part II 追加後): 操作的意味論 (reduction / packet 上の評価規則) も §13 / §14 で形式化済

### 1.3 目的の優先順位

1. **誤用の早期検出**: typo / 異幅混在 / kind 違反を resolver で reject
2. **直感の保存**: tcpdump 風の式 (`tcp.dport == 443`) は今までどおり通る
3. **uniform な拡張性**: IPv4 / IPv6 / MAC を別 kind ではなく `Int<N>` に吸収して構造を単純化

---

## 2. 表記規約

| 記号 | 意味 |
|---|---|
| `e : τ` | 式 e は型 τ を持つ |
| `Γ ⊢ e : τ` | 環境 Γ (vocab + label table) のもとで e の型は τ |
| `τ₁ ⊓ τ₂` | 2 つの型の greatest common type (widening 結果) |
| `v ⤳ Int<N>` | 値 v が Int<N> に narrow される (fit check 付) |
| `Int<N>` | N bit unsigned integer 型 (1 ≤ N ≤ 128) |
| `2ⁿ` | 2 の n 乗 |

EBNF は `dsl-grammar.md` の表記をそのまま流用。

---

## 3. 型 τ

### 3.1 型の集合

```
τ ::= Int<N>          N ∈ {1, 2, ..., 128}
    | CIDR4
    | CIDR6
    | Bool
    | Action
```

各型の役割:

| 型 | 役割 | 由来 |
|---|---|---|
| `Int<N>` | 整数値全般 (フィールド値、リテラル narrow 後、算術結果) | vocab の `bit<N>` field 宣言 |
| `CIDR4` | IPv4 subnet (range として使用) | リテラル `<addr>/<prefix>` (AF=4) |
| `CIDR6` | IPv6 subnet | 同 (AF=6) |
| `Bool` | 真偽値 | cmp 結果 / `<aux>.exists` / quantifier 結果 / Bool literal |
| `Action` | XDP action 等の symbolic 値 | `XDP_DROP` 等の literal |

### 3.2 IPv4 / IPv6 / MAC は型ではなく shaped Int<N>

**IPv4 / IPv6 / MAC** は独立した型ではなく、**Int<N> の特定 width** として扱う:

| 概念 | 型 |
|---|---|
| IPv4 アドレス値 | `Int<32>` |
| IPv6 アドレス値 | `Int<128>` |
| MAC アドレス値 | `Int<48>` |

リテラル parser は `ValIPv4` / `ValIPv6` / `ValMAC` を識別するが、**型システム上は単なる Int<N>**。識別情報は診断 (エラーメッセージ) 用途にのみ使う。

これにより:

- `ipv4.dst < 10.0.0.10` のような ordered cmp が自然に書ける (Int<32> 同士)
- `eth.src + 1 == eth.dst` のような MAC 算術も書ける (Int<48> 同士)
- 「IPv4 とは Int<32>」「MAC とは Int<48>」と説明し直せて、type 系の sort 数が減る

### 3.3 Subtyping

**subtype 関係は持たない**。`Int<8> ⊑ Int<16>` のような暗黙ワイドニングは subtype ではなく **explicit な widening 演算** (§5) として表現する。これにより:

- 「異幅 cmp が暗黙に通る」事故を**意図的な widening** に置き換える
- 型推論が単純 (subtype 探索が要らない)
- 将来 explicit cast 構文 (`(bit<32>) tcp.dport` 等) を入れる余地を残す

### 3.4 Bit-slice

field の特定 bit 範囲を取り出す **bit-slice 構文**:

```
field[lo:hi]                    ; half-open bit range, lo inclusive / hi exclusive
                                ; bit 0 = network-order MSB (IETF 規約)
                                ; result type = Int<hi - lo>
```

例:

| 式 | 結果型 | 意味 |
|---|---|---|
| `ipv6.src[0:32]` | `Int<32>` | IPv6 アドレスの先頭 4 octets (= `/32` prefix を数値化) |
| `ipv6.src[96:128]` | `Int<32>` | 末尾 4 octets (IPv6 → IPv4 互換アドレス検査などに) |
| `ipv6.src[64:128]` | `Int<64>` | 下位半分 (subnet identifier + interface ID) |
| `ipv4.dst[0:8]` | `Int<8>` | IPv4 アドレスの最上位 octet (Class A の network 番号など) |

**結果幅と用途のマトリクス** (§9.1):

| 範囲 | cmp (`==`/`!=`) | arith binop / bitwise | non-aligned 端点 |
|---|---|---|---|
| **`≤ 64`** | ✅ single LDX | ✅ single register | ✅ codegen で `pow2 ≥ cover` LDX → bswap → shift+mask |
| **`(64, 128]`** | ✅ resolver desugar (LDX-aligned chunks の AND/OR-chain、例: `[0:96]` → `[0:64]` AND `[64:96]`) | ❌ single register に乗らないため未対応 | ❌ byte-aligned 端点必須 |

`!=` の chain は OR、`==` は AND。endpoint が 64bit 境界を跨ぐ場合は両端 byte-aligned が要件 (sub-byte 跨ぎ + 64+ bit は scope 外)。

**型ルール**:

```
[T-FieldSlice]
Γ ⊢ field(f) : Int<W>     0 ≤ lo < hi ≤ W
─────────────────────────────────────────
Γ ⊢ field(f)[lo:hi] : Int<hi - lo>
```

**意味論**:

```
⟨field(f)[lo:hi], σ⟩ ⇓_P n
  where n = (load(f, σ, P) の bit lo..hi-1 を host order で連結した値)
```

bracket predicate と where 算術の双方で使用可:

```
eth/ipv6[src[0:32]==0x20010db8]/tcp                        # bracket
where ipv6.src[64:128] == ipv6.dst[64:128]                  # where-arith
where (ipv6.src[0:32] & 0xff000000) != 0                    # arith / bitwise と組合せ
```

実装: `lexer/lexer.go` の TokColon、`parser/predicate.go::tryParseIndexExpr` の slice 分岐、`resolve/typing.go::detachTrailingSlice` + `attachSlice`、`codegen/codegen.go::applySliceToOffset`。

---

## 4. リテラル

### 4.1 整数リテラル

| 表記 | 例 |
|---|---|
| 10進 | `443`, `1024` |
| 16進 (`0x` prefix) | `0xff`, `0xc0a80101` |
| 負数 (`-` prefix) | `-1`, `-128` |

**parser-time 値域**: `[-2⁶³, 2⁶⁴)`。これを超える数値リテラルは **parser でエラー**。

`-1` のような負数は **2's complement で文脈型 `Int<N>` に narrow** される (例: `Int<16>` 文脈で `-1` ⤳ `0xffff`)。

### 4.2 IPv4 リテラル

```
ipv4 := octet '.' octet '.' octet '.' octet
octet := 0..255
```

例: `10.0.0.1`, `192.168.1.1`

**parser-time 制約**:

- 各 octet が 0..255 範囲内
- zero-prefix octet 拒否 (`010.0.0.1` は reject)
- trailing dot 拒否 (`10.0.0.1.` は reject)

**型**: `Int<32>` (詳細は §3.2)。

### 4.3 IPv6 リテラル

RFC 4291 形式に準拠:

```
ipv6 := full-form | shortened-form | ipv4-mapped-form
```

例: `fe80::1`, `2001:db8::1`, `::ffff:1.2.3.4`

**parser-time 制約**:

- RFC 4291 に準拠
- zone id (`%eth0`) 拒否 — packet bytes に乗らないため
- bracket form (`[fe80::1]`) 拒否 — URL 表記との混同を避ける

**型**: `Int<128>`。

### 4.4 MAC リテラル

```
mac := octet ':' octet ':' octet ':' octet ':' octet ':' octet   (hex)
```

例: `aa:bb:cc:dd:ee:ff`, `AA:BB:CC:DD:EE:FF`

**parser-time 制約**:

- colon 区切り 6 octet のみ
- 大文字小文字どちらも許容
- dash 区切り (`aa-bb-..`) と Cisco dot 形式 (`aabb.ccdd.eeff`) は **拒否** (確定)

**型**: `Int<48>`。

### 4.4.1 MAC 表記の単一化に関する決定事項

実用上 MAC アドレスは 3 つの慣習表記が流通する: colon (`aa:bb:cc:dd:ee:ff`、IEEE / ifconfig / ip-link)、dash (`aa-bb-cc-dd-ee-ff`、Windows / 一部 syslog)、Cisco dot (`aabb.ccdd.eeff`、Cisco IOS)。本書はこのうち **colon のみ** を受理する。理由:

1. **lexer の値モード曖昧性回避**: Cisco dot 形式は `aabb.ccdd.eeff` のように `.` を区切り文字に使う。一方、IPv4 リテラルも `.` 区切り (`10.0.0.1`)。同一トークン内で `.` を 2 用途に分けると classifier が `aabb.ccdd.eeff` と `10.0.0.1.5` (= 5 oct なので即 reject だが先読みコストが要る) を区別できず、正規表現ベースで解いてもエッジケースが残る。
2. **dash 形式は構造的に value-byte を使う**: `-` は値モードで負数 literal の prefix として既に役割を持つ (§4.1)。`-aa-bb-..` のような頭から `-` で始まる token を MAC として扱おうとすると負数判定と衝突する。
3. **canonical form の統一**: 1 つの形式に絞ることで filter 文字列を比較・キャッシュ・diff する処理が単純化される。
4. **必要なら IDE / wrapper レイヤで変換可能**: dash / dot 表記を colon に正規化するのは 1 行の置換なので、library 利用者の責務として外側に出す。

このため §4.4 の reject は最終決定であり、follow-up として再検討する予定はない。

### 4.5 CIDR リテラル

```
cidr4 := ipv4 '/' prefix4   (prefix4: 0..32)
cidr6 := ipv6 '/' prefix6   (prefix6: 0..128)
```

例: `10.0.0.0/24`, `fe80::/64`

**parser-time 制約**:

- prefix が AF ごとの範囲内 (`/0`〜`/32` or `/0`〜`/128`)
- **host bits 非ゼロは reject** (例: `10.0.0.5/24` は reject、`10.0.0.0/24` を要求)
  - エラーメッセージで誘導: `network would be 10.0.0.0/24` + `(suggestion: 10.0.0.5/32 for the single host)`
- `/0` (= 全アドレス match)、`/32` / `/128` (= host match) は OK

**型**: `CIDR4` / `CIDR6`。

### 4.6 Bool リテラル

```
bool-lit := 'true' | 'false'
```

**型**: `Bool`。

constant folding 可能 (`where true` ≡ `where` 省略、`where false` ≡ 全 reject)。

### 4.7 Action リテラル

upper-case ident:

```
action-lit := upper-case-ident
```

例: `XDP_DROP`, `XDP_PASS`, `XDP_TX`, `XDP_REDIRECT`, `XDP_ABORTED`

**resolver-time 制約**:

- `caps.Action` map に登録された ident のみ valid
- 登録外 ident (`XDP_FOO`) は resolver で reject

**型**: `Action`。

---

## 5. 暗黙変換と widening

リテラルや異幅整数の比較・演算で発火する **暗黙変換ルール**を定義する。

### 5.1 リテラルの principal-typing

整数リテラル `v` は parse 直後には **型を持たない値** として扱う。利用文脈で必要な型が決まったときに、その型に narrow される (= 値域チェック)。

具体的には:

| 文脈 | narrow 先 | 動作 |
|---|---|---|
| `Int<N>` field との cmp | `Int<N>` | `v` を Int<N> に narrow、fit check (§7) |
| `Int<N>` field との arith | `Int<N>` | 同上 |
| Bool 文脈 (`where v`) | `Bool` | `v != 0` として coerce (§5.4) |
| 単独 `where v` (literal-Bool fold) | `Bool` | `true` / `false` に fold |

**注意**: 「`UInt`」のような専用型を spec 上は導入しない。リテラルは値であって型ではない、と扱う (Go の untyped constant に近い設計)。

### 5.2 整数 widening (`Int<N>` × `Int<M>`)

二項演算 (cmp / arith) で異幅整数が出会ったとき:

```
Int<N> ⊓ Int<M> = Int<max(N, M)>           (zero-extension で短い方を拡張)
```

例:

- `tcp.dport (Int<16>) == ipv4.ttl (Int<8>)` → 両者を `Int<16>` に lift して比較 (上位バイトに 0)
- `eth.src (Int<48>) < 0xaabbccddeeff (literal)` → literal を `Int<48>` に narrow、ordered cmp を `Int<48>` で行う
- `ipv6.src (Int<128>) == ipv4.dst (Int<32>)` → `Int<128>` に lift (Int<32> を zero-extend)

**符号拡張は行わない** — DSL の整数は全て unsigned のため。

### 5.3 widening の適用範囲

widening は **比較演算の両 operand**、および **算術演算の operand 同士** で発火する。算術の結果型は `Int<max(N, M)>` (§6.1)。

### 5.4 `Int<N>` → `Bool` coercion (Bool 文脈)

「Bool が要求される文脈」で `Int<N>` 値が現れたとき、C 風の "non-zero check" として coerce する:

```
v ∈ Int<N> → (v != 0) ∈ Bool         (Bool 要求文脈で発火)
```

Bool 要求文脈とは:

- `where atom` (`where tcp.syn`)
- `not` の operand (`not tcp.syn`)
- `and` / `or` の operand (`tcp.syn and tcp.ack`)
- `any(...)` / `all(...)` の inner expression
- `Bool == Bool` / `Bool != Bool` の operand (片方が Bool のとき他方も Bool に coerce)

例:

| 式 | 解釈 |
|---|---|
| `where tcp.syn` | `tcp.syn != 0` (Int<1> → Bool) |
| `where ipv4.ttl` | `ipv4.ttl != 0` (実質 always true、tautology だが型 OK) |
| `where tcp.dport - 80` | `(tcp.dport - 80) != 0` ≡ `tcp.dport != 80` |
| `where 0` | `false` (literal-Bool fold) |
| `where 1` | `true` (literal-Bool fold) |

**逆方向 (Bool → Int) coercion は行わない**。`true + 1` のような書き方は型エラー。

### 5.5 明示 cast 構文

導入しない。将来的に必要になったら検討 (follow-up F2 として登録、§10)。

---

## 6. 演算

### 6.1 算術演算 (`+`, `-`, `*`, `/`, `%`, `&`, `|`, `^`, `<<`, `>>`)

**operand 制約**:

- 両 operand とも `Int<N>` (リテラル narrow 含む)
- `Bool`, `Action`, `CIDR4`, `CIDR6` は禁止 (型エラー)

**結果型**: `Int<max(N, M)>`、modulo `2^max(N, M)` (silent wrap)。

**precedence** (concrete syntax の binding 強さ):

| precedence | 演算子 |
|---|---|
| 高 | `*` `/` `%` `&` `<<` `>>` (mul-class) |
| 低 | `+` `-` `\|` `^` (add-class) |

bitwise op は通常の C と同様に `&` を mul-class、`|`/`^` を add-class に置く (`tcp.flags & 0x12 == 0x12` を `(tcp.flags & 0x12) == 0x12` と読む)。

例:

| 式 | 結果型 | 値 (例) |
|---|---|---|
| `tcp.dport + 1` | `Int<16>` mod 2¹⁶ | dport=65535 のとき結果 0 (wrap) |
| `tcp.dport + ipv4.ttl` | `Int<16>` (widen) | |
| `ipv6.src + 1` | `Int<128>` mod 2¹²⁸ | (`field op const` の codegen は実装、ただし verifier-load staged — §9) |
| `ipv4.total_length - 20` | `Int<16>` mod 2¹⁶ | total=10 のとき結果 65526 (wrap) |
| `tcp.window * 2` | `Int<16>` mod 2¹⁶ | overflow 黙ってラップ |
| `tcp.flags & 0x12` | `Int<9>` (TCP flags は 9 bit) | bitwise AND |
| `tcp.dport >> 4` | `Int<16>` | logical right shift |

**static `/0` `%0`**: RHS が literal `0` のとき **resolver で reject**。

**runtime `/0` `%0`**: BPF 既定の **結果 0** を意味論として codify。`tcp.dport / ipv4.ttl` で TTL=0 だったとき結果 0。

**shift 量の範囲**: `<<` / `>>` の RHS は `[0, 64)` 以内の static literal を推奨。範囲外は BPF 定義の masked shift 挙動に従う (静的 reject はしない)。

### 6.2 比較演算 (`==`, `!=`, `<`, `≤`, `>`, `≥`)

#### Typing matrix

| LHS | RHS | `==` `!=` | `<` `≤` `>` `≥` |
|---|---|---|---|
| `Int<N>` | `Int<M>` | ✅ widen to `Int<max(N,M)>` (codegen ≤128 — bracket は dual-LDX、where-arith は F3 ordered + F4 eq/ne) | ✅ 同左 |
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

すべての比較演算は **operand を入れ替えても等価**。例:

- `tcp.dport == 443` ≡ `443 == tcp.dport`
- `ipv4.dst == 10.0.0.0/24` ≡ `10.0.0.0/24 == ipv4.dst`
- `tcp.dport < 1024` ≡ `1024 > tcp.dport` (ordered cmp は op を反転)

parser は LHS / RHS どちらにも literal を許容する。

### 6.3 論理演算 (`not`, `and`, `or`)

operand は **`Bool` のみ** (Int<N> → Bool の coercion 経由で Int<N> が出てくることは可)。

```
not  : Bool → Bool
and  : Bool × Bool → Bool
or   : Bool × Bool → Bool
```

短絡評価あり (and の左 false で右スキップ、or の左 true で右スキップ)。

### 6.4 CIDR membership

```
== : Int<32> × CIDR4 → Bool       (Int<32> ∈ CIDR4)
== : Int<128> × CIDR6 → Bool      (Int<128> ∈ CIDR6)
!= : 同上の否定
```

**ordered cmp は不可** (§6.2 のとおり)。CIDR の境界相対比較は `Int<N>` の `<` `>` で書く:

- `ipv4.dst >= 10.0.0.0 and ipv4.dst <= 10.0.0.255` (range の境界明示)

### 6.5 quantifier (`any`, `all`)

```
any : Bool → Bool         (∃ over aux header stack)
all : Bool → Bool         (∀ over aux header stack)
```

inner expression は **stack reference を 1 つだけ含む Bool 式**。stack reference の数が 0 / 2 以上は parser-time error。

空 stack の場合:
- `any({}) = false`
- `all({}) = true`

詳細は `dsl-grammar.md §1.4` 参照。

---

## 7. 値域チェック (fit check)

### 7.1 概要

リテラル narrow が起きるすべての場面で、値が target 幅に収まるか確認する。

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

`Int<N>` への narrow は値域 `[-2^(N-1), 2^N)` に収まる必要がある:

- 非負側上限: `2^N` (= unsigned max + 1)
- 負側下限: `-2^(N-1)` (= signed min)

つまり `-1` は任意 N で OK (= 全 1 bit)、`-129` は `Int<8>` には収まらない (signed range `[-128, 256)` から外れる) が `Int<9>` 以上なら OK。

例:

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

literal の暗黙幅と field の幅が異なるときに reject:

| 例 | 結果 |
|---|---|
| `tcp.dport == 10.0.0.1` | ❌ IPv4 literal は Int<32>、tcp.dport は Int<16> → width mismatch |
| `ipv4.dst == fe80::1` | ❌ IPv6 literal は Int<128>、ipv4.dst は Int<32> → width mismatch |
| `tcp.dport == aa:bb:cc:dd:ee:ff` | ❌ MAC literal は Int<48>、tcp.dport は Int<16> → width mismatch |
| `ipv4.dst == fe80::/64` | ❌ CIDR6 (Int<128> 用)、ipv4.dst は Int<32> → AF mismatch |
| `tcp.dport == XDP_DROP` | ❌ Action と Int<16> → kind mismatch |

**注**: §3.2 で IP/MAC を Int<N> に吸収したので「同幅であれば OK」とも書けるが、リテラル parser が識別している kind 情報 (IPv4 / IPv6 / MAC) を使って **より親切なエラーメッセージ** を出す: `IPv4 literal cannot be compared with bit<16> field tcp.dport (IPv4 requires bit<32>)`。

---

## 8. 型エラー一覧

resolver / parser が出すエラーメッセージのカタログ。すべて `<position> ` プレフィックス付き、末尾ピリオドなし。

### 8.1 fit check 系

実装の helper (`resolve/typing_errors.go`) と一致。`resolve/typing_errors_test.go` で drift を検知する。

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

(parser は LHS-literal / Bool 経路で早期 reject、resolver は IR boundary で defense in depth として再 reject)

### 8.4 coercion / kind mismatch

(Spec 上は禁止だが、現 parser/AST が Bool/Action/CIDR を arith node の operand に出せない構造のため明示エラーは発生しない。D8 一元化 (`resolve/typing.go`) で operand-kind の resolver-side reject 自体は実装したが、parser/AST 構造上 unreachable な経路なので catalog には行が立たない。)

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

`codegen.Capabilities.StrictArithLint` を有効にすると、保守的に検出した overflow / underflow パターンを resolver が型エラーとして reject する:

```
arith may overflow: <expr> can exceed Int<N> max value (use a wider field or guard)    # errArithOverflowSuspect
arith may underflow: <expr> can fall below 0 (RHS may exceed LHS)                       # errArithUnderflowSuspect
```

検出パターン (false-positive を避けるため保守的):
- `field + field` / `field * field` で結果が Int<max(N,M)> をはみ出し得る
- `field - field` で RHS ≥ LHS の可能性

`field + const` などの一般パターンは pass。

### 8.8 codegen 未実装 (resolver は OK、codegen で reject)

`ErrNotImplemented` の wrapped reason として現れる。spec §9.1 の段階展開ぶん:

```
dsl codegen is not yet fully implemented: value V exceeds int32 immediate range — staged Int<N>>32 cmp (dsl-types.md §9.1, F3)
```

---

## 9. 実装ステージング

### 9.1 codegen サポート範囲

型システムは uniform に書かれているが、codegen の実装は段階的に展開:

| 操作 | N ≤ 64 | 64 < N ≤ 128 |
|---|---|---|
| `==`, `!=` | ✅ 既存 (single load) | ✅ 既存 (dual load — IPv6 cmp 経路 / F4) |
| `<`, `≤`, `>`, `≥` | ✅ 既存 | ✅ bracket / where-arith 両方実装 (F3、`emitIPv6OrderedCmp` + `genArithCompare128` ordered branch、register-pair lex compare) |
| `+`, `-` | ✅ 既存 | ✅ where 経路で完全実装 (F4 — `field op const`、`field op field` 両方、stack-bridged carry / borrow) |
| `*` | ✅ 既存 | ❌ 廃止 (F11 bit-slice で代替) |
| `/`, `%` | ✅ 既存 | ⏳ 当面実装しない (software loop、需要薄) |
| **bit-slice** `field[lo:hi]` | ✅ 任意 bit 範囲 (single LDX + bswap + shift+mask、F11/F13) | ✅ byte-aligned 端点に限り cmp 可 (F12 で resolver desugar) |

未実装ぶんは codegen が `ErrNotImplemented` を返す。**型では well-typed、codegen で `not yet implemented`** という分離。

**Literal narrow** (§4.1 / §7.3): 整数リテラル (負数を 2's complement で uint64 化したものを含む) は codegen の最終 emit 直前に **対象 field の幅 N でマスク** される。`tcp.dport == -1` ⇒ 比較 immediate = `0xffff` (Int<16> narrow)。これにより signed-extended 値が int32 immediate 範囲に収まる。実装は bracket predicate 用 (`codegen/predicate.go::emitIntPredicate`) と where arith cmp 用 (`codegen/where.go::genArithWithBits`、target bits は両 operand の field 最大幅から計算) の 2 箇所。

### 9.2 段階展開の意図

- 型仕様は uniform で書く → drift しない
- 実装は需要に応じて codegen を追加する PR を出すだけ → 型仕様は不変
- ユーザーには "型 OK だが実装待ち" を素直に伝える

### 9.3 実装履歴メモ

`feat/p4_based_dsl` ブランチで DSL コンパイラを 0 から立ち上げ、その上に本書 (型システム + 形式仕様) を載せた。最終的に **6 章別 commit** に整理して landed:

| commit | 章 |
|---|---|
| `1ba5b8d7` | feat(dsl): kunai DSL compiler — scaffolding through multi-protocol vocab |
| `ca45e1a4` | feat(dsl): aux header system — gating, stacks, dynamic indices, option walk |
| `4e997249` | refactor(dsl): vocab maintenance — self-validating dispatch + p4c interop |
| `2fc3120d` | **feat(dsl): static type system + formal spec (PR-1 ~ D8)** ← 本書 Part I + Part II |
| `69e65376` | **feat(dsl): F1-F13 follow-up landings** ← §9.4 全 follow-up |
| `9e180f54` | chore(dsl): branch review polish (P0 nil-refs + unit tests + doc sync) |

各 commit の body には子機能の内訳とヘルパ関数名・テスト名が並ぶので、`git log --format=full feat/p4_based_dsl ^main` で章別の落とし込みが追える。本書の D0-D10 各決定がどう実装に降りたかは `2fc3120d` および `69e65376` を参照。

**Pre-squash backup**: 161 commit の細かい history は `pre-squash-backup` tag に保存。必要なら `git log pre-squash-backup` で個別 commit 単位の追跡が可能。

### 9.4 follow-up 項目

`dsl-followups.md` に登録される後続作業。本書の決定に直接由来するもの:

| # | 項目 | 由来 |
|---|---|---|
| F1 | overflow lint mode ✅ 完了 (`resolve.Options.StrictArithLint` opt-in、`codegen.Capabilities.StrictArithLint` 経由で host が選択)。検出パターンは保守的: `field + field` / `field * field` の overflow、`field - field` で RHS ≥ LHS の underflow を error 化。`field + const` などの一般パターンは false-positive を避けるため pass | §6.1 silent wrap への安全網 |
| F2 | 明示 cast 構文 (`(bit<32>) tcp.dport`) ⏸ 仕様で「入れない」と決定 (§5.5)。F1 の overflow ケアの代替手段が必要になったら再検討 | §5.5 |
| F3 | `Int<128>` ordered cmp の codegen ✅ bracket / where-arith 両方完了。bracket は `emitIPv6OrderedCmp`、where-arith は `genArithCompare128` の ordered branch で同じ lex compare ロジックを共有 (high half decision + low half fall-through、`highHalfJumps` / `lowHalfMissJump` を流用) | §9.1 |
| F4 | `Int<128>` arith binop (`+`, `-`) の codegen ✅ 完了。`field == field` / `field op const == field` / `field op field == field` の全形が verifier-load 通過。旧版が `field op const` で permission denied になっていたのは emit が R6/R7 (host-callee-saved) を使い ABI 違反していたため。現在は const-relative carry detect (R5+const 後 `R5 < const` で wrap 判定、orig 保存不要) と stack-bridged の field+field shape で R6-R8 完全不使用。実装は `genArith128FieldOpConst` / `genArith128FieldOpField` で分岐 | §9.1 |
| F5 | `Int<128>` arith binop (`*`) の codegen ❌ 廃止 (= スコープから外す)。代替として bit-slice 構文 `field[lo:hi]` を導入 (下記参照)。実用上 IPv6 同士の乗算は使い道がなく、bit-slice の方が prefix/suffix 比較で広く使えるため | §9.1 |
| F11 | bit-slice `field[lo:hi]` ✅ MVP 完了。bracket predicate / where-arith 両方で使用可 | dsl-types.md §3.4 |
| F12 | bit-slice の (64, 128) 中間 width cmp ✅ 完了 (resolver で AND/OR-chain に desugar、`tryDesugarMultiLDXSliceCmp`) | F11 の延長 |
| F13 | bit-slice の non-aligned 範囲 (`[3:9]`, `[4:12]` など) ✅ 完了 (codegen で pow2-cover load → bswap → shift+mask、`emitSliceShiftMask`)。≤ 64bit 内なら任意の bit 範囲を抽出可 | F11 の延長 |
| F6 | bitwise op (`&`, `|`, `^`, `<<`, `>>`) ✅ 完了。precedence: `&` `<<` `>>` は mul/div 級、`|` `^` は add/sub 級 | DSL 機能拡張 (TCP flag check 等で需要) |
| F7 | `field in [...]` 実装 ✅ 整数 alternatives は完了 (`emitInPredicate`)、IPv4/IPv6/MAC/CIDR alternatives は MVP scope 外 | 既存 dead syntax の有効化 |
| F8 | `field has FLAG` 専用 codegen ⏸ superseded — F6 の bitwise `&` で同等表現 (`tcp.flags & 0x12 == 0x12`) が書けるので独自 emit は不要と判断。**resolver は引き続き `PredHas` を `Unsupported` 扱い** (使うと `ErrNotImplemented`) で、ユーザーには bitwise 形式を促す形になっている。vocab 側に flag 定数を declare するのは vocab 著者の自由 | F6 で代替 |
| F9 | `flow.*` dead syntax 削除 ✅ 完了 | 整理 |
| F10 | `Bool == Bool` precision-preserving codegen ✅ 完了 | `genConditionAsBool` で各 operand を {0, 1} に評価して register に置き、scratch slot 経由で比較。per-packet operand 評価は 1 回ずつ |

---

## 10. 関連ドキュメント

- [`dsl-overview.md`](./dsl-overview.md) — index
- [`dsl-grammar.md`](./dsl-grammar.md) — formal EBNF + 例文 (本書の具象構文側)
- [`dsl-internals.md`](./dsl-internals.md) — 内部実装ノート、ABI、vocab 著者ガイド
- [`dsl-usage.md`](./dsl-usage.md) — エンドユーザー向け CLI ガイド
- [`dsl-followups.md`](./dsl-followups.md) — 残課題リスト (F1-F13 / 完了状態 / 未着手項目)

---

# Part II. 形式仕様 (構文論 + 操作的意味論)

Part I は **実装者向け実用仕様**だった (どこに何の check を入れるか)。Part II は **言語仕様としての形式定義**: 抽象構文・型付け規則・操作的意味論を judgment 形式で書き下す。codegen の正当性 (verifier 通過 ⇒ spec 通り動く) を将来 lemma として証明したいときの土台。

実装が Part II と乖離した場合は、コードか Part II のどちらかが間違っている。両者を同期しているのが Part I (実装ステージング §9) と §15。

## 11. 抽象構文

`dsl-grammar.md` は **具象構文** (= parser が食う EBNF)。本節は **抽象構文** (= AST node の inductive 定義) を表す。具象 → 抽象の対応は parser の責務 (`pkg/kunai/parser/`)。

### 11.1 表記

メタ変数:

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
     | action_lit(a)                                       a ∈ caps.Action ∪ XDP_*
     | ident_lit(name)                                     bare identifier (action keyword carrier; resolver narrows)
     | string_lit(s)                                       MVP-unsupported, parser-only

a  ::= XDP_PASS | XDP_DROP | XDP_TX | XDP_REDIRECT | XDP_ABORTED  (host-supplied)
```

`L̄` 等の overline は 0 個以上の繰り返しを表す。`?` は optional。

**capture spec 対応表** (concrete syntax → AST `CaptureKind`):

| spec 形 | AST kind | 備考 |
|---|---|---|
| `all` | `CapAll` | scratch buffer 全部 |
| `headers` | `CapHeaders` | chain 末尾までの header 累積 |
| `headers+N` | `CapHeadersPlus` | 上記 + N byte |
| `label+N` / `proto+N` / `layer-target` | `CapToLayer` (`Extra=N`) | 対象 layer まで + N byte |
| `absolute(N)` | `CapAbsolute` | chain 構造に依存しない静的 N byte |
| `fields(f̄)` | `CapFields` | 個別 field 列挙、MVP-unsupported |

### 11.3 環境 Γ

型付けと意味論で参照する環境:

```
Γ = ⟨V, Λ, Σ, Caps⟩

V    : Vocabulary           — proto 名 → ProtocolSpec (vocab で declare された field 幅・aux header 構造)
Λ    : Label  → LayerInst   — 解決済 label-to-layer binding
Σ    : Stack  → AuxSpec     — aux header stack の declared 形 (capacity 等)
Caps : Action → Int<32>     — host が許容する action keyset
```

resolver は構文木 + Γ を入力に取り、IR (= 抽象構文の subset) と型情報を出力する。

---

## 12. 型付け規則 (Typing Judgments)

形式: `Γ ⊢ e : τ` ("環境 Γ のもと、e の型は τ")。

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

bitwise / shift 演算 (`&`, `|`, `^`, `<<`, `>>`) も算術と同じ widening / wrap 規則に従う。`<<` / `>>` の RHS は概念的に shift 量 (= スカラー) であって型計算上は他の二項演算と同じ扱いだが、実用上は static literal が推奨 (§6.1 末尾)。

literal narrow: `Γ ⊢ e₁ : Int<·>` のとき surrounding context (= cmp 相手 field の幅か算術 binop の他方の幅) から N を決定し fit-check (§7) を通す。

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

順序付き cmp on `CIDR/Action/Bool` は **rule なし** (= 不在) ⇒ 型エラー。

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

---

## 13. 操作的意味論 (Operational Semantics)

big-step (`⇓`) 形式で filter 評価を定義。1 packet ごとに `accept` / `reject` を判定する。

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

quantifier `q` に対して、`L(q)` の reduction を「q-iteration が成功したか」で定義する。`L(1)` は §13.4。それ以外は反復 + 上下限の制約。

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

ここで `m_chain` は静的 chain 解析 (vocab + chain 全体形) から導かれる **iteration 上限**。実装は `pkg/kunai/codegen/` の `chainCap` 計算で同等。

実装対応: `+` / `*` / `{n,m>4}` は `bpf_loop` + bpf2bpf callback として emit (`pkg/kunai/codegen/loop_*.go`)。`{n,m≤4}` は静的 unroll。

### 13.6 Capture 評価

`eval-captures` は層解決後の chain 状態 ⟨π', α', Λ'⟩ から、各 capture clause を per-clause なバイト範囲に解決する。

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

実装対応: `pkg/kunai/codegen/capture.go` が `eval-captures` を BPF instruction に展開、perf event に view を載せる。

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

---

## 14. p4lite parser machine の意味論

aux header の extract semantics。`pkg/kunai/protocols/*.p4` の `parser` block を small-step machine として解釈する。

### 14.1 状態

```
ψ = ⟨s, π, α⟩
  s : StateName        現在の parser state (`start`、ユーザ定義状態、`accept`、`reject`)
  π : ℕ                cursor (proto layer 内の相対 offset)
  α : AuxView record   抽出済 aux の蓄積 (拡張中)
```

`accept` / `reject` は terminal。

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

`transition select(k) { ... }` の鍵 `k` は p4lite の制限 expression。最大 2 種:

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

`current_header` は extract block 内で直前に `extract()` した header に bound されている。p4lite parser は extract と transition の順序を強制するため、select-key は常に "ちょうど抽出された" header の field を指す。

実装対応: `pkg/kunai/vocab/p4lite/parser.go` が select expression を AST に格納し、`pkg/kunai/codegen/parser_machine.go` がこれを `R3 = mem[π + field_offset]` + 必要なら `R3 &= const` に展開。

### 14.4 layer 全体での aux 抽出

`[E-Layer-Proto-1]` における `aux-extract(p, π, P, α)` は `start → accept` (or `reject`) までの transitive closure として定義される:

```
aux-extract(p, π, P, α) = α' such that ⟨start, 0, α⟩ →* ⟨accept, π_final, α'⟩  (proto bytes 内 relative)
                        = ⊥ if →* ⟨reject⟩
```

`⊥` (reject) は親 layer の `[E-Layer-Proto-1-Fail-Pred]` 系統の失敗にマップされる。

---

## 15. 実装との対応 (Soundness sketch)

### 15.1 各実装ステージ ↔ 形式仕様

| 実装ステージ | パッケージ | 対応する formal section |
|---|---|---|
| 具象構文 → AST | `pkg/kunai/parser/`、`pkg/kunai/lexer/` | §11 抽象構文 |
| AST → IR + 型検査 | `pkg/kunai/resolve/` | §12 型付け規則 |
| IR → eBPF instructions | `pkg/kunai/codegen/` | §13、§14 操作的意味論 |
| vocab parser block 解釈 | `pkg/kunai/vocab/p4lite/` | §14 parser machine |

### 15.2 Soundness conjecture (codegen の正当性)

「Compile が成功した filter F は、任意の packet P に対して spec の意味論と同じ判断を返す」:

```
∀ F, P.  Γ ⊢ F : FilterOK   ∧   kunai.Compile(F) = (insns, _, nil)
       ⇒ run(insns, P) ↓ accept(α, Λ, captures)  iff  ⟨F, P⟩ ⇓ accept(α, Λ, captures)
       ⇒ run(insns, P) ↓ reject                  iff  ⟨F, P⟩ ⇓ reject
```

ここで `run(insns, P)` は kernel BPF verifier に通った `insns` を XDP として実行した結果。

このうち実装が保証する範囲は次の通り:

1. **Type soundness (resolver)**: `Γ ⊢ F : FilterOK` ⇒ resolver は IR を生成してエラーを返さない。実装: `resolve/typing.go` (§9 ステージング A) で fit-check / div-zero を含むすべての §12 rule を網羅的に走らせる。**現状: 完全実装。** 不足ケースは型エラーとして reject されるべきだが見逃しがあれば spec バグまたは実装バグ。
2. **Codegen soundness (BPF instructions)**: well-typed IR ⇒ 等価な命令列。実装: `codegen/` 配下のテーブル駆動 emit。**現状: §9.1 のとおり Int<128> 系で部分実装** (= 型 OK / `ErrNotImplemented`)。Soundness は「emit 成功した命令列について」成立。
3. **Verifier 通過性**: emit された命令列が kernel BPF verifier に通る。形式的保証は無いが回帰 test (`internal/program/load_dsl_test.go` を 4 kernel matrix で実行) で経験的に検証。

完全な lemma-style 証明は将来課題。本書は **証明できる土台を spec として固定する** ことが主目的。

### 15.3 Proof sketch (各 sub-claim の方針)

完全な機械証明は (Coq / Agda / 形式メタ言語の選定込みで) 将来課題だが、人間レベルの sketch を共有しておく。

#### Type soundness (resolver) — 構造帰納

resolver は AST を root から再帰的に walk する。各 §12 rule に対応する resolver の関数は:

| §12 rule | resolver 実装 |
|---|---|
| T-FieldPrim / T-FieldAux | `resolve/where.go::resolveQualifiedField` |
| T-IntLit + narrow | `resolve/typing.go::checkArithExpr` |
| T-CmpEq-Int / T-CmpOrd-Int | `resolve/typing.go::checkArithCondition` (経由で `arithCmpTargetBits`) |
| T-CmpCIDR4 / T-CmpCIDR6 | `resolve/typing.go::checkLiteralWidthShape` (旧名: `validateLiteralFieldType`) |
| T-Where-Bool-Decay | parser で WAtomArith に書き換え (parseCmpOrBoolAtom) |
| T-And / T-Or / T-Not | `resolve/where.go::resolveWhere` の `WAnd / WOr / WNot` 分岐 |
| T-Quant | `resolve/where.go::findQuantTarget` |

帰納仮説: 各部分式が well-typed なら resolver は対応する IR ノードを返してエラーなし。

帰納ステップ: 各 rule で前提の typing が成立 ⇒ resolver の関数は前提の構造を expect ⇒ IR を返す or 既知のエラーパス。

D8 一元化 (commit `0f353cd1`) と Bool ordered cmp resolver reject (commit `d87caff9`) で §12 の rule は resolver 側で全網羅された。残るギャップは parser 側で先に reject される経路 (= 構造的に IR に出てこない) のみ。§15.4 punch list は Type soundness 行を ✅ 完了化済。

#### Codegen soundness — operational simulation

codegen は IR ノードを `asm.Instructions` に展開する。サブクレーム:

> 各 IR ノード `n` について、§13 で定義された `⇓` の reduction が `gen(n, ...)` の emit する命令列を実行した場合の結果と一致する。

これは **operational simulation lemma** と呼ぶ形:

```
∀ n, σ.  ⟨n, σ⟩ ⇓_P b   ⟹   ∃ σ_bpf'.  bpf-step*(insns(n), σ_bpf(σ)) = σ_bpf'(σ, b)
```

ここで `σ_bpf` は packet σ を BPF レジスタ + stack 状態に encode する操作。詳細は `pkg/kunai/codegen/codegen.go` の package doc に書かれた ABI 契約 (R0=data, R1=data_end, KunaiStackTop など) を参照。

代表的サブ lemma:

- **arith binop の simulation**: `binop(+, e₁, e₂) ⇓ n₁ + n₂ mod 2^w` ⟺ `gen(...)` が emit する `add R3, R5` (BPF 64bit add) の結果が同じ
- **cmp simulation**: `cmp(e, ==, v) ⇓ b` ⟺ emit された `JEq R3, imm, label` の routing が一致 (= jump 先 == fallthrough のとき b=true)
- **chain step simulation**: `[E-Layer-Proto-1]` の `π' = π + total_bytes` ⟺ emit される `add R4, |hdr|` (`R4` が cursor)

これら全部を機械的に証明したい場合は SMT (BPF 命令を非解釈関数で encode) でやる手があるが、本プロジェクトでは経験的検証 (= verifier 通過 + dsltest による packet test) に依存。

#### Verifier acceptance — 帰納的構造

BPF verifier の通過性は kernel 任せだが、kunai は次の構造的招待を遵守する:

1. **Stack 使用量**: KunaiStackTop 以下に収まる (`pkg/kunai/codegen/codegen.go` パッケージ doc で固定)
2. **Loop bound**: 静的 unroll は constant、`bpf_loop` は引数の上限を const として渡す
3. **Pointer arithmetic**: `R0 ≤ R4 ≤ R1` を毎 step 維持 (chain emit が bounds check を入れる)
4. **Register lifetime**: caller-saved (R1-R5) の保持は relevant block 内のみ

これらを保ちつつ insns 列が verifier に通れば operational soundness の前提条件 (= insns が実行できる) は満たされる。

### 15.4 残タスク

| 項目 | 状態 |
|---|---|
| Type soundness の §12 rule 全網羅 (D8 一元化) | ✅ 完了 (resolve/typing.go + typing_errors.go に集約、ordered cmp on Bool/network literal の resolver-side defense in depth も完備) |
| Codegen soundness の lemma-style 証明 | 未着手 (sketch のみ) |
| Verifier acceptance の formal property | 未着手 (経験的検証のみ) |
| Mechanical proof framework 選定 | 未着手 |

#### 既知の verifier corner case

経験的検証で発見済の「型 OK / Compile 成功 / kernel verifier reject」ケース:

- **`where false`** ✅ 解決済 (`codegen.go::isConstantFalseCondition`): filter top-level の where が constant-false に評価されるとき、Gen は layer chain emit を skip して minimal always-reject program (R2=0 → filter_result) のみ返す。これで chain bounds check の side effect が unreachable な accept tail と組み合わさって verifier 側 liveness 検査に引っかかる事態を回避。dslEntryExprs にも復帰済。
