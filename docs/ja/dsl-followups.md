# DSL 続編バックログ

本ドキュメントは **次に何を、どの優先度で、どう手をつけるか** を整理する作業ノート。各項目は単独 PR にできる粒度に切ってある。

## ブランチ完了状態

`feat/p4_based_dsl` ブランチで以下が landed:

- **DSL コンパイラ** (lexer / parser / resolver / codegen) と多層 protocol vocab — chap 1-3
- **静的型システム + 形式仕様** (`dsl-types.md` Part I + Part II、~1300 行) — chap 4
- **F1-F13 follow-up** (overflow lint、bit-slice、Int<128>、bitwise op、in、BoolEq precision、flow.* 削除、…) — chap 5
- **レビュー polish** (nil-ref guard、unit test、doc sync、CI fix) — chap 6
- **F14**: kunai packet-pointer codegen — chap 13 (`--mode xdp` で DSL 全パターン verifier 通過)

優先順位は「実利用での痛さ × 工数の軽さ」で並べた個人見解で、実装着手前にレビューで上下する想定。

## 完了履歴

詳細はコード・該当 commit・git log を参照。各 entry は概要のみ。

```
P0-1  CI vimto             (255d9dd)
P0-2  IP リテラル predicate (766e8e8, 369d556, 02ba9c2, feat/p4_based_dsl)
P0-3  CHAIN_END 一般化      (befecd2, 64dff53)
P0-4  p4c CI 検証          (Dockerfile + cache、`docker/p4c-check/`)
A     可変長 header 対応    (parser machine + HDRLEN/OPT/FlagTriggers)
B     aux header model      (PR-A〜PR-D + PR-B'、設計は `dsl-internals.md §6`)
P1-5  ソース位置統一        (d258272 — PositionedError で line:col prefix)
P1-6  --dsl-help            (6ad3b97 — grammar + bundled protocol catalogue)
P1-7  --list-protos         P1-6 で代替
P3-12 alt 異種 size+dispatch per-alt body emit + matched flag (R5)
P3-13 alt-of-alt             resolver flatten (`((a|b)|c)` → `(a|b|c)`)
P5-15 pkg/kunai/ 移動        internal/dsl/ → pkg/kunai/
P5-16 target 抽象化         Capabilities + host/xdp + ABI 契約 + regression test
F1    Overflow lint mode    `Capabilities.StrictArithLint` opt-in
F3    Int<128> ordered cmp  bracket + where-arith
F4    Int<128> arith binop  +/- partial (field op const ; field+field staged)
F6    bitwise op            `&` `|` `^` `<<` `>>`
F7    field in              整数 alternatives (multi-word/aux/where 形は staged)
F9    flow.* 削除            dead syntax 完全除去
F10   Bool == Bool          precision-preserving codegen
F11   bit-slice MVP         `field[lo:hi]` 全 layer 実装
F12   bit-slice mid-width   `(64,128]` 範囲を multi-LDX desugar
F13   bit-slice non-aligned ≤64bit 範囲で post-load shift+mask
F14   packet-pointer codegen `--mode xdp` で DSL 13 chain 全 verifier 通過
P2-8  field in              ✅ F7 で landed
P2-9  field has             ✅ F6 bitwise & で superseded (`tcp.flags & 0x12 == 0x12`)
B-1   .exists bool atom     ✅ 型システム PR-2 で対応 (where 句直接記述)
```

## P2: 機能拡張 (需要次第)

### 10. 算術ネスト 4 段以上

**動機**: 現在 stack slot が 4 段。`((a+b)*c+d)*e` のような長い式が ErrNotImplemented。

**スコープ**:
- `arithStackBase = -56`, max depth 4 を 8 か 16 まで拡張
- BPF stack 512 byte 制限内に収める
- 既存 stack 利用箇所 (`-48` の args ptr, bpf_loop ctx の `-128`〜 など) との衝突を再確認

**工数**: 0.5 日。

### B-2. IPv4 options vocab 拡張

**動機**: §B PR-D で TCP options の vocab 宣言と option-walk codegen は通った。同じ枠組みで IPv4 options (Router Alert, Record Route, Source Route, Timestamp, Security 等) を declare すれば追加 codegen なしで動く。

**スコープ**:
- `pkg/kunai/protocols/ipv4.p4` に `IPV4_OPT_TERMINATOR_KIND/PADDING_KIND/LENGTH_BYTE_OFF` + 各 option の `<NAME>_KIND/SIZE` + `header ipv4_opt_<name>_h`
- 主要対象: Router Alert (kind 148, 4 B 固定)、Record Route / LSR / SSR / Internet Timestamp (可変、内部 array — Phase 2 まで `.exists` のみ)
- dsltest E2E

**工数**: 1 日 (RA だけなら 2 時間)。

### B-3. CIDR / IPv4 / MAC literal を aux field に

**動機**: §B PR-A〜D で integer 比較の aux access は通ったが、IPv4 / IPv6 / MAC / CIDR literal を aux 経由で比較するパスは現状 `ErrNotImplemented`。発火する書き方は 2 種:

- bracket form: `gtp[opt.flow_label == fe80::1]` — codegen `predicate.go::emitIPv6Predicate` 等の `pred.Field.Aux != nil` ガード
- where form (single + quantified): `where srv6.segments[0].addr == fc00::/16`、`where any(srv6.segments.addr == fc00::/16)` — codegen `where.go::genLiteralCompare` の CIDR 分岐内 `aux != nil` ガード (現エラー: `CIDR literal predicate on auxiliary header field is not yet supported`)

**スコープ**:
- `pkg/kunai/codegen/predicate.go::emitIPv4Predicate` / `emitIPv6Predicate` / `emitMACPredicate` / `emitIPv4CIDRPredicate` / `emitIPv6CIDRPredicate` の `pred.Field.Aux != nil` ガードを通す
- `pkg/kunai/codegen/where.go::genLiteralCompare` の CIDR / multi-byte literal 分岐で aux 対応 — 既存 `emitFieldLoad` (anchor 経由) で abs / slot 両モード対応にする
- aux byte offset を `fieldRefByteOffset` で取り、`genLiteralCompareDynamic` 同様に gating + 多 byte 読み出しを emit
- bracket form と where form のヘルパ共通化を視野

**工数**: 1-2 日 (5 + 1 関数の並列対応)。

### B-4. Option 内部 array (SACK.blocks / RR.addrs)

**動機**: §B PR-D は TCP options を Schema A/B (固定フィールド + 単発) に絞った。SACK は `{left, right}` ブロックの配列 (Schema C)、IPv4 RR は IP アドレスの配列。これらにアクセスするには option 内部 array に `[N]` index と `any/all` を効かせる必要あり。

**スコープ**:
- vocab に array 宣言 (option header 後の trailing variable 領域 + 要素サイズ)
- resolver: `tcp.options.SACK.blocks[N].left` の 5-part path 受理
- codegen: option-walk で見つけた option base + `[N] * elem_size` で内部要素アクセス
- `any(tcp.options.SACK.blocks.left > 1000)` などの量化

**工数**: 2-3 日。chain quantifier 系のロジック流用可。

## P3: コード負債 / Sanity 系

### 11. Sanity self-dispatch chain

**動機**: chain self-dispatch は Field / NoCheck のみ。Sanity (NIBBLE) は codegen で明示拒否。

**スコープ**:
- 実用ケース稀 (MPLS s-bit は CHAIN_END で対応済み、SRv6 もまだ必要なし)
- 「dispatch 全種類が chain で使える」という API 対称性のため

**工数**: 0.5 日 (callback 内 sanity 検査の emit は既存ヘルパ流用)。

## P3.5: 型システム関連 follow-up (`dsl-types.md` から派生)

### F2. 明示 cast 構文 ⏸ negative spec

`dsl-types.md §5.5` で「**入れない**」と決定。F1 (overflow lint) が landed したので overflow ケアの代替も既に提供済。需要が出たら再検討する保留枠として残置。

### F5. `Int<128>` arith binop (`*`) ❌ 廃止

scope outside と判断。F11 bit-slice (`field[lo:hi]`) で「128bit 同士の比較 / prefix 抽出」を可能にしたため、ipv6 同士の乗算は実用 scenario が見当たらない。bit-slice の方が prefix/suffix 比較で広く使えるため。

### F8. `field has FLAG` 実装 ✅ F6 で superseded

F6 の bitwise `&` で `tcp.flags & 0x12 == 0x12` と書けるようになり、専用 emit は不要。vocab 著者が flag 定数を declare するかどうかは vocab 設計の自由。

### F15. `action` atom の semantic 一般化 (XDP 専用 → 完了状態 register)

**動機**: 現状 `action` atom + `Capabilities.Action` の API は "XDP retval" を念頭に設計されてる感がある (XDP_DROP/XDP_PASS 等の名前が dsl-grammar.md にも明示されていた)。本質は **「host のパケット処理完了状態を保持する 1 register」をフィルタする機能** なので、TC verdict / socket filter verdict など他 host も同じ atom 名 (`action`) で expose できるべき。

**スコープ (narrow)**:
- API は **`Capabilities.Action map[string]int32` のまま** (multi-atom registry には拡張しない)
- TC adapter は `Capabilities.Action` に `TC_ACT_OK` / `TC_ACT_SHOT` / ... を登録するだけで、文法・resolver 触らず動く
- DSL grammar の `action-value ::= ident` の wording を「XDP action」→「host の完了状態 register」に reframe (済 — `dsl-grammar.md` で実施)
- 必要なら generic 名 (`pass`/`drop`) を XDP/TC 両方で登録して cross-host 移植性を上げる検討は別途

**やらないこと (= 過剰一般化として却下)**:
- `Capabilities.Atoms map[string]Atom` 的 multi-atom registry — `where queue_id == 3` / `where ifindex == 7` 等の任意メタデータ filter に拡張するのは "なんでもできる = なんでもできない" になりがち。DSL は packet header 読み + 完了状態 overlay の 2 軸に絞る

**現状代替**: 上記 reframe doc 済なので、**実コード変更不要**。TC adapter 着手時に `Capabilities.Action` に TC_ACT_* を登録すれば即動く。本 entry は "意図のメモ" 扱い。

## P4: 大物 (スコープ要再検討)

### 14. `flow.is_new` / `flow.age` / `flow.state` 状態 atom

**動機**: 連続パケット間の関係 (= flow tracking) に基づくフィルタ。

**スコープ**:
- BPF_MAP_TYPE_HASH で flow tuple → メタデータの map を持つ
- パケットごとに lookup + update
- map size, eviction policy, key 設計など考慮事項多い

**工数**: 数日〜1 週間。本格仕事。

## 中長期 (具体化はそのとき)

- **p4c とのインターオペ拡張**:
  - **kunai → p4c (既達)**: 自作 vocab 16 ファイルすべて `p4test --parse-only --Werror` 通過 (P0-4)。p4lite は P4-16 の strict subset として設計されており、`header` / `const` / `parser` (extract/select/accept/reject 含む) は full に対応。
  - **p4c → kunai (現状の限界)**: 任意の P4 file を p4lite で食えるのは「dsl が必要とする宣言だけが含まれるファイル」まで。`action` / `table` / `control` / `apply` / `extern` を含む実 dataplane プログラムは `lexer.go::rejectedKeywords` で明示 reject (詳細は `dsl-internals.md §5`)。dataplane `.p4` から header 定義と parser block だけを抽出する preprocessor、もしくは対応キーワードを silent skip するモードが、本格 P4 ecosystem との橋渡しに必要。
- **BTF auto-vocab**: kernel に load されている BPF プログラムの BTF から自動 vocab 生成
- **DSL→tcpdump ロスレス変換** (一部式): デバッグ時に「この DSL 式を tcpdump で書くと何か」を表示

これらは技術的に面白いが MVP の延長線にはない大物。要望ベースで考える。

## 参考

- 文法 (formal EBNF + 例文) — [`dsl-grammar.md`](./dsl-grammar.md)
- コード読解 — [`dsl-internals.md` §2.3 パッケージごとのツアー](./dsl-internals.md#23-パッケージごとのツアー-依存順-leaf--root)
- 利用者向けガイド — [`dsl-usage.md`](./dsl-usage.md)
- 開発経緯は git log を参照 (旧 `dsl-development-summary.md` / `plan_dsl.md` は本 followups と git 履歴に統合)
