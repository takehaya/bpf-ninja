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
P2-10 算術ネスト 4→8        bpf_loop ctx を 16 byte 下に移動 + maxArithDepth bump
B-1   .exists bool atom     ✅ 型システム PR-2 で対応 (where 句直接記述)
B-3   parser-block TLV walk  PR-3-1〜4 + Phase 2 retry (demand-driven slot, lifted prelude, ~6 insn vs legacy ~200; 4 kernel matrix green)
B-5   ParserCounter extern   p4lite に Tofino TNA 互換 ParserCounter (extern + set/decrement/is_zero) を追加。vocab loader / codegen / dsltest E2E まで通り、合成 IPv4 vocab で IHL=5/6/7/15 walk が verifier 通過
B-2   IPv4 options vocab     ParserCounter ベースの 2-key tuple-select walk + demand-driven bulk-advance fallback (02ea93e) で production migration (625ba5e)。Router Alert (kind=148) を declare、4 kernel matrix green
```

## P2: 機能拡張 (需要次第)

### 10b. 算術ネスト depth 8 → 16 (将来枠)

**動機**: P2-10 で 4 → 8 まで上げた (`maxArithDepth = 8`、bpf_loop ctx を -16 シフトして [-160, -128) gap を半分使用)。さらに 16 まで上げると `where` 句で 15 段の binop が書けるが、現時点で 8 段越えの実用ケースは出ていない。

**ブロッカー**: 16 にすると arith slot 13 (-160) が `whereLayerEntrySlotBase = -160` と衝突する。回避案は 2 通り:

- (a) `whereLayerEntrySlotCap` を 12 → 8 に減らす (12-layer chain は実用稀。192 byte → 128 byte の節約で arith に 8 slot 回せる)
- (b) where layer slots を `[-256, -160)` に押し下げる ([-512, -256) は今全部 free だが host が将来拡張する余地として残しておきたい)

**スコープ (将来)**:
- 上記 (a) または (b) を採用
- `pkg/kunai/codegen/codegen.go::KunaiStackTop` doc block 更新
- `TestZeroCapsIsHostAgnostic` で stack budget が 512 byte 内に収まること再確認

**parser quirk** (P2-10 と同時にレポート、修正は別件): where atom の冒頭 `(` は parseWhereAtom が where-or-expr 用に消費するので、`where (a+b)*c == 21` の形で arith subexpression を parens 化することが できない。回避は `where a*c+b*c == 21` のように parens を外すか、`where ... and (a*c == 21)` 形の bool wrap で書く。修正には parser の lookahead 追加 (paren が arith なのか where なのか peek) または明示的 syntax marker (`@(` 等) が必要。

**工数**: 0.5〜1 日 (どの slot 構成を採用するか合意 + test 拡張)。

### B-2. IPv4 options vocab 拡張 ✅ landed (Router Alert)

**動機**: §B PR-D で TCP options の vocab 宣言と option-walk codegen は通った。同じ枠組みで IPv4 options を declare すれば追加 codegen なしで動く。

**経緯と完了 (2026-05-04)**:

1. B-5 (ParserCounter extern) と 2-key tuple-select (`(pc.is_zero(), pkt.lookahead<bit<8>>())`) の vocab + codegen は先行 landing。合成 IPv4 vocab 経由の `TestParserCounterTupleDispatch` (dsltest) で E2E 検証済。
2. 第一次 production migration (commit `39f5c530`) は `eth/ipv4/udp/gtp/...` chain で kernel verifier 1M insn limit 超過 → 一旦 revert。原因は bpf_loop subprogram の探索を verifier が下流レイヤと isolate できなかったため。
3. **demand-driven bulk-advance fallback** (commit `02ea93e`): program が `ipv4.options.<X>` を query しない場合は bpf_loop を emit せず Mechanism 1 相当の bulk advance に short-circuit する codegen を追加。`option_demand.go::collectQueriedOptions` パターンを walk 全体に拡張。
4. **production migration 再試行 + Router Alert** (commit `625ba5e`): bundled `ipv4.p4` を Mechanism 8 化。`(4,5):accept` fast path は verifier blowup の原因だったので削除し、bulk-advance fallback が IHL=5 = 0-byte advance を吸収する形に。Router Alert (kind=148) を `ipv4_opt_router_alert_h` として declare、`parse_router_alert` state で extract。
5. 4-kernel matrix (6.1 / 6.6 / 6.12 / 6.18) で全 `TestBpf*` green を確認。

**残スコープ (現状の小品 / future)**:
- 他の主要 IPv4 options (Record Route、LSR/SSR、Timestamp、Security) は現状未宣言。要望次第で declare すれば codegen 追加なしで動く想定。
- B-4 (Option 内部 array) で Record Route の `addrs[N]` や Timestamp の `entries[N]` を扱う場合は別経路。

### B-2a. tcp parse_unknown_opt の length≥2 guard (verifier blowup で deferred)

### B-2a. tcp parse_unknown_opt の length≥2 guard (verifier blowup で deferred)

**動機**: tcp.p4 の `parse_unknown_opt` は `pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3)` で length byte を読んで advance するが、length=0/1 の malformed packet だと R4 が peeked window を超えず、parse_options self-loop が同じ kind/length に対して再入し MAX_DEPTH (32) まで spin する。

**試行 (2026-05-04)**: `vocab.HeaderLength` に `MinValue` field を足し、`buildAdvanceLookahead` で `MinValue = LookaheadBits/8 = 2` をセット、`emitVariableTrail` で `JLT lenReg, 2, fail` の guard を発行する変更を実装 → `eth/ipv4/tcp where tcp.options.MSS.value == 1460` 系で kernel verifier が 1M insn 上限超過。bpf_loop callback (parse_options 自己ループ) の中に新 conditional を足すと MAX_DEPTH 反復で scalar ID 数が掛け算で増えて verifier 探索が爆発。

**現状の落とし所**: emit を no-op にして deferred。MAX_DEPTH=32 の cap は維持されてるので length=0/1 packet も終端する (32 iter ぶんの CPU 浪費だけ、infinite loop ではない) — 正しさ問題ではなく polish 項目。コメントを `parser_machine.go::emitVariableTrail` 内に残してある。

**残スコープ**:
- (a) bpf_loop callback から early-exit する tight local label を仕組み化し、`JLT lenReg, 2, exitLabel` で scalar ID を引き回さない経路を作る
- (b) または lookahead-driven advance を専用 emit (`emitTLVAdvance`) に切り出し、loop body 全体を verifier-friendly な形に再構成
- (c) length byte mask を tighten (`AND 0xFE` → `JLT 2`) して verifier に値域 hint を渡せないか探る

**工数 (予測)**: 1-2 日 (emit 形態探索 + 4-kernel verifier 検証)。優先度低 (CPU 浪費のみ、機能不足ではない)。

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
