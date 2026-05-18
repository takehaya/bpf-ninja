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
B-4   Option 内部 array      TCP SACK の {left, right} ブロック配列を 4-PR で land (c97a0ba/a4375c1/0cba890/51f9992)。owner-bound HeaderStack + dispatched-but-not-extracted aux で R1 verifier 爆発を回避、static unroll 量化で bpf_loop 増やさず。RR 追加は PR-A.5 として別 entry
B-3   aux literal predicate  IPv4/IPv6/MAC/CIDR の 6 gate sites を解除 (6547a42)。新 auxLoadEmitter で aux 4 mode (single/static-stack/dynamic-stack/owner-bound) を unify、`srv6.segments[0].addr == fc00::/16`、`ipv4.options.RR.addrs[0].addr == 10.0.0.1` 等が動く
B-4a  IPv4 Record Route      pc.decrement に field-expr / lookahead-form 拡張 (69cc697)、ipv4.p4 RR declare (b17d1c5)。R1 contingency 発火 → dispatched-but-not-extracted shape に pivot。SACK と同型の addrs[N] / any/all
#11   IPIP layered dispatch  (synth chain は revert)。ipv4.p4 / ipv6.p4 に `IPV4_IPV4_PROTOCOL=4` / `IPV6_IPV6_NEXT_HEADER=41` を 1 行 declare、`eth/ipv4/ipv4/tcp` / `eth/ipv6/ipv6/tcp` で IPIP / 6-in-6 が表現可能。各 layer 独立 parser machine で IHL>5 / ext header も正しく handle
F15   TC adapter             `pkg/kunai/host/tc/` 新規 (host/xdp の peer)。 `loadPacketPointers` を host-aware 化 + sk_buff member offset を runtime BTF resolve、 `--mode tc-entry/tc-exit` で `where action == TC_ACT_SHOT` 等が動く。 4-kernel verifier matrix に TC 用 entry 追加
R32   dynamic scratch        per-filter `FilterMinPrefix` で in-kernel scratch read を 512 B → 必要分のみに動的縮小。 fentry filter cost を 0.7→14.5 Mpps に解消 (paper §6 R32)
R22   sharded ringbuf hoist  per-CPU ringbuf を `ARRAY_OF_MAPS` で entry/exit/xdp の全 attach mode に統一。 capture 出力は `path.pcap.cpuN` shards に分散
SnapA snaplen Option A       `capture` 句なし = `capture all` の sugar (= MaxCapLen=0 → host DefaultCapLen=1500 fallback)。 tcpdump 互換 UX を優先、 ringbuf 予約縮小は `capture headers` 等で opt-in
V4    P4 vocab-driven layout `codegen/parser_trail.go::knownVariableTails` ハードコード map + `resolve/where.go::optionsSegment` 予約名 + `codegen/where.go::stackCountSource` の srv6-specific 分岐を全削除。SRv6 は native `pkt.advance` で表現、ipv6_ext_h は `@kunai_variable_tail` + `@kunai_writeback` で表現、byte offset 6 (ipv6.next_header) は ipv6.p4 の field layout から動的解決。declare-only top-level aux stack は `@kunai_layout[after=primary|<stack>]` 必須化 (alias bug 防止)、chain 解決 + cycle 検出付き。SRv6 segments の runtime iteration count は `@kunai_stack_count[field=last_entry, offset=1]` から動的解決。filterset_test 30 sub-test insn count 全 byte-for-byte 維持、`p4c --parse-only` 通過
```

### V4 intentional non-violations (= `.p4` 駆動化せず Go に残した hardcode)

V4 migration で「`.p4` 1 個 drop で新規 protocol を足せる」 を建前として 4 件の
protocol-specific hardcode を `.p4` 側に逃したが、 同 survey で見つかった残り
2 件は **意図的に Go 側に残置** した。 将来の audit 担当者がこれを「未解決の
違反」 と誤解して再対応しないよう、 判断根拠を残す。

**violation D: `pkg/kunai/vocab/loader.go::classifyConsts` の命名規約 regex**

dispatch const を `<SELF>_<PARENT>_<FIELD>` 等の正規表現マッチで分類してる箇所
(`reField`, `reChainEnd`, `reNoCheck`, `reSanityName`)。 形式上「`.p4` 1 個
drop で済む」 を破るが、 これは **cross-file consistency の load-bearing
mechanism**:

- 全 16+ プロトコルが同じ命名規約に従う事で typo / 誤分類が起こりにくい
  (= `TCP_IPV4_NEXT_HEADER` のような pattern が全 protocol で統一)
- annotation 化すると uniformity が weakening、 各 `.p4` が独自にカテゴリ宣言
  できてしまう
- 新規 protocol が命名規約に従わない場合は **明示エラーで loader が弾く** 方が
  silent miscompile より遥かに安全 (= 規約破りは設計者の意図と離れた事を
  示唆するシグナルとして機能する)

つまりこの regex は「強制的な API contract」 であって、 `.p4` 側に annotation
として落とすと API contract が緩むだけで何も得しない。 残置で正解。

**violation E: `pkg/kunai/vocab/loader.go::maxDepthCap = 64`**

全 protocol 共通の MAX_DEPTH 上限 64。 `.p4` 側で `<SELF>_MAX_DEPTH = N` を
declare できるが、 **64 を超える値は Go 側で reject** する hard ceiling。

これは **BPF verifier の 1M insn limit に対する安全弁**:

- N を大きく超える depth (例: 4096) を `.p4` で declare すると、 codegen が
  4096 × 1 iteration あたり数十命令 → 1M insn 制限を踏む
- vocab author が知らずに巨大値を書くと load 時には通っても compile 時に
  cryptic な verifier reject が出る、 デバッグ困難
- 64 は経験的に妥当な上限 (現存 vocab は max が 32 = TCP_PARSER_MAX_DEPTH)
- annotation 化して vocab 側 override を許すと事故母体になる ROI 釣り合わず

protocol 別の安全弁として残置で正解。 もし将来 verifier の 1M 上限が緩和
されたら (Linux 6.20+ で state-ID coalescing が入る話 = B-2a 関連) この cap も
再評価候補。

### ⚠️ Breaking changes since v0.x (master 投入時に release notes へ)

- **SnapA (snaplen Option A)**: `capture` 句なしの payload default が「filter
  最小 prefix」 から「full packet (1500 B)」 に変わった。 旧挙動に依存して高
  throughput を出していた pipeline は filter 末尾に `capture headers` を追記
  すること。 詳細: `docs/ja/dsl-usage.md` の "snaplen トレードオフ" 節。
- **R22 sharded output**: `-w foo.pcap` の出力は `foo.pcap` (SHB+IDB のみの
  marker) + `foo.pcap.cpuN` (実 packet) に分散。 単一 file を期待する downstream
  tool は `mergecap` 等で結合する。

## P2: 機能拡張 (需要次第)

### 10b. 算術ネスト depth 8 → 16 ✅ landed

**動機**: P2-10 で 4 → 8 まで上げた。 さらに 16 まで上げて `where` 句で 15 段の binop が書けるように。

**Land 内容 (commit 016cacc77c)**: stack 再配置で `maxArithDepth = 8 → 16`、 `bpfLoopCtxOffsetSlot = -144 → -208` (-64 シフト)、 `whereLayerEntrySlotBase = -160 → -224` (-64 シフト)、 `dynamicAuxOffsetSlotBase = -256 → -280` (-24 シフト)、 `whereLayerEntrySlotCap = 12 → 7`。 trade-off は whereLayerEntrySlotCap 縮小だが現存 chain set (TCP at layerPos=5 が最深) は全 pass。

**parser quirk** (10b と関係しない別件、 修正は未着手): where atom の冒頭 `(` は parseWhereAtom が where-or-expr 用に消費するので、`where (a+b)*c == 21` の形で arith subexpression を parens 化することができない。 回避は `where a*c+b*c == 21` のように parens を外すか、`where ... and (a*c == 21)` 形の bool wrap で書く。 修正には parser の lookahead 追加 (paren が arith なのか where なのか peek) または明示的 syntax marker (`@(` 等) が必要。

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

**動機**: tcp.p4 の `parse_unknown_opt` は `pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3)` で length byte を読んで advance するが、length=0/1 の malformed packet だと R4 が peeked window を超えず、parse_options self-loop が同じ kind/length に対して再入し MAX_DEPTH (32) まで spin する。

**試行 (2026-05-04)**: `vocab.HeaderLength` に `MinValue` field を足し、`buildAdvanceLookahead` で `MinValue = LookaheadBits/8 = 2` をセット、`emitVariableTrail` で `JLT lenReg, 2, fail` の guard を発行する変更を実装 → `eth/ipv4/tcp where tcp.options.MSS.value == 1460` 系で kernel verifier が 1M insn 上限超過。bpf_loop callback (parse_options 自己ループ) の中に新 conditional を足すと MAX_DEPTH 反復で scalar ID 数が掛け算で増えて verifier 探索が爆発。

**残スコープ (2026-05-04 再評価で 3 案とも棄却)**:
- (a) bpf_loop callback から early-exit する tight local label に `JLT lenReg, 2, exitLabel` を発行 → ❌ JLT が verifier scalar ID を増やす根本原因は jump 先ではなく **no-jump 経路の新 scalar ID 伝播**。jump 先を変えても MAX_DEPTH×N の id explosion は緩和されない。
- (b) lookahead-driven advance を専用 emit (`emitTLVAdvance`) に切り出し → ❌ 別関数にしても結局 lenReg を packet からロード → 比較 → 分岐の流れは同じ。verifier の state-ID 蓄積問題は構造的で emit の場所を変えても解決しない。
- (c) length byte mask tighten で branch-less saturation → ❌ `lenReg | 2` は length=4→6, length=8→10 など偶数長を壊す。`& 0xFE` は length=1→0 と退化。BPF に saturating arith / cmov が無く、branch-less に length≥2 を強制する操作がない。

**現状の落とし所 (defer 確定 + soft 仕様 test pin)**: emit は no-op のまま deferred。 MAX_DEPTH=32 cap は維持されるので length=0/1 packet も終端する (32 iter ぶんの CPU 浪費だけ、 infinite loop ではない) — 正しさ問題ではなく polish 項目。 コメントは `parser_trail.go::emitVariableTrail` 内に残置。

**Regression test (`TestTCPMalformedUnknownOptShortLength` in `dsltest/runner_test.go`、 commit 56664ac8 で land + e2e80851 で table-driven 集約)**: hand-rolled malformed TCP packet (kind=99, length=0/1) を eth/ipv4/tcp filter に通す table-driven test (LengthZero / LengthOne 2 subtests)、 `prog.Test()` が timeout / panic せず完走することを確認。 verdict は pin しない (R3 がどの byte に landing するかで match / reject が分かれうる) が、 **完走そのもの**を MAX_DEPTH cap への依存として lock-in。

**security analysis**: malformed packet が MAX_DEPTH 終端で R4 が garbage 位置に landing → 後続の where 評価が誤った byte を読む可能性 (例: `tcp.dport == 443` が garbage と比較)。**ただし** real-world TCP packets で length=0/1 unknown option は実質存在せず、誤分類は起きても system compromise にはならない。filter logic の "soft" 仕様として受容。

**今後の道筋**: BPF verifier 側の改善 (kernel 6.20+ で state-ID coalescing が入る等) があれば再評価。kunai 側からの解決策は現状なし。

**class 化**: 本 entry が指す問題は **「new branch in bpf_loop callback → scalar-ID inflation」 fingerprint の class** の 1 instance であって、 単独の TCP unknown_opt 固有問題ではない。 同 fingerprint で発火した過去事例:

- **B-2a (本 entry)**: tcp.p4 `parse_unknown_opt` の length>=2 guard
- **B-4 R1 contingency**: TCP SACK の `extract(sack); pkt.advance((sack.length - 2) << 3)` の JLT+Sub combo → `eth/(ipv4|ipv6)/tcp` で 1M insn 超過 → dispatched-but-not-extracted shape へ pivot
- **B-4a R1 contingency**: IPv4 RR 同型問題 → 同じ pivot
- **B-2a-2 het-alt × TLV-walk multi-kind cascade (kernel 6.12)**: `eth/(ipv4|ipv6)/tcp where tcp.options.MSS.value == 1460` が kernel 6.12 (May 2026 ci-kernels image 以降) のみで 1M insn 超過 (62K total_states, 565 peak)。 het-alt が 2 path に膨らんだ predecessor 状態 + tcp.p4 `parse_options` が宣言済 8 kind を全部 inline cascade すると、 6.12 stricter scalar-ID coalescing が kind 毎の per-iter scalar を merge せず探索コスト爆発。 6.1 / 6.6 / 6.18 では merge する。 → mitigation (d) で対応

4 件全部 **callback 内 (または callback predecessor 状態) に divergent scalar が残ると MAX_DEPTH × scalar-ID が verifier 探索を爆発させる** という共通の構造的制限。 systemic mitigation:

- **(a) compile-time callback branch-count assertion ✅ landed**: `pkg/kunai/codegen/callback_lint.go::assertCallbackComplexity` (閾値 + rationale はファイル冒頭の comment block を参照)。 hook は `genBpfLoopCallback` (chain) + `emitSelfLoopCallback` / `emitMultiStateCallback` (parser-machine self-loop) の callback emit 末尾。 boundary tests は `callback_lint_test.go`。 「callback 内に新 branch を追加する codegen regression」 を catch する (= B-2a / B-4 R1 / B-4a R1 family)
- **(b) callback 内 length-guard 専用 emit pattern**: lookahead-driven advance を専用関数化、 個別 site が同じ shape を再発明しないよう強制 (未着手、 1.0 後)
- **(c) codegen fuzzer in CI**: ランダム vocab + ランダム where で生成した program を 4-kernel matrix verifier に投げ、 1M insn 超を回帰検出 (未着手、 1.0 後)
- **(d) demand-driven kind-cascade elision ✅ landed**: TLV-walk multi-state dispatch (TCP options / IPv4 options) で、 query が参照しない aux を extract する case を default (parse_unknown_opt-equivalent な lookahead-driven advance) へ畳む。 `pkg/kunai/codegen/parser_loop.go::caseRedundantWithDefault` が dispatch loop で per-case 判定し、 `emitMultiStateDispatch` (1-key) と `emitMultiStateCounterKindDispatch` (2-key) 両方で elide。 elision 条件は **4 件すべて成立**: (1) target sibling が manual advance / counter op を持たず extract のみ、 (2) いずれの extract も `IsStackPush` でない (= `<stack>.next` への push は side effect なので保護)、 (3) extract した aux が `queriedOptions` に無い、 (4) default sibling が parse_unknown_opt-equivalent (zero extract + 1 lookahead-driven advance) である。 EOL (target=accept) / NOP (literal advance) / queried kinds / SACK 系の dispatched-but-not-extracted shape (no extract → 条件 (1) 違反でなく、 条件 1 の対偶: extract がない target はそもそも対象外、 = B-4 R1 / B-4a R1 と互換) は条件を満たさず常に emit される。 B-2a-2 fingerprint を構造的に解消: TCP options 1-query (MSS のみ) で per-iter cascade が 8 case → 4 case (EOL/NOP/MSS+SACK/default) に縮小、 het-alt 2× factor を吸収。 unit test は `pkg/kunai/codegen/parser_loop_elision_test.go::TestTLVWalkCascadeElidesUnqueriedKinds` で kind-byte JNE.Imm immediates を直接 walk、 queried kind の生存と unqueried-extract-only kinds の elide を atomic に pin (vocab-independent)。 vocab 側 invariant guard は `pkg/kunai/vocab/cascade_elision_invariant_test.go` (commit 3 で追加)。

dispatched-but-not-extracted shape (B-4 / B-4a で確立) が現状の workaround、 owner-bound stack `OwnerOption != ""` 時に適用。 invariant test `pkg/kunai/vocab/owner_bound_invariant_test.go::TestOwnerBoundStacksUseDispatchedButNotExtracted` で「owner aux 状態に Extract op がない」 を pin、 将来の revert を CI 検出。

### B-3. CIDR / IPv4 / MAC literal を aux field に ✅ landed

**動機**: §B PR-A〜D で integer 比較の aux access は通ったが、IPv4 / IPv6 / MAC / CIDR literal を aux 経由で比較するパスは `ErrNotImplemented` で bail していた。

**完了 (2026-05-04, commit 6547a42)**: 1 PR で 6 gate sites (predicate.go の 5 emit 関数 + where.go::genLiteralCompare の CIDR branch) を解除。新ヘルパー `auxLoadEmitter` (codegen.go) が aux mode 4 種 (single / static-stack / dynamic-stack / owner-bound static) の addressing を unify、prelude + loadAt closure を返す。

新 DSL 表現:

```
where srv6.segments[0].addr == fc00::/16              # IPv6 CIDR + 静的 stack
where any(srv6.segments.addr == 2001:db8::/32)        # IPv6 CIDR + iter (rebind)
where ipv4.options.RR.addrs[0].addr == 10.0.0.1       # owner-bound + IPv4 literal
where any(ipv4.options.RR.addrs.addr == 192.168.1.1)  # owner-bound + iter
```

**設計の肝**:
- 多 byte 比較は `R5 = element-start` を 1 度計算 + `LoadMem(R3, R5, FieldByteOff+chunkOff, size)` を chunk 毎に発行。dynamic stack は既存 `emitDynamicStackAddress` 流用、owner-bound は slot 値 + sentinel + scalar narrowing 経由 (`boundedScalarLoad` で R3.umax を ScratchBufSize-relative に pin、verifier-safe)。
- IPv6 multi-chunk で `cmpRegEqU32` が R5 を clobber するのを避けるため、aux path は `R2` を mask/host scratch に。
- where path の `genLiteralCompare` 入口で owner-bound 検出 → `genOwnerBoundLiteralCompare` (5 literal kind 全対応)。CIDR aux gate は単純削除、既存 `whereLiteralFieldOffset` の fold が static / single aux を吸収。dynamic stack CIDR は新 `genDynamicCIDRv4 / v6`。

**残スコープ**: なし (本 entry は完了)。

### B-4. Option 内部 array (SACK.blocks / RR.addrs) ✅ TCP SACK landed

**動機**: §B PR-D は TCP options を Schema A/B (固定フィールド + 単発) に絞った。SACK は `{left, right}` ブロックの配列 (Schema C)、IPv4 RR は IP アドレスの配列。これらにアクセスするには option 内部 array に `[N]` index と `any/all` を効かせる必要あり。

**完了状況 (TCP SACK, 2026-05-04)**: 4-PR で landed。

| # | scope | commit |
|---|---|---|
| PR-1 | vocab infra: `HeaderStack.OwnerOption` + `OffsetAfterOwner` 自動 bind loader | c97a0ba (+ c665512 simplify) |
| PR-2 | tcp.p4 SACK declare、R1 risk 発火 → dispatched-but-not-extracted aux 設計に pivot | a4375c1 |
| PR-3 | resolver 5-part path + 静的 index codegen (`tcp.options.SACK.blocks[N].field`) | 0cba890 |
| PR-4 | any/all 量化子 (static unroll, owner-slot 経由 count source) | 51f9992 |

**設計の肝**:
- SACK aux は **declared-but-not-extracted**: parse_sack は extract せず lookahead-driven advance のみ。slot prelude が dispatch case kind=5 で SACK の per-packet base を slot に記録、predicate codegen は slot+0/+1/+2 で kind/length/blocks を読む。
- 初回試行は `extract(sack); advance((sack.length - 2) << 3)` の AdvanceOpField 形だったが、bpf_loop callback 内に JLT+Sub combo (B-2a と同種) を入れると het-alt chain (`eth/(ipv4|ipv6)/tcp`) で 1M insn 上限超過。pivot で完全回避。
- `dynamicAuxMaxSlotsPerLayer` は **4 → 5** (8 ではなく conservative 増分: `eth/ipv4/udp/gtp/ipv4/tcp` chain で TCP at pos=5 を維持)。

**残スコープ**:
- **PR-5 (動的 index, 低優先 / staged)**: `tcp.options.SACK.blocks[<dyn-byte>].left` 形。TCP に dynamic byte source (IPv4 IHL のような primary-byte で blocks 数を数えるパターン) なくテスト難。SACK の場合「length byte」が動的だが、これは count の参照であって index ではない。需要が出た時に再検討。

### B-4a. IPv4 Record Route follow-up ✅ landed

**動機**: B-4 が TCP SACK で internal array 機構を入れたので、同じ枠組みで IPv4 RR (kind=7, 1..9 アドレスのリスト) を declare すれば addrs[N] / any/all アクセスを得られる。

**完了 (2026-05-04)**: 2 PR で landed。

| # | scope | commit |
|---|---|---|
| PR-2 | `pc.decrement(<aux>.<field>)` field-expr (parser + types + loader + codegen) | 69cc697 |
| PR-3 | ipv4.p4 RR declare + R1 contingency 発火で `pc.decrement` lookahead-form 追加 | b17d1c5 |

**経緯**:
1. 計画段階: `extract(rr); pc.decrement(rr.length); pkt.advance((rr.length-3) << 3); transition walk;` の Router Alert 同型 shape を見込み。可変長対応のため `pc.decrement` を field-expr (`<aux>.<field>`) 受理に拡張 (PR-2)。
2. 実装すると **R1 risk 発火**: trailing `pkt.advance((rr.length - 3) << 3)` が AdvanceOpField + Base=3 → MinimumTotal=3 → JLT+Sub combo を bpf_loop callback で emit、`where ipv4.options.RR.kind == 7` で 1M insn 越え。B-2a / SACK v1 と同種パターン。
3. **Contingency pivot**: `pc.decrement` を lookahead-form (`(bit<8>)pkt.lookahead<bit<16>>()[7:0]`) も受理するよう拡張、parse_rr を **dispatched-but-not-extracted** 化。両 op が同じ lookahead window から length byte を読み、R3 を消費せず option 全体を advance。

**設計の肝**:
- `pc.decrement` 3-template (literal / field-expr / lookahead) → `CounterCallStmt` + `CounterOp` に sum type fields。
- `auxLoadEmitter` の owner-bound prelude 修正: R5 は SCALAR (slot+elemOff)、loadAt は per-chunk で `boundedScalarLoad` 経由 (R3.umax ≤ ScratchBufSize 確保で verifier-safe)。
- `stackCountSource` の ByteOff: `OffsetAfterOwner-1` (SACK 偶然マッチ) → 固定 `1` (RFC 標準 length byte 位置 / TCP 9293 + IPv4 791 共通)。RR (OffsetAfterOwner=3) で破綻していた count 計算を修正、SACK regression なし。

**新 DSL 表現** (B-3 と組合せ):

```
where ipv4.options.RR.kind == 7
where ipv4.options.RR.addrs[0].addr == 10.0.0.1
where any(ipv4.options.RR.addrs.addr == 192.168.1.1)
```

**工数**: 計画時 1.5-2 d (再見積もり) → 実績 R1 contingency 込みで 1 d (PR-2) + 1 d (PR-3)。

### B-6. cw `?` (NO_CHECK optional) codegen 未実装

**動機**: parser_test / resolve_test で `eth/mpls+/cw?/eth@inner/ipv4/tcp` チェーンが parse + resolve まで通っているが、 verifier load を試行すると codegen が `optional "cw" with no-check dispatch cannot detect absence` で reject する。 cw は MPLS PW で deployment 次第で挿入される 4-byte marker (RFC 4385)、 NO_CHECK dispatch なので runtime には「next 4 bytes が cw か inner header か」 を判定する手段がない。

**現状**: codegen 未対応。 `cw?` を含むチェーンは parser/resolver は通るが verifier load 不可。

**スコープ**: 「heuristic で cw 有無を判定」 (例えば first_nibble == 0 を check) を codegen が実装するか、 `cw?` を fixed `cw` (= 必ず付いてる前提) に縛る。 RFC 4385 仕様上 first_nibble は 0 が typical (= `0x0_`) なので heuristic は実用上動く。

**工数**: 0.5 d (heuristic peek emit + parser_machine 連動)、 別 PR。 当面 cw を含む chain は表現可能だが load 不可、 doc 上明示。

## P3: コード負債 / Sanity 系

### 11. Self-validating self-dispatch chain ❌ 不要 (= 設計の wrong question だった、layered dispatch で代替)

**当初の動機**: chain self-dispatch (`+` `*` `{N,M>1}`) は `<SELF>_<SELF>_<FIELD|NO_CHECK>` const を要求。 self-validating protocol (ipv4/ipv6/srv6) を chain したい場合 (`ipv4+` の IPIP tunnel 等) はその const がなく `ErrNotImplemented` で reject される。

**着手 → revert の経緯 (2026-05-04 〜 2026-05-05)**:

1. parser machine の start state `transition select` から `(byteOff, mask, shift, expected)` を合成する synth path を実装。 `eth/ipv4+/tcp` / `eth/ipv6+/tcp` の compile + verifier 通過まで land。
2. simplify pass + OCR multi-agent review で **silent miscompile** が判明: chain emit は per-iter 固定 hs (= primary header size) で advance するため、 ipv4 で IHL>5 (options 持ち) や ipv6 で chained iter に ext header があると R4 がずれて誤分類する。
3. doc-only warning vs codegen refuse vs IHL guard 案を検討するも、 そもそも問いを取り違えていたことが判明。 実用 IPIP は **常に 2 段固定** (RFC 上も推奨)、 N 段 IPIP は実存しない → chain 量化詞 (`+`) は不要。
4. **解** = layered dispatch: ipv4.p4 / ipv6.p4 に **1 行ずつ const 追加** で `eth/ipv4/ipv4/tcp` / `eth/ipv6/ipv6/tcp` が書ける。 各 layer は独立に parser machine が走るので IHL>5 / ext header も正しく handle される (silent miscompile クラスが消滅)。
5. synth chain の全コード (180 行 + tests + builder + doc) を revert、 layered dispatch を land。

**Land 内容 (2026-05-05)**:

- `pkg/kunai/protocols/ipv4.p4`: `const bit<8> IPV4_IPV4_PROTOCOL = 4;` (IANA "IPIP" 番号)
- `pkg/kunai/protocols/ipv6.p4`: `const bit<8> IPV6_IPV6_NEXT_HEADER = 41;` (IANA "IPv6" tunneling 番号)
- `pkg/kunai/dsltest/builders.go`: `BuildEthIPIPTCP(t, IPIPOpts{InnerOptions: ...})` / `BuildEthIPv6inIPv6TCP(t)` を gopacket で組み立て
- `pkg/kunai/dsltest/runner_test.go::TestIPIPLayered` / `TestIPv6inIPv6Layered`: IHL=5 + IHL=6 (Router Alert option) inner、 reject 系を含む
- `internal/program/load_dsl_test.go`: 4 kernel matrix に `eth/ipv4/ipv4/tcp` / `eth/ipv6/ipv6/tcp` 追加

**結論**: `<SELF>_<SELF>_<FIELD|NO_CHECK>` const を必要とする chain self-dispatch (本 entry の当初動機) は設計として誤っていた。 N 段 tunneling は実存せず、 1-2 段 tunneling は layered dispatch で表現可能 + 各 layer の parser machine が独立に走るので可変 trailer も正しく handle される。 chain 量化詞 (`ipv4+` 等) を self-validating protocol に対して書く意味は無い。

## P3.5: 型システム関連 follow-up (`dsl-types.md` から派生)

### F2. 明示 cast 構文 ⏸ negative spec

`dsl-types.md §5.5` で「**入れない**」と決定。F1 (overflow lint) が landed したので overflow ケアの代替も既に提供済。需要が出たら再検討する保留枠として残置。

### F5. `Int<128>` arith binop (`*`) ❌ 廃止

scope outside と判断。F11 bit-slice (`field[lo:hi]`) で「128bit 同士の比較 / prefix 抽出」を可能にしたため、ipv6 同士の乗算は実用 scenario が見当たらない。bit-slice の方が prefix/suffix 比較で広く使えるため。

### F8. `field has FLAG` 実装 ✅ F6 で superseded

F6 の bitwise `&` で `tcp.flags & 0x12 == 0x12` と書けるようになり、専用 emit は不要。vocab 著者が flag 定数を declare するかどうかは vocab 設計の自由。

### F15. `action` atom の semantic 一般化 + TC adapter ✅ landed (2026-05-05)

**動機**: 現状 `action` atom + `Capabilities.Action` の API は "XDP retval" を念頭に設計されてる感がある (XDP_DROP/XDP_PASS 等の名前)。 本質は **「host のパケット処理完了状態を保持する 1 register」をフィルタする機能** で、 TC verdict / socket filter verdict など他 host も同じ atom 名 (`action`) で expose できるべき。

**Land 内容**: kunai 側の API は **無変更** (`Capabilities.Action map[string]int32` のまま)、 TC 側だけ揃えた:

- `pkg/kunai/host/tc/tc.go` (新): `host/xdp/xdp.go` の peer。 `Actions` map (TC_ACT_UNSPEC..TRAP の 10 verdict)、 `FexitFetcher()` (XDP と同じ tracing args ABI = `R10[-48]+8`)、 `FexitCapabilities()`。 BPF tracing args ABI が host type 非依存なので EmitFetch ロジックそのまま流用、 違いは Action map の値だけ
- `internal/program/program.go`: `loadPacketPointers(progType)` を host-aware 化、 `compileFilter(progType)` で adapter dispatch、 `captureWithXdpOutput(progType)` で `bpf_xdp_output` (XDP) / `bpf_skb_output` (TC) を切替
- `internal/program/skbuff_btf.go` (新): kernel `struct sk_buff` の `data` / `len` member offset を runtime BTF resolve (`btf.LoadKernelSpec()`)。 TC tracing context の args[0] は **`__sk_buff` ではなく kernel `struct sk_buff *`** で、 BPF rewrite が効かないため member offset の動的解像が必要 (kernel version で動く)
- `internal/attach/attach.go`: `FindBPFProgramByID` 新規 (XDP/SchedCLS/SchedACT を accept)、 `FindXDPProgramByID` は wrapper 化 (XDP 限定 type check 維持)
- `cmd/xdp-ninja/main.go`: `--mode tc-entry` / `--mode tc-exit` 追加、 TC は `-p <prog-id>` 必須 (interface-based clsact qdisc walk は out of scope)
- `internal/program/load_dsl_test.go`: `TestBpfEntryWithDSLFilterTC` / `TestBpfExitWithDSLFilterTC` 追加。 entry 側は kunai 9 chain pattern (eth/ipv4/tcp、 IPIP layered、 vlan+ 等) で TC context loading の host-aware path を pin、 exit 側は `where action == TC_ACT_SHOT` で TC verdict atom を pin

**out of scope (follow-up)**:
- TC interface-based auto-detect (clsact qdisc walk + filter chain enum) — production 用は -p 指定で十分
- TC integration test (`make test-integration` の TC 版、 veth + tc qdisc + dummy classifier)
- TC-specific context atom (`where skb.mark == X` / `where skb.queue_id == Y`) — F15 で却下した「multi-atom registry」 案
- `--mode auto` (program type 自動判別)

**やらないこと (= F15 当初から明示)**:
- `Capabilities.Atoms map[string]Atom` 的 multi-atom registry — DSL は packet header 読み + 完了状態 overlay の 2 軸に絞る

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

## R15 / R16 follow-up (future、 2026-05-15 ユーザ提案)

`--bench-drop` (XDP_DROP) で kernel netif bypass、 microburst stress 下で 32× capture rate up を実証。 paper §6 で「pure capture pipeline capacity」 measurement として記載予定。

ユーザ提案の **ringbuf reserve fail 時の cross-shard retry**:

```c
slot = bpf_ringbuf_reserve(inner_maps[cpu_id], size, 0);
if (!slot) {
    for (i = 1; i <= N_FALLBACK; i++) {
        u32 alt = (cpu_id + i) % numCPUs;
        slot = bpf_ringbuf_reserve(inner_maps[alt], size, 0);
        if (slot) break;
    }
}
```

**評価**: R15 実証で「**ringbuf overflow が真因の場面は稀** (XDP_DROP で消える)」 が判明、 retry idea は ROI 低い。 paper v1.1 / future work で検討。 もし implement するなら:
- BPF verifier に複数 map lookup OK か確認 (loop unroll で N_FALLBACK = 2-4 程度に絞れば pass)
- cross-CPU write の cache line bounce cost を `perf stat` で実測
- consumer-side で「自 CPU 以外の shard も読む」 ロジック追加 (currently 1:1 mapping)
