# Decisions

Behaviours that `docs/ja/dsl-types.md` §13 leaves undefined, and how the Lean
spec resolves them. "現行 Go 実装の挙動" was measured on 2026-10-01 with
`kunai.Compile` / `dsltest.Runner` under root (XDP, zero `Capabilities`),
on the commit this file was added in. Vector ids refer to `Kunai/Vectors/*.lean`.

Status values: 提案中 (implemented as recommended, awaiting sign-off) /
承認済 (date).

One entry per open point, numbered `D-NNN`. Each records the question, the
candidates, what the Go implementation does today (with the test or code that
shows it), the recommendation, the status, and where the decision is reflected.
Entries are never deleted; a rejected candidate stays in the log.

## D-001: quantifier 途中の predicate 失敗
- 論点: `mpls[label==5]{1,8}` で 2 回目の反復の predicate が false のとき、(a) そこで反復を止め k=1 で成功、(b) layer 全体 ✗。§13.5 [E-Quant-Range-Step] の停止条件は dispatch miss / bounds のみで predicate 失敗を含まない。
- 候補: (a) 停止して k 反復で成功 / (b) ✗
- 現行 Go 実装の挙動: **経路により異なる。** 静的 unroll (`{1,3}`, m ≤ 4) は (b): `eth/mpls[label == 5]{1,3}/ipv4/tcp` にラベル 5,6,7 → reject。bpf_loop 経路 (`{1,8}`, `+`) は predicate を **初回反復にしか適用しない**: 同じパケットで `{1,8}` → accept、`[label == 6]{1,8}` → reject、`[label == 7]{1,8}` → reject。(a) でも (b) でもない。`codegen/chain.go:83-133` vs `codegen/bpfloop.go`。
- 推奨: (b)。predicate は「その layer のすべてのインスタンスが満たすべき条件」と読むのが `vlan[tci==100]?` の既存挙動 (`vlan_tagflex_test.go:42-54`) と整合する。bpf_loop 経路は issue として報告する (Go の挙動は変えない)。
- 状態: 承認済 (2026-10-01)
- 反映先: `Eval/Layer.lean` `iterate` (`.error .pred => throw e`), vectors `quant-pred-mid-fail`, `quant-pred-mid-fail-static`, `quant-pred-first-fail`, `quant-pred-all-hold`

## D-002: greedy / バックトラック無し
- 論点: `eth/mpls{1,8}/mpls/ipv4` は greedy なら決してマッチしない。仕様として確定するか。
- 候補: (a) greedy 確定 / (b) バックトラック
- 現行 Go 実装の挙動: greedy。`eth/mpls{1,8}/mpls/ipv4/tcp` (3 ラベル) → reject、`eth/mpls{1,2}/ipv4/tcp` (3 ラベル) → reject (2 個消費後 ipv4 を 3 個目のラベルで parse して version 不一致)。
- 推奨: (a)。BPF で backtracking は現実的でなく、§13.5 の k の決め方 (最初の失敗で停止) も greedy を含意する。resolver に到達不能警告を出す issue を起票する。
- 状態: 承認済 (2026-10-01)
- 反映先: `Eval/Layer.lean` `iterate`, vectors `quant-greedy-unreachable`, `quant-range-greedy-overrun`

## D-003: 不在レイヤの field 参照
- 論点: `eth/vlan?/ipv4 where vlan.tci == 10` で vlan が無いとき。
- 候補: (a) 比較 (atom) は false / (b) filter は reject / (c) 型エラー
- 現行 Go 実装の挙動 (2026-10-01 時点): **コンパイル時 `ErrNotImplemented`** ("where-clause field on quantified layer" / "past quantified layer")。→ PR #126 で実装 (`TestCompileWhereOnQuantifiedLayers`, `dsltest/absent_layer_test.go`): 量化 layer は entry slot に「不在」または最後の instance の開始を記録し、where の atom は slot が不在なら false へ飛ぶ。`eth/vlan?/ipv4/tcp where tcp.dport == 80` は通る (ipv4 が可変長 slot 境界になるため)。`README.ja.md:18` の例 `eth/mpls{1,8}/ipv4/tcp where ipv4.total_length > 100` は当初コンパイルできなかった (例を差し替え済) が、この実装で通るようになった (`TestCompileWhereOnQuantifiedLayers`)。
- 推奨: (a)。atom 単位で false にする。(b) は `not (vlan.tci == 1)` を書けなくし、(c) は実装制限を仕様に昇格させる。ユーザー決定 (2026-10-01): 仕様は純粋に書き、Go の制限は vector の `goStatus: notImplemented` で表す。注意: `not (vlan.tci == 1)` は不在時に true になる。
- 状態: 承認済 (2026-10-01)。不在時の真理値表:

  | パケット | `vlan.tci == 10` | `vlan.tci != 10` | `not (vlan.tci == 10)` |
  |---|---|---|---|
  | vlan あり、tci=10 | true | false | false |
  | vlan あり、tci=20 | false | true | true |
  | vlan なし | false | false | true |

  無い layer への比較はどの演算子でも false。「あって tci≠10」は `!=`、「無いか、あっても≠10」は `not (==)` と書き分ける。
- 反映先: `Eval/Where.lean` `loadField` (`none`), `evalWhere` `.arith`/`.litCmp` (`| pure false`), vectors `where-absent-layer-false`, `where-absent-layer-not`, `where-past-quantified-ok`

## D-004: alternation の順序と重なり
- 論点: `(vlan|qinq)` で両方の dispatch が一致するとき先勝ちか。alt 枝の同サイズ制約 (§11, T-LayerAlt) が何を保証するか。
- 候補: (a) 先勝ち commit (後続枝は試さない) / (b) 一意一致を要求 / (c) 失敗時に次の枝を試す
- 現行 Go 実装の挙動: (a)。`eth/(vlan|qinq)/ipv4/tcp` と `(qinq|vlan)` はどちらも vlan パケットに accept、`(vlan[tci == 200]|qinq)` は tci=100 で reject (predicate 失敗後に qinq を試さない)。同一 proto を 2 枝に書く `(ipv4[ttl == 1]|ipv4[ttl == 255])` は **ロード時に "duplicate symbol" で失敗** (Go bug、issue)。同サイズ制約は `codegen/alternation.go` に無く、`dsl-grammar.md:56` / `dsl-usage.md:257` もサイズ差を許す。
- 推奨: (a)。§13 に [E-Layer-Alt-First] を追加し、T-LayerAlt の uniform-size 制約は削除する (dsl-types.md 修正提案)。
- 状態: 承認済 (2026-10-01)
- 反映先: `Eval/Layer.lean` `evalAlt`, vectors `alt-first`, `alt-second`, `alt-none`, `alt-first-pred-fails` (Go のラベル衝突は `fix/kunai-spec-conformance` で修正済)

## D-005: `?` の skip 条件と Range-Step の停止条件
- 論点: [E-Quant-Optional] case B は dispatch miss だけを skip にしている。dispatch は一致するが bounds で L(1) が失敗する場合は skip か ✗ か。また [E-Quant-Range-Step] は bounds 失敗を停止条件に含めているため、文字どおりだと `?` ≢ `{0,1}` になる。
- 候補: (1) 仕様書どおり非対称のまま (`?` は ✗、`{0,1}` / `*` は k=0 ✓) / (2) Range-Step の停止条件から bounds を外し、すべての quantifier で「skip / 停止は dispatch miss のみ、bounds 失敗は ✗」に揃える
- 現行 Go 実装の挙動: **経路により異なる。** `eth/vlan?` も `eth/vlan*` も eth + vlan 2 バイトのパケットを reject (`codegen.go:1040-1062` は親の dispatch field だけを peek し、以後の bounded load 失敗は `dslReject`)。一方 bpf_loop 経路は反復途中の bounds 失敗を「そこで停止」と扱う: `eth/mpls{1,8}` に 2 個目のラベルが 2 バイトで切れたパケット → accept (k=1)。`{0,1}` は `ErrNotImplemented`。案 1 でも案 2 でも Go のどちらかの経路とは食い違う。
- 推奨: (2)。dispatch が一致しているのにヘッダが壊れているパケットを accept するのは説明できず、Go の実測とも一致し、`?` ≡ `{0,1}` が定理になる。
- 状態: 承認済 (2026-10-01、案 2)
- 反映先: `Eval/Layer.lean` `iterate` (bounds は `throw`), `Laws.lean: opt_eq_range`, vectors `quant-opt-bounds-reject`, `quant-range01-bounds-skip`, `quant-star-bounds-skip`, `quant-range-truncated-mid-chain`, `dsl-types.md` §13.5

## D-006: 切り詰めパケットと where
- 論点: chain は通ったが where の field が packet 末尾を越える場合。
- 候補: (a) reject / (b) false
- 現行 Go 実装の挙動: reject (`ranged_predicate_test.go:20` "truncated TCP predicate field")。Phase 2 の範囲 (primary field のみ) では chain の bounds 検査が先に効くため到達不能。
- 推奨: (a)。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Where.lean` `loadField` (`throw .reject`)。vector は Phase 5 (aux field) で追加

## D-007: `any` / `all` の空 stack
- 論点: §13.8 注記どおり any → false, all → true。
- 現行 Go 実装の挙動: 同じ (`dsl-types.md:1136`, §6.5)。
- 推奨: 採用。空 stack は「layer はあるが要素が 0」のとき。layer 自体が無い (skip された optional) ときは D-003 と同じく `any` も `all` も false (vector `srv6-all-absent-layer`)。
- 状態: 承認済 (2026-10-01、一括) (実装は Phase 5)
- 反映先: `Eval/Where.lean` `evalWhere` `.any`/`.all`

## D-008: host により意味が変わる箇所
- 論点: `packetStartsAtL3` のとき `eth` root は警告だが reject ではない。Lean ではどう扱うか。
- 候補: (a) illTyped / (b) バイト列上で評価して結果に任せる
- 現行 Go 実装の挙動: 警告のみ。`Compile("eth/ipv4", {PacketStartsAtL3: true})` はエラーなし。
- 推奨: (b)。警告は意味論の外。cursor 0 から評価し、L3 パケットに `eth` を当てれば普通に reject される。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval.lean` (host は dispatch に関与しない), vectors `host-l3-ipv4-root`, `host-l3-eth-root`
- 追記 (2026-10-03): `vlanInMetadata` の host で必須の `vlan` layer (alternation の枝を含む) は illTyped。Go も `ErrNotImplemented` ではなく型エラーを返すようにした (`codegen.ErrVlanInMetadata`、vectors `host-tc-vlan-mandatory`, `host-tc-vlan-alt*`, `host-tc-qinq-vlan`)。追記 2 (2026-10-05): 規則を `qinq` にも広げた (`Host.tagInMetadata`)。kernel の `skb_vlan_untag` は 802.1Q と 802.1ad の外側 tag を同じように metadata に移すので、byte 列に無い理由は両者で同じ。Go も必須の `qinq` を `ErrVlanInMetadata` にした (vectors `host-tc-qinq-mandatory`, `host-tc-qinq-optional`)。

## D-009: 算術の幅 (定数同士)
- 論点: `mod 2^max(width(e₁), width(e₂))` の width が定数由来のとき。
- 候補: (a) 64 / (b) 文脈 (兄弟 operand) の幅、無ければ 64
- 現行 Go 実装の挙動: 定数は兄弟 field の幅で fit-check される ("value 256 does not fit in bit<8> (in arithmetic context)")。定数同士は fold (`300 > 200` → true)。`-1 == 255` は `ErrNotImplemented` (int32 immediate)。
- 推奨: (b) を narrow (fit check) に使い、演算自体は D-015 により 64 bit。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Where.lean` `sideWidths`, `evalArith` `.const`, vectors `typ-literal-fit`, `typ-literal-fit-arith`, `where-const-fold`

## D-010: alternation の評価規則が §13 に無い
- 論点: §13 には `alt(L̄)` の E-rule が無い (T-LayerAlt のみ)。
- 推奨: [E-Layer-Alt-First] を追加 (D-004)。枝は field dispatch 必須 (NO_CHECK / self-validating 枝は illTyped)、quantifier 不可、root 不可 (いずれも Go の `validateAlternatives` と同じ)。
- 状態: 承認済 (2026-10-01)
- 反映先: `Eval/Layer.lean` `evalAlt`, vector `alt-root-illtyped`

## D-011: bracket `in` の規則が §13 に無い
- 論点: §13.7 は [E-Pred-Cmp] のみ。`in [v…]`, `in @set`, `range` の規則が無い。
- 現行 Go 実装の挙動: `in [80, 8000..8080]` は `ErrNotImplemented` (range) だった → PR #130 で実装 (host order に揃えて `lo ≤ v ≤ hi`、両端は resolver が field 幅で fit-check)。`in @set` は SetSlots が要る。
- 推奨: `in [v…]` = いずれかの v と `==`。range は `lo ≤ n ≤ hi`。`in @set` は D-036。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Layer.lean` `evalPred`, `Eval/Check.lean` (range の両端が field 幅に収まる、lo ≤ hi), vectors `pred-in-list`, `pred-in-range`, `pred-in-range-miss`, `typ-pred-in-range-wide`

## D-012: Phase 2 のプロトコル簡略化
- 論点: vocab を手で写す際に落としたもの。
- 内容: ipv6 拡張ヘッダ (next_header ∈ {0,44,60} で Go は `ipv6_ext_h` を walk し cursor が進む)、ipv4 options の kind 検査 (Go は EOL/NOP/RR/RA 以外を reject; Lean は IHL 分を読み飛ばすだけ)、tcp options の walk (Go は MSS/WS/SACK/TS の length 検査で reject しうる)、srv6/gre/gtp/geneve/qinq/esp/icmp。vector はこれらを踏まないパケットだけを使う (ipv4 options は NOP、tcp options は NOP)。
- 状態: 承認済 (2026-10-01、一括) (Phase 5 で解消)
- 反映先: `Vocab.lean`

## D-013: 同一 proto が複数ある chain での無ラベル参照
- 論点: `eth/ipv4/ipv4/tcp where ipv4.ttl` や `eth/mpls{1,8}/… where mpls.label` の解決。
- 現行 Go 実装の挙動: 静的重複は "protocol is ambiguous (2 instances); qualify with an @label"。量化 layer は D-003 の `ErrNotImplemented` だった → PR #126 で `lookupByQualifier` が上限 ≠ 1 の量化 layer を複数扱いにし、同じ ambiguous エラー (vector `where-repeated-unlabelled`)。
- 推奨: 静的に 2 個以上になりうる (重複、または上限 ≠ 1 の quantifier) なら illTyped。ラベルは `Λ ⊕ {ℓ ↦ inst}` どおり最後の束縛が勝つ。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Where.lean` `staticCount`, `resolveRef`, vectors `where-ambiguous`, `where-label-inner-outer`

## D-014: shift 量
- 論点: `<<` / `>>` の RHS が 64 以上のとき。
- 現行 Go 実装の挙動: BPF の masked shift (64 bit ALU なので `& 63`)。`ipv4.ttl << 65 == 0` → false (= `<< 1`)。
- 推奨: `b % 64`。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Where.lean` `binop`

## D-015: 算術の wrap 幅 (§13.9 と実装の食い違い)
- 論点: §13.9 は `+ − *` を `mod 2^max(width(e₁), width(e₂))` で wrap すると書く。
- 現行 Go 実装の挙動: **wrap しない。** 64 bit レジスタで計算し定数だけ narrow する。`eth/ipv4/tcp where ipv4.ttl + 1 > 200` は ttl=255 で **true** (§13.9 では (255+1) mod 256 = 0 で false)。`ipv4.ttl + 1 == 0` → false。
- 推奨: 実装に合わせて §13.9 を「Int<64> で計算、定数は文脈幅で fit-check」に改める。BPF の自然な挙動で、per-node wrap をコード生成する利点が無い。64 bit を超える field (ipv6 src/dst) を含む算術は D-035。
- 状態: 承認済 (2026-10-01)
- 反映先: `Eval/Where.lean` `binop` (64 bit), vectors `where-arith-no-wrap`, `where-arith-ops`

## D-016: 宣言ヘッダ長が固定部より短い
- 論点: ipv4 `ihl < 5`, tcp `data_offset < 5`。
- 現行 Go 実装の挙動: reject (`ihl=4` → reject、`tcp_boundary_test.go:75` n<5 reject)。
- 推奨: reject (Fail-Pred 系統)。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Layer.lean` `extract` (`if l < spec.fixedLen then throw .pred`), vectors `chain-ipv4-ihl4`, `chain-tcp-dataoffset4`

## D-017: self-validation (parser-block reject) の失敗種別
- 論点: `select(version) { 4: …; default: reject }` の ⊥ を dispatch miss と見るか predicate 失敗と見るか (`ipv4?` の skip 判定に影響)。
- 候補: (a) 常に Fail-Pred (§14.4 の記述) / (b) 常に dispatch miss (skip) / (c) 親 const が無く自己検証が唯一の dispatch のときだけ miss、親 const があるときは Fail-Pred
- 現行 Go 実装の挙動: `eth/ipv4/tcp` に version=5 → reject。`eth/ipv4?/tcp` は **verifier で load 失敗** ("math between map_value pointer and register with unbounded min value")、issue 4。`eth/mpls/ipv4?/tcp` はコンパイルできる。
- 推奨: (c)。`mpls/ipv4?` では version が「次は ipv4 か」を判定する唯一の材料なので miss (skip) が自然。`eth/ipv4?` では ethertype がすでに ipv4 と言っているので、version≠4 は破損であり D-005 と同じく ✗。
- 状態: 承認済 (2026-10-01、案 c)
- 反映先: `Eval/Layer.lean` `dispatch` (edge 無し + `requires` を dispatch 段階で検査), `extract` (`requires`), vectors `quant-selfvalidating-skip`, `quant-selfvalidating-present`, `quant-selfvalidating-short-v4` / `-short-v6` / `-empty`, `quant-selfvalidating-cascade`, `quant-selfvalidating-broken`, `typ-no-dispatch-after-skip` (Go は親定数の無い場合、parser の entry select が要求する field を probe する), `dsl-types.md` §13.5

## D-018: quantified layer のラベル再束縛
- 論点: `mpls@m{1,8}` は反復ごとに `m` を束縛し直す。
- 現行 Go 実装の挙動: `where m.label` は `ErrNotImplemented` だった → PR #126 で実装: 静的 unroll の各反復と bpf_loop callback が entry slot を上書きし、最後の instance が残る (vectors `where-label-repeated-last`, `-first-miss`)。
- 推奨: `Λ ⊕` どおり最後の束縛が勝つ (D-013)。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Layer.lean` `extract` (labels に cons), `Eval/Where.lean` `resolveRef`

## D-019: `and` / `or` の評価順
- 論点: §6.3 は short-circuit、§13.8 [E-W-And]/[E-W-Or] は両辺評価。差が出るのは第 2 項が reject (D-006) するとき。
- 現行 Go 実装の挙動: codegen は jump による short-circuit。Phase 2 の範囲では観測不能 (primary field は chain で bounds 済)。
- 推奨: 両辺を評価するが、第 1 項で結果が決まるなら第 2 項の動的 reject は無視する (short-circuit と同じ結果)。型エラーは隠さない。
- 状態: 承認済 (2026-10-01)
- 反映先: `Eval/Where.lean` `logic`

## D-020: capture の対象 layer が不在
- 論点: `eth/vlan?/ipv4 capture vlan` で vlan が無いとき。
- 候補: (a) その capture 句だけ省く / (b) reject (D-021 と揃える)
- 推奨: (a)。`capture vlan+8 capture ipv4+8` のように複数句を並べれば「vlan があれば vlan+8、無ければ ipv4+8」が書けるので、省く方が表現力がある。Go は `?` 以降の `capture <layer>` が `ErrNotImplemented` で、実装時に再確認する。
- 状態: 承認済 (2026-10-01、案 a)
- 反映先: `Eval/Where.lean` `evalCapture` `.toLayer`
- Go (PR #126): capture 長は compile 時の上限 (全 instance がある場合、`prefixHeaderSizeUpper`)。対象 layer が無いときは句を落とせず上限分を capture する (verdict は一致、vectors `cap-absent-layer`, `cap-present-layer`)。
- 追記 (2026-10-05): alternation の member を対象にした capture (`(ipv4@a|ipv6) capture a`) も同じ規則: 別の member がマッチした packet では `a` は不在で句は落ちる。Go はここでも compile 時の上限 (その member のサイズ) を capture する。where の atom (#146 で matched-member slot を確かめるようにした) と違い capture 長は immediate なので、host 側に長さを渡す経路を変えない限り揃えられない (vectors `cap-alt-member-*`)。

## D-021: per-capture `where` の合成
- 論点: §13.6 は `gate(c, σ) = false` なら capture 句を省くだけ (verdict は変えない) と読める。`dsl-grammar.md:219` / `dsl-usage.md:217` は「filter 全体の where と AND 合成」。
- 候補: (a) gate (句を省く) / (b) AND (false なら reject)
- 現行 Go 実装の挙動: (b)。`eth/ipv4/tcp capture all where tcp.dport == 1` は dport=80 のパケットを reject。
- 推奨: (b)。grammar / usage と実装が一致しており、§13.6 の `eval-captures` を「すべての gate が true のときのみ accept」に直す。
- 状態: 承認済 (2026-10-01)
- 反映先: `Eval/Where.lean` `evalCapture` (`throw .reject`), vectors `cap-where-false-rejects`, `cap-where-true`, `syn-capture`

## D-022: `%` の 0 除算
- 論点: §13.9 は `%` の n₂ = 0 で 0 を返すとする。
- 現行 Go 実装の挙動: BPF の `MOD` 定義どおり **被除数を返す** (`tcp.dport % ipv4.ttl == 0` は ttl=0, dport=80 で false)。`/` の 0 除算は 0 (一致)。
- 推奨: BPF に合わせ `n₁` を返す。§13.9 を修正。
- 状態: 承認済 (2026-10-01)
- 反映先: `Eval/Where.lean` `binop` `.mod`, vector `where-mod-by-zero-dynamic`

## D-023: 証明できなかった等式 (Phase 4)
- `opt_eq_range` (`L?` ≡ `L{0,1}`): D-005 案 2 の採用後に **成立** (`Laws.lean: opt_eq_range`)。案 1 のままなら不成立だった。
- `alt_comm`: **不成立** (先勝ち)。`Laws.lean: alt_order_matters`。
- `and_comm_where` / `or_comm_where`: 両辺が Stop しない (reject / illTyped を投げない) という仮定付きで成立 (`Laws.lean`)。仮定なしでは D-019 の short-circuit により非対称。
- `bracket_eq_where` (`…/p[f op v]` ≡ `…/p where p.f op v`): **未証明**。両者は `cmpValue` / `narrowInt` を共有するので p が chain 内で一意・非量化・root 以外なら一致するはずだが、`extract` の Fail-Pred と `evalWhere` の false を `eval` の reject に結び付ける証明が長く、Phase 4 では見送った。vector `pred-cmp` / `where-cmp-ops` などで個別に一致を確認している。 (→ 下の追記 2026-10-03 で証明。条件はそちらが正)
- `prefix_independence` / `filterMinPrefix`: 未着手。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Laws.lean`
- 追記 (2026-10-03): `bracket_eq_where` を `Laws.lean` で証明した。主張は `evalChain` / `evalWhere` の水準で、文脈 `c` は共通: p は量化なし・他の predicate 無しで、bracket 無しの chain が `stF` で match し、p の名前が `stF` でその layer が抽出した instance を指す (chain 内で一意、label に隠されない) とき、`[f op v]` 付きの chain は where の atom `p.f op v` が `stF` で true なら同じ `stF` で match、false なら Fail-Pred。root 以外という条件は不要だった。atom が評価できない場合の報告だけが違う (bracket は自分の layer で chain を止めるので packet 末尾を越える field はその場の bounds 失敗、where は chain 全体の後)。対象は cmp predicate 1 つ。filter 全体の `eval` の等式 (2 つの filter で `c.layers` と `check` が違う) までは示していない: `staticProto` / `check` が preds に依らないことと、`staticCount = 1` から名前がその instance を指すことの補題が要る。証明のため `extract` を `extractInst` / `checkPreds` / `State.push` に分け、`resolveRest` は head と path を取らず `RefBody` (`Ref` が extends) を返す形にした。この変更で ill-typed の文言が 1 つ変わる: `unsupported: field path` は、head が label でも bracket の path (head 無し) でも protocol 名から始まる (vectors `typ-path-unsupported-deep`, `-label`, `-bracket`)。補題: `evalChain_append`, `evalChain_proto_inv`, `extract_cmp`, `litCmp_eq_evalPred`, `bracket_eq_where_at` (chain を分解した形)。
- 追記 2 (2026-10-03): filter 全体の `eval` の水準まで伸ばした (`Laws.lean: bracket_iff_where_eval`)。p は量化なし・他の predicate 無し、chain の中でその protocol の最初の layer で、p の名前を label に持つ layer が無く、名前が静的に protocol 自身に解決され (`staticProto`)、bracket の path が解決でき、両方の filter が `check` を通るとき、`…/p[f op v]/…` が accept する ⇔ `…/p/… where p.f op v` が accept する。関係付けるのは accept だけ: どちらも accept しない packet では、bracket が chain を自分の layer で止めるぶん報告 (reject / illTyped) が食い違いうる。「名前がその layer の instance を指す」は仮定ではなく導いた: chain の評価は自分の layer の protocol の instance と自分の layer の label しか状態に足さない (`evalChain_grows`)。2 つの filter の文脈を等しくするため、`Ctx.layers` を chain の shape (`Layer.shape`: bracket predicate を落としたもの) にし、`check` の predicate を見る部分は `F.layers` を受け取る形にした。仮定は全部静的で、具体的な filter では評価で閉じる (`tcp_dport_bracket_iff_where`: 任意の packet について)。残り: 片方の `check` 成功からもう片方を導くこと、reject ⇒ reject。
- 追記 3 (2026-10-03): 静的な側を証明した (`Eval/Check.lean: check_bracket_where`): bracket 形が `check` を通るなら where 形も通り、bracket の path は解決できる。これで `bracket_iff_where_eval` の仮定から「where 形の `check`」「bracket path の解決」「p がその protocol の最初の layer」が消えた (最後のものは `staticProto` が名前自身を返すことから従う: `Eval/Where.lean: staticProto_unique`)。「p の名前を label に持つ layer が無い」も仮定から外れた: `check` を通る filter の label は protocol 名ではない (`check_labels`)。残る仮定は p が量化なし・他の predicate 無し、名前が protocol 自身に解決される、bracket 形が `check` を通る、の 3 つ。証明のため `check` の loop を構造的再帰の `allOk` に書き直した (最初のエラーで止まる順序は同じ。vector は不変)。reject ⇒ reject は未着手: bracket が false のとき where 形は後続 layer の失敗に進むので、一般には成り立たない。
- 気づき: `labelProto` (静的) は alternation の member の label を見ないが、`evalAlt` は member の label を束縛し、`resolveRef` (動的) は `st.labels` を先に見る。label が protocol 名と同じだと (`eth/ipv4/(tcp@ipv4|udp) where ipv4.src == …`) 静的には ipv4、実行時には tcp の instance を読んでしまう。Go の resolver は label と protocol 名の衝突を型エラーにしているので、Lean の `check` にも同じ規則を入れて塞いだ。label の重複 (Go は `duplicate label`) も同様に型エラーにした (vectors `typ-label-collides`, `typ-label-collides-alt`, `typ-label-duplicate`)。member の label を where から参照する形 (`(tcp@x|udp) where x.dport …`) は当初 Lean では未知の名前として illTyped だった。追記 (2026-10-03): `labelProto` が alternation の member の label も見るようにした (Go の resolver は元から受け付ける)。意味は D-003 のまま: その member がマッチしなかった packet では label は束縛されず、atom は false。protocol 名で member を指す形 (`(vlan|qinq) where vlan.tci == 100`) も同じ。Go はここで食い違っていた: 同じサイズの alternation ではどの member がマッチしたかを見ずに同じ offset を読み (qinq の packet で `vlan.tci` が qinq の tci を読んで accept)、サイズの違う alternation は `ErrNotImplemented` だった。alternation がマッチした member の番号を stack slot に記録し、member を読む atom がそれを先に確かめる形に直し、サイズの違う alternation も通るようにした (vectors `where-alt-*`)。capture の対象が member の形は未対応のまま。同じ protocol の member が 2 つある alternation (`(ipv4@a|ipv4@b) where ipv4.ttl …`) を protocol 名で指すのは曖昧として illTyped (`staticCount` が member を数える。Go の resolver と同じ)。あわせて直した Go の不具合 2 件: alternation が 2 つ続く形 (`eth/(ipv4|ipv6)/(tcp|udp)`) は verifier に拒否されていた (2 つ目の group の member が、match した member の番号を初期化されない register から読んでいた。番号は slot から読むようにした。vectors `alt-two-groups*`)。`any` / `all` の body が stack の持ち主以外の不在 layer を読むと quantifier 全体が false になっていた (`all(x.f == 1 or vlan.tci == 5)`。不在はその atom だけを false にする。vectors `where-quant-other-*`)。上の定理は「p の名前を label に持つ layer が無い」を仮定に置いている。

## D-024: 上限 m に達したときの over-run
- 論点: `mpls{1,2}` に 3 段のスタック。§13.5 の Range-Step は「k = m で停止 ✓」とだけ言うが、3 段目が残ったまま次の layer (無ければ accept) に進むのは「深さ 1〜2 のスタック」という読みに反する。
- 候補: (a) k = m で無条件に ✓ / (b) chain-end を宣言する proto では m 個目のヘッダが end 信号 (MPLS s=1) を持たなければ ✗
- 現行 Go 実装の挙動: 静的 unroll (`chainEndRequire`) は (b)、bpf_loop 経路 (`+`, `{n,m>4}`) は (a) (既知の gap、`bpfloop.go` のコメント)。
- 推奨: (b)。`{n,m}` と `+`/`*` (m = MAX_DEPTH) を同じ規則にし、「サポートする深さを超えたスタックは reject」と読む。bpf_loop 側は issue。
- 帰結: `{1,1}` ≡ `1` は chain-end を持たない proto に限って成立 (`Laws.lean: one_eq_range_layer` に仮定を追加)。mpls では `{1,1}` が「スタックはここで終わる」を含意するので `mpls` と異なる (Go も同じ)。`?` ≡ `{0,1}` は `?` にも同じ要求を課して維持。
- 状態: 提案中
- 反映先: `Eval/Layer.lean` `chainEnded` / `iterate` / `extractOpt`, `Laws.lean`, vectors `quant-overrun-bounded`, `quant-overrun-open` (goStatus mismatch), `quant-exact-bound`

## D-025: 可変長 layer の長さ
- 論点: §13.4 の `total_bytes(p, P, π)` は「primary + 抽出した aux の合計」だが、tcp は EOL で walk を止めても Go は data_offset×4 まで進む。
- 推奨: `len = max(宣言長, parser machine が消費した長さ)`。宣言長は ipv4 IHL / tcp data_offset / geneve opt_len (`vocab.HeaderLength` 由来)。srv6 は machine の消費量 (= 8 + 16×(last_entry+1)) と一致。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Layer.lean` `extract`, `gen/vocab2lean` `declaredLength`

## D-026: parser machine の反復上限
- 論点: §14 は `MAX_DEPTH` の役割を定義しない。Go は bpf_loop の max_iter (self-loop は inline 1 回 + MAX_DEPTH 回) として使い、上限到達で accept する。
- 推奨: 「同じか手前の状態への遷移」を 1 反復と数え、`MAX_DEPTH` 回で accept (状態はそのまま)。ipv6 (MAX_DEPTH=4) は 5 個目まで拡張ヘッダを読み、6 個目は読まずに accept → 後続の dispatch が miss。
- 現行 Go 実装の挙動: 同じ (vector `ipv6-ext-five-at-depth`, `ipv6-ext-six-exceeds-depth`)。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Machine.lean` `run`
- 追記 (2026-10-06): Go の TLV walk (`emitMultiStateSelfLoop`: ipv4 / tcp / geneve の option) は inline の初回反復が無く、bpf_loop を `MAX_DEPTH` 回しか回していなかった (dispatch が 1 回少ない)。`MAX_DEPTH + 1` 回に直した (vectors `ipv4-opt-depth-last-dispatch-*`)。

## D-027: 抽出されなかった option / aux の field
- 論点: `tcp.options.MSS.value == 1460` で MSS が無いとき。
- 候補: (a) atom は false (D-003 と同じ) / (b) filter を reject
- 現行 Go 実装の挙動: (b)。sentinel -1 を見て `dslReject` に飛ぶため `not (tcp.options.MSS.value == 1460)` も reject。
- 推奨: (a)。D-003 と同じ理由。`.exists` で明示的に問える。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Where.lean` `loadRef`, vectors `tcp-opt-mss-absent`, `tcp-opt-mss-absent-not` (goStatus mismatch), `gtp-opt-field-absent`

## D-028: TLV walk の非前進
- 論点: unknown option の length が 0 / 1 のとき、`advance(len)` が読んだバイトを越えない。
- 現行 Go 実装の挙動: reject (`parser_region.go` の `JLT len, off+1`)。
- 推奨: lookahead 駆動の advance は「読んだバイトの先」まで進まなければ ⊥。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Machine.lean` `doAdvance`, vectors `tcp-opt-unknown-len0`, `tcp-opt-unknown-len1`

## D-029: 壊れた option 領域
- 論点: `eth/ipv4/tcp` に壊れた option (kind 不明、長さ 0、領域末尾をまたぐ) を持つパケット。
- 当初の決定 (2026-10-01): 仕様では parser machine は常に走り、⊥ なら reject。Go は option を参照しない filter では walk を省く (demand-driven) ので accept し、意図的な逸脱として mismatch のまま維持していた。
- 改訂 (2026-10-05、ユーザー決定): Go の demand-driven な扱いをそのまま仕様にすると、`where tcp.dport == 80 or tcp.options.MSS.exists` が左辺 true でも reject になる (option を「書いたかどうか」で verdict が変わる) ので採らない。代わりに、宣言された option 領域 (`lenRule` のある layer: ipv4 の IHL、tcp の data_offset、geneve の opt_len) の中で walk が ⊥ になったら、その layer は option を 1 つも持たないものとし、chain は宣言長の先へ進む。option を読む atom は D-003 / D-027 の不在と同じく false (`not (…)` は true、`any` は false、`all` は true)。途中まで見えた option も含めて全部を捨てる。宣言長そのものが不正な場合と、領域が packet に収まらない場合は従来どおり reject。
- 性質: verdict は atom が読むものだけで決まり局所的。`or` / `and` の交換則などの law はそのまま。壊れた option を弾く手段として `<layer>.options.valid` (Bool) を足した (2026-10-06、`Where.optionsValid`、`Inst.optsValid`): 宣言された option 領域を持つ layer にだけ書け (それ以外は illTyped)、layer が無ければ false。Go はこの atom があると、その layer の option を参照していなくても walk を走らせ、結果を slot に残す (vectors `tcp-opts-valid*`, `ipv4-opts-valid-malformed`, `typ-opts-valid-no-region`)。
- 反映先: `Eval/Layer.lean` `extractBody`。Go: `parser_loop.go` `emitMultiStateSelfLoop` (callback の reject を `_malformed_` landing へ: R4 を walk 入口に戻し、option slot を不在に、bulk advance で宣言長だけ進む)、`skipsRegionFaultAt` (旧 `hasDeclaredOptionRegion`)。srv6 の segment walk は宣言長を持たないので対象外 (従来どおり reject)。F10 pin 257→283。vectors `tcp-opt-malformed-*`, `ipv4-opt-malformed*`。mismatch は 0 になった。Go と仕様で option 領域を何回 dispatch するかがずれていた件 (D-026 追記) もあわせて直した。
- 追記 (2026-10-06、ユーザー決定): 「宣言された領域」を protocol 名でなく P4 の構造と annotation だけで決めるようにした。**境界が宣言された領域** = parser の loop 状態が、header から設定した counter の `is_zero()` で終わる walk (ipv4 / tcp / geneve の option、srv6 の segment)。**自己終端の chain** (ipv6 / gtp の拡張ヘッダ) は終端が歩くまで分からないので、失敗は常に reject。領域の中の失敗の扱いは parser の `@kunai_option_region[on_fault=skip|fail]` で宣言し、既定は `skip` (layer はその walk の aux を持たず宣言長の先へ進む、`.valid` で読める)。`fail` は packet を reject する。srv6.p4 は `fail` を宣言する (segment が読めない SRH は SRH として成り立たない。RFC 8754 は segment を 1 個以上要求する)。`skip` は今の実装では領域が byte 単位で数えられている (loop から出る各経路が消費した byte 数だけ counter を減らす) walk にだけ書け、そうでない walk に既定の `skip` が当たると loader がエラーで `fail` の明示を求める。判定は Go の `vocab.ProtocolSpec.SkipsRegionFault` 1 箇所にまとめ、resolver (`.valid`)、codegen (malformed landing)、spec の語彙生成 (`ProtoSpec.regionLoop`) がそこを参照する。Lean では machine の実行中に loop 状態へ入った後の reject を `MFail.regionFault` として区別し、`extractBody` はそれだけを「aux 無し」にする (header 自体の失敗はこれまでどおり reject)。annotation の値は P4 の予約語 `reject` を避けて `fail` にした。`fail` の領域は、filter がその領域を読まなくても Go は walk を走らせる (省くと壊れた領域を見落として accept し、verdict が filter の書き方に依存してしまうため。そのぶん命令数と verifier の探索は増える。aux stack の walk は再 anchor の検査が同じ失敗を reject するので省いたまま)。領域として認識するのは「select が `counter.is_zero()` で終わり、他の枝がすべて loop に戻る」multi-state loop だけで、1 状態の counter loop は今は領域ではない (失敗は常に reject)。領域の無い parser への annotation と、annotation の重複は loader エラー。spec の宣言長 (`lenRule`) は byte 単位で数えられた領域の counter の設定式からだけ作る (Go が領域の先へ進む位置と同じ式)。byte 単位でない領域 (`fail` を宣言した要素数や field 長の walk) には `lenRule` が無く、layer は machine が消費した所までになる。Go もその場合は walk の終わった位置から次へ進む。vectors `srv6-segments-truncated-fails`, `typ-srv6-segments-valid`, `geneve-version-one`。後続: srv6 の segment が stack 容量 (8) を超える正当な SRH は、入る分だけ読み、切り詰めた印を残して先へ進む予定 (stack 一般の規則として)。

## D-030: option の「視認」と重複
- 論点: `parse_sack` / `parse_rr` は `extract` せず lookahead で長さ分 advance するため、§14 の α には SACK / RR の view が入らない。しかし `tcp.options.SACK.blocks[0]` は参照できる。
- 現行 Go 実装の挙動: kind byte が一致した位置を記録する (prelude)。同じ option が複数あれば最後が勝つ。
- 推奨: lookahead key が option の kind byte と一致した時点でその option の view を cursor に置く (`OptionDecl.kindByte`)。重複は最後が勝つ。owner-bound stack (blocks, addrs) は owner の length byte から要素数を得る。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Machine.lean` `sightOptions`, `Eval/Where.lean` `stackEntries`, vectors `tcp-opt-sack-*`, `ipv4-rr-*`, `tcp-opt-mss-duplicate-last-wins`

## D-031: stack の要素数と範囲外 index
- 論点: `ipv6.exts[1]` で 1 個しか抽出していないとき、`any`/`all` の反復範囲。
- 候補: (a) 抽出した要素数 (`count(stack(σ))`) / (b) capacity
- 現行 Go 実装の挙動: count source が無い stack (ipv6.exts, gtp.exts) は capacity 8 を unroll し、静的 index は count を見ずにバイトを読む。`srv6.segments[2] != …` は範囲外で true。
- 推奨: (a)。範囲外 index は不在 → atom false (D-027)。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Where.lean` `stackEntries` / `refView`, `Eval/Layer.lean` `evalPred` (bracket も同じ規則), vectors `ipv6-exts-index-absent`, `ipv6-exts-all`, `srv6-segments-index-absent`, `ipv6-exts-bracket-index-absent`, `gtp-exts-bracket-absent` (Go は #120/#121/conformance-4 で一致)

## D-032: bracket predicate と write-back
- 論点: `ipv6[next_header == 6]/tcp` で拡張ヘッダがあるとき、predicate は write-back 前後どちらの値を見るか。
- 現行 Go 実装の挙動: 最初の extract 直後に評価するため元の値 (0)。`where ipv6.next_header` は write-back 後の値。
- 推奨: §13.4 [E-Layer-Proto-1] の `∀ ρ ∈ π̄. ⟨ρ, σ'⟩` どおり aux-extract 後 (write-back 後) の値。bracket と where が同じ値を見る。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Layer.lean` `extract` (predicates は `inst` の patches 込みで評価), vector `ipv6-next-header-writeback-bracket` (goStatus mismatch)

## D-033: 読めない lookahead key
- 論点: counter が 0 でちょうどパケット末尾にいるとき、`select(pc.is_zero(), lookahead<8>)` の lookahead は読めない。`(true, _)` で accept すべきか ⊥ か。
- 現行 Go 実装の挙動: accept (`eth/vlan?/ipv4` に eth + ipv4 ちょうど 34 バイト)。
- 推奨: 読めない key は wildcard にだけ一致する (遅延評価と同じ結果)。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Machine.lean` `evalKey` / `valMatches`, generated vectors `*/trunc34`

## D-034: skip された chain の後の dispatch 親
- 論点: `eth/mpls*/ipv4` で mpls が 0 個のとき、ipv4 の `parent_dispatch` は eth (実行時の直前 layer) か mpls (静的な直前 layer) か。
- 現行 Go 実装の挙動: 静的 (mpls)。mpls→ipv4 は const 無しで self-validating 扱いになり、さらに option を参照しない filter は parser machine を走らせない (D-029) ため version も見ない。結果 **ethertype 0x0806 (ARP) のフレームを `eth/mpls*/ipv4/tcp` が accept する**。`eth/vlan*/ipv4/tcp` は vlan→ipv4 に ethertype const があるので正しく reject。
- 推奨: 実行時の直前 layer (σ の最後の instance)。§13.4 の `parent_dispatch(p, σ, P)` は σ に依存する関数として書かれており、Lean もそう実装している。Go は issue。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Layer.lean` `dispatch`, generated vectors `quant-mpls-star-zero/flip12`, `/flip13` (`fix/kunai-spec-conformance-2` で Go も一致)。Go 側の grandparent dispatch は「optional layer が 1 つ、その親が optional でなく、次の layer が量化なし」の形。optional が連続する形は静的な親に対する dispatch をそのまま使い、それが実行時のどの親でも同じ読み (同じ定数、親末尾からの同じ位置) になる場合だけ受け付ける (`eth/qinq?/vlan?/ipv4`: ethertype は eth/qinq/vlan いずれも末尾 2 byte)。そうでない形 (`eth/vlan?/mpls?/ipv4`: ipv4 は mpls の下では self-validating、vlan の下では ethertype) は `ErrNotImplemented` (vectors `absent-consecutive-*`)。

## D-035: 64 bit を超える算術
- 論点: §13.9 は Int<64> で計算すると書き (D-015)、Int<128> (ipv6 src/dst) を含む算術は Lean では illTyped にしていた。Go は `+` `-` を 128 bit (64 bit 2 つ、桁上がり・借り付き) で計算し、比較も 128 bit で行う。`*` は dsl-types §9.1 で廃止 (bit slice で代替)、`/` `%` bitwise shift は codegen 無し (`ErrNotImplemented`)。
- 推奨: Go の実装範囲を仕様にする。operand の幅が 64 を超えるとき、`+` `-` は `mod 2^w` (w = max 幅、実質 128)、それ以外の演算子は illTyped。比較は幅に関係なく値の比較。定数は文脈幅 (128) で fit-check。Go 側は `*` 等を resolver で型エラーにする (ErrNotImplemented ではなく)。
- 状態: 承認済 (2026-10-02)
- 反映先: `Eval/Where.lean` `wideArithWidth` / `binop (w := …)`, `Eval/Check.lean` `checkArith`, vectors `arith-128-*`, `typ-arith-128-mul`, `typ-arith-128-band`; Go `resolve/typing.go` `checkArithExpr`
- 追記 (2026-10-03): 幅の混在 (`ipv6.src + tcp.dport`, `ipv6.src == tcp.dport * 2`) を Go も実装した。64 bit 以下の部分式は 64 bit pipeline で計算して zero-extend する。その部分式の中のリテラルは部分式の幅で fit-check する (`ipv6.src == tcp.dport * 70000` は型エラー)。あわせて D-009 (リテラルは隣の operand の幅を取る) を Go の 64 bit 経路にも揃えた: resolver は binop ごとに隣の幅で fit-check し (`ipv4.ttl + 300 == tcp.dport` は型エラー)、codegen は負のリテラルを隣の幅の 2 の補数で読む (`tcp.dport + -1` は 0xffff を足す)。Go に残る未実装: 65〜127 bit の slice (128 bit 式が `±` の右側に来る形は #143、両側に来る形 (`(a + b) - (c + d)`) は 2026-10-06 に実装した: 左の結果を予約 slot の上に退避して右を計算する。この形だけが slot を余分に使うので、他の式の入れ子上限は変わらない。vectors `arith-128-wide-right*`, `arith-128-wide-both*`) (vectors `arith-128-mixed-width-*`, `arith-128-const-binop`, `typ-arith-128-narrow-fit*`, `typ-literal-fit-arith-sibling`, `where-negative-literal-sibling`)。

## D-036: `in @set` の意味
- 論点: `field in @name` は filter 内では key の抽出だけで、membership の lookup は host が filter の後に行い verdict に AND する (`internal/program` の `emitPktSetLookups`)。Lean は Phase 2 で illTyped にしていた。
- 現行 Go 実装の挙動: SetSlots を持たない host は `ErrNotImplemented`、宣言の無い set は型エラー、key 幅と field 幅は一致必須、量化 layer と alternation member では reject (key が書かれない経路があるため)。
- 推奨: Host に宣言済 set (名前、key 幅、要素) を持たせ、`in @name` は「宣言されていれば field の値が要素に含まれるか、未宣言なら illTyped」。key 幅は filter が field のために読む load 窓 (bit 範囲を覆う最小の 1/2/4/8 byte、Int<128> は 16; 4 bit の `ihl` は bit<8>、bit 4 から始まる 8 bit の `traffic_class` は bit<16>) と一致、量化 layer と alternation member は不可、同じ set は filter 内で 1 回 (host は set ごとに key を 1 つ持ち 1 回 lookup する; Go codegen は同じ key slot への 2 度目の書き込みを拒否し、複合 key の別 field は別 slot なので書ける)、参照された key を chain 順に各 key の幅 (最大 8) で align して並べたとき host の key buffer 16 byte 以内 (いずれも illTyped、Go では resolver / codegen の通常エラー)。set の宣言自体 (重複、要素の範囲) は host 側の問題で、仕様は見ない。scalar set のみを対象とし、複合 key (複数 field、未書込 field は host が zero-fill) は仕様外。end-to-end の verdict (filter ∧ lookup) を仕様にする。Go runner は set を持つ vector のうち accept を kernel で照合し (filter 単体でも accept になる)、reject は lookup 由来かもしれないので compile-only。
- 状態: 承認済 (2026-10-02)
- 反映先: `Host.lean` `SetDecl` / `Host.sets`, `Eval/Layer.lean` `evalPred`, `Eval/Check.lean` `checkPred` / `checkProtoLayer`, vectors `pred-inset-*`, `typ-pred-inset-*`, `syn-pred-inset`; Go `dsltest` `specSetSlots`

## D-037: 繰り返す layer の self edge
- 論点: `{n,m}` (m > 1), `*`, `+` の 2 個目以降の instance は自分自身の protocol を親に dispatch する。`check` は `possibleParents` に自分を含めないので self edge を見ておらず、`srv6{0,2}` は静的に通って実行時に 2 個目が D-017 の probe (routing_type == 4) に落ちる (tcp の sport の下位 byte が 4 だと 2 個目の srv6 とみなして reject)。`gre{0,2}` は gre が 1 個 match した後で初めて illTyped になり、「illTyped は packet に依らない」に反する。
- 現行 Go 実装の挙動: codegen が `chained X has no self-dispatch const` の `ErrNotImplemented`。
- 推奨: 2 個目の header を抽出しうる layer (`*`, `+`, `{n,}`, m > 1 の `{n,m}`; 量化子の形で決め、`MAX_DEPTH` の値には依らない) には宣言された self edge を要求し、無ければ illTyped。self-validation の probe は chain の連結には使わない。Go は resolver (`checkChainShape`) で同じ型エラーにする。`?` / `{0,1}` は self edge 不要。
- 付記: `*` / `+` の反復上限は `<PROTO>_MAX_DEPTH`。ipv6 ではこの定数が拡張ヘッダ walk の上限 (4) と兼用で、入れ子の深さの意味ではない。可変長 layer の繰り返しを実装するときに分ける。
- 状態: 承認済 (2026-10-03)
- 反映先: `Eval/Check.lean` `checkProtoShape`, vectors `typ-repeat-no-self-edge`, `typ-repeat-no-self-edge-star`; Go `resolve/resolve.go` `checkChainShape`

## Go 側への issue 候補 (この作業では変更しない)

`fix/kunai-spec-conformance` で対応済みのものは ✅、残りは `issues/` に本文がある。

1. ✅ bpf_loop 経路の quantifier predicate が初回反復にしか適用されない (D-001) — callback が毎反復 predicate を replay。
2. ✅ `README.ja.md:18` の例がコンパイルできない (D-003) — 例を差し替え。量化 layer 以降の where field 参照自体は未実装のまま。
3. ✅ 同一 proto を含む alternation がロード時 "duplicate symbol" (D-004) — ラベル名に layer Index を含めた。
4. ✅ `eth/ipv4?/tcp` が verifier で落ちる (D-017) — 可変長 / self-validating な optional layer は `ErrNotImplemented` に。その後、親に dispatch 定数がある可変長 layer の `?` / `{0,1}` (`ipv6/srv6?`, `eth/ipv4?`, `ipv4/gre?`) は実装: parser machine の entry dispatch の失敗先を absent ラベルにし、dispatch は bounds / slot store / advance より前なので absent 経路は R4 と slot を触らない (vectors `quant-selfvalidating-broken`, `quant-opt-*`, `srv6-opt-*`, `gre-opt-*`, `srv6-all-absent-layer`)。親定数の無い self-validating layer の `?` (`mpls/ipv4?`、cascade の中で定数の無い runtime parent に当たる `ipv6/srv6?/ipv4?` も) は、parser の entry select が要求する primary field (`vocab.Requires`、Lean の `requires` と同じ出所) を layer を消費する前に probe する: select が reject する値なら miss で skip、読めなければ miss ではなく layer 自身の bounds check が reject (vectors `quant-selfvalidating-*`, `srv6-opt-then-ipv4-opt`)。可変長 layer の繰り返し (`{0,m>1}`, `*`) は未実装。
5. ✅ `{0,1}` が `ErrNotImplemented` (D-005) — `{0,m}` (m ≤ 4) は `?` の peek 経路 + 静的 unroll。
6. ✅ 到達不能 chain `mpls{1,8}/mpls` に警告が無い (D-002) — resolver が警告を出す。
7. ✅ `dsl-types.md` の記述 (D-004, D-015, D-021, D-022) — `feat/lean-spec` で修正済。
8. ✅ bpf_loop 経路が反復途中の bounds 失敗を「停止」と扱う (D-005) — dispatch 一致後の bounds 失敗は reject。
9. bpf_loop 経路の RangeMin 判定が VLAN (self-dispatch で停止) で 1 つずれていた — 8 と同時に修正済 ✅。

10. ✅ bpf_loop 経路が反復上限で chain-end 信号を要求しない (D-024) — ループ後に最後の header の end 信号を要求 (`fix/kunai-spec-conformance-3`)。

11. ✅ 抽出されなかった option の field 参照が filter 全体を reject する (D-027) — atom が false になるよう fail label を通した (`fix/kunai-spec-conformance-2`)。
12. ✅ 壊れた option 領域 (D-029) — 2026-10-05 に仕様を改訂して解消: 宣言された option 領域の中で walk が失敗したら、その layer は option を持たないものとし chain は続く。Go も option を参照する filter で同じ扱いにした (mismatch 0)。
13. ✅ 静的 index が count を見ない・`!=` が範囲外で true (D-031) — count source のある stack (srv6, SACK, RR) は #120、parser machine が push する stack (ipv6.exts, gtp.exts) は push 数を数える demand slot で #121。可変長 ext header の `exts[i]` は読む側で手前の entry を辿って位置を出す (`fix/kunai-spec-conformance-4`, vectors `ipv6-exts-index-after-long-ext`, `ipv6-exts-any-after-long-ext`)。可変長 entry への動的 index も、push 上限まで展開した walk を index の段で止めて読む (PR #131, vectors `ipv6-exts-dynamic-index-var-len*`, `gtp-ext-dynamic-index`)。
14. ✅ bracket predicate が write-back 前の値を見る (D-032) — write-back を持つ proto は walk 後に評価。
15. ✅ `tcp.options.X.exists` を実装。
16. ✅ `eth/mpls*/ipv4/tcp` が ARP を accept する (D-034) — skip された layer の後の dispatch は実行時の親に対して行う。1 つの optional は absent edge で grandparent に dispatch (#120)、連続する optional は各 optional の entry slot (不在 sentinel) を近い順に試す cascade で実行時の親を選ぶ (`fix/kunai-consecutive-optionals`, vectors `absent-consecutive-*`)。全候補で dispatch が同じ読みになる形 (`eth/qinq?/vlan?/ipv4`) は従来どおり静的 1 回。
17. ✅ (spec 側) Lean の bracket predicate が primary header の field しか型付けしなかった — `resolveBracket` で where と同じ規則 (T-FieldAux / T-FieldStackStatic、不在なら false、write-back 後の値) に拡張 (`fix/kunai-spec-conformance-4`, vectors `ipv6-exts-bracket-*`, `gtp-exts-bracket`)。Go は push 数で数える stack を index する bracket predicate を walk 後に評価し push count で guard する (write-back を持つ ipv6 は全 predicate を walk 後、持たない gtp はその predicate だけを walk 後に回し、他は walk 前のまま; vectors `gtp-exts-bracket`, `gtp-exts-bracket-absent`, `gtp-exts-bracket-mixed`)。量化 layer の predicate は反復ごとの replay で count が確定しないため `ErrNotImplemented` のまま。
18. ✅ 自己 edge の dispatch が前 header の chain-end 信号を見ない — `eth/mpls/mpls` が 1 label の stack で 2 枚目を ipv4 の先頭 4 byte から読んでいた。`genDispatch` が同一 proto の親に対して先に end 信号を検査する (PR #128, vectors `chain-mpls-self-edge-miss`, `quant-self-edge-opt`, `quant-self-edge-star`)。

残: self edge を持つ可変長 layer の繰り返し (`ipv4{0,2}`, `ipv4*`)。self edge の無い protocol の繰り返し (`srv6{0,2}`, `gre*`) は型エラー (D-037)。入れ子は `ipv4/ipv4?/ipv4?` で 3 段まで書ける。
