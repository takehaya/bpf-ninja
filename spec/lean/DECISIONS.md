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
- 現行 Go 実装の挙動: `in [80, 8000..8080]` は `ErrNotImplemented` (range)、`in @set` は SetSlots が要る。
- 推奨: `in [v…]` = いずれかの v と `==`。range は `lo ≤ n ≤ hi`。`in @set` は Phase 2 では illTyped。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Eval/Layer.lean` `evalPred`, vectors `pred-in-list`, `pred-in-range` (goStatus notImplemented)

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
- 推奨: 実装に合わせて §13.9 を「Int<64> で計算、定数は文脈幅で fit-check」に改める。BPF の自然な挙動で、per-node wrap をコード生成する利点が無い。64 bit を超える field (ipv6 src/dst) を含む算術は Lean では未対応 (Go はコンパイルする; vector `typ-arith-128` は mismatch)。
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
- 反映先: `Eval/Layer.lean` `dispatch` (edge 無し + `requires` を dispatch 段階で検査), `extract` (`requires`), vectors `quant-selfvalidating-skip`, `quant-selfvalidating-broken`, `typ-no-dispatch-after-skip` (いずれも goStatus notImplemented: Go は self-validating / 可変長の optional を未実装), `dsl-types.md` §13.5

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
- `bracket_eq_where` (`…/p[f op v]` ≡ `…/p where p.f op v`): **未証明**。両者は `cmpValue` / `narrowInt` を共有するので p が chain 内で一意・非量化・root 以外なら一致するはずだが、`extract` の Fail-Pred と `evalWhere` の false を `eval` の reject に結び付ける証明が長く、Phase 4 では見送った。vector `pred-cmp` / `where-cmp-ops` などで個別に一致を確認している。
- `prefix_independence` / `filterMinPrefix`: 未着手。
- 状態: 承認済 (2026-10-01、一括)
- 反映先: `Laws.lean`

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

## D-029: option の検証は常に行う
- 論点: `eth/ipv4/tcp` (option を参照しない filter) に壊れた option を持つパケット。
- 現行 Go 実装の挙動: option を参照しない filter は walk を省略し (bulk advance)、accept。参照すると同じパケットが reject。
- 推奨: 仕様では parser machine は常に走る (⊥ なら reject)。
- 状態: 承認済 (2026-10-01、一括)。Go 側は 2026-10-01 に「意図的な逸脱として維持」で確定 (option を filter する時に初めて読む)。
- Go の逸脱: option を参照しない filter は option 領域を walk せず宣言長 (IHL / data_offset / opt_len) だけ進む (demand-driven walk、`canFallbackToBulkAdvance`)。差が出るのは「option 領域が壊れている、かつその layer の option を参照していない」filter だけで、Go が余計に accept する方向 (誤って reject する方向には倒れない)。常時 walk に変えると全 pin が約 2 倍 (F1 143→340、F7 349→643、F9 293→653)、GTP/Geneve の二重 ipv4 chain で verifier 予算のリスク、ipv4 の MAX_DEPTH 到達時の R4 補正も要る。壊れた option を弾きたい filter はその layer の option を 1 つ参照すれば walk が走る。
- 反映先: `Eval/Layer.lean` `extract`, vectors `tcp-opt-malformed-no-query`, `chain-ipv4-ihl6/flip34` (goStatus mismatch のまま維持: 既知の逸脱として機械可読に残す), `docs/ja/dsl-types.md` §14.5, `docs/ja/dsl-internals.md`

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
- 反映先: `Eval/Where.lean` `stackEntries` / `refView`, `Eval/Layer.lean` `evalPred` (bracket も同じ規則), vectors `ipv6-exts-index-absent`, `ipv6-exts-all`, `srv6-segments-index-absent`, `ipv6-exts-bracket-index-absent` (Go は #120/#121/conformance-4 で一致)

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

## Go 側への issue 候補 (この作業では変更しない)

`fix/kunai-spec-conformance` で対応済みのものは ✅、残りは `issues/` に本文がある。

1. ✅ bpf_loop 経路の quantifier predicate が初回反復にしか適用されない (D-001) — callback が毎反復 predicate を replay。
2. ✅ `README.ja.md:18` の例がコンパイルできない (D-003) — 例を差し替え。量化 layer 以降の where field 参照自体は未実装のまま。
3. ✅ 同一 proto を含む alternation がロード時 "duplicate symbol" (D-004) — ラベル名に layer Index を含めた。
4. ✅ `eth/ipv4?/tcp` が verifier で落ちる (D-017) — 可変長 / self-validating な optional layer は `ErrNotImplemented` に。skip の実装 (D-017 案 c) は未着手。
5. ✅ `{0,1}` が `ErrNotImplemented` (D-005) — `{0,m}` (m ≤ 4) は `?` の peek 経路 + 静的 unroll。
6. ✅ 到達不能 chain `mpls{1,8}/mpls` に警告が無い (D-002) — resolver が警告を出す。
7. ✅ `dsl-types.md` の記述 (D-004, D-015, D-021, D-022) — `feat/lean-spec` で修正済。
8. ✅ bpf_loop 経路が反復途中の bounds 失敗を「停止」と扱う (D-005) — dispatch 一致後の bounds 失敗は reject。
9. bpf_loop 経路の RangeMin 判定が VLAN (self-dispatch で停止) で 1 つずれていた — 8 と同時に修正済 ✅。

10. ✅ bpf_loop 経路が反復上限で chain-end 信号を要求しない (D-024) — ループ後に最後の header の end 信号を要求 (`fix/kunai-spec-conformance-3`)。

11. ✅ 抽出されなかった option の field 参照が filter 全体を reject する (D-027) — atom が false になるよう fail label を通した (`fix/kunai-spec-conformance-2`)。
12. ✗ option を参照しない filter は option を検証しない (D-029) — やらない (2026-10-01 決定)。demand-driven walk は設計判断として維持し、仕様との差は D-029 に記録。vectors は mismatch のまま。
13. ✅ 静的 index が count を見ない・`!=` が範囲外で true (D-031) — count source のある stack (srv6, SACK, RR) は #120、parser machine が push する stack (ipv6.exts, gtp.exts) は push 数を数える demand slot で #121。可変長 ext header の `exts[i]` は読む側で手前の entry を辿って位置を出す (`fix/kunai-spec-conformance-4`, vectors `ipv6-exts-index-after-long-ext`, `ipv6-exts-any-after-long-ext`)。可変長 entry への動的 index は `ErrNotImplemented` (`ipv6-exts-dynamic-index-var-len`)。
14. ✅ bracket predicate が write-back 前の値を見る (D-032) — write-back を持つ proto は walk 後に評価。
15. ✅ `tcp.options.X.exists` を実装。
16. ✅ `eth/mpls*/ipv4/tcp` が ARP を accept する (D-034) — skip された layer の後の dispatch は実行時の親に対して行う。1 つの optional は absent edge で grandparent に dispatch (#120)、連続する optional は各 optional の entry slot (不在 sentinel) を近い順に試す cascade で実行時の親を選ぶ (`fix/kunai-consecutive-optionals`, vectors `absent-consecutive-*`)。全候補で dispatch が同じ読みになる形 (`eth/qinq?/vlan?/ipv4`) は従来どおり静的 1 回。
17. ✅ (spec 側) Lean の bracket predicate が primary header の field しか型付けしなかった — `resolveBracket` で where と同じ規則 (T-FieldAux / T-FieldStackStatic、不在なら false、write-back 後の値) に拡張 (`fix/kunai-spec-conformance-4`, vectors `ipv6-exts-bracket-*`, `gtp-exts-bracket`)。Go は walk 後に predicate を評価する proto (ipv6) では push count で guard、walk 前に評価する proto (gtp) では `ErrNotImplemented`。
18. ✅ 自己 edge の dispatch が前 header の chain-end 信号を見ない — `eth/mpls/mpls` が 1 label の stack で 2 枚目を ipv4 の先頭 4 byte から読んでいた。`genDispatch` が同一 proto の親に対して先に end 信号を検査する (PR #128, vectors `chain-mpls-self-edge-miss`, `quant-self-edge-opt`, `quant-self-edge-star`)。

残: self-validating / 可変長 layer の `?` (D-017 案 c の実装)。
