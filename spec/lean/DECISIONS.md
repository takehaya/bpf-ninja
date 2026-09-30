# Decisions

Behaviours that `docs/ja/dsl-types.md` §13 leaves undefined, and how the Lean
spec resolves them. "現行 Go 実装の挙動" was measured on 2026-10-01 with
`kunai.Compile` / `dsltest.Runner` under root (XDP, zero `Capabilities`),
on the commit this file was added in. Vector ids refer to `Kunai/Vectors/*.lean`.

Status values: 提案中 (implemented as recommended, awaiting sign-off) /
承認済 (date).

## D-001: quantifier 途中の predicate 失敗
- 論点: `mpls[label==5]{1,8}` で 2 回目の反復の predicate が false のとき、(a) そこで反復を止め k=1 で成功、(b) layer 全体 ✗。§13.5 [E-Quant-Range-Step] の停止条件は dispatch miss / bounds のみで predicate 失敗を含まない。
- 候補: (a) 停止して k 反復で成功 / (b) ✗
- 現行 Go 実装の挙動: **経路により異なる。** 静的 unroll (`{1,3}`, m ≤ 4) は (b): `eth/mpls[label == 5]{1,3}/ipv4/tcp` にラベル 5,6,7 → reject。bpf_loop 経路 (`{1,8}`, `+`) は predicate を **初回反復にしか適用しない**: 同じパケットで `{1,8}` → accept、`[label == 6]{1,8}` → reject、`[label == 7]{1,8}` → reject。(a) でも (b) でもない。`codegen/chain.go:83-133` vs `codegen/bpfloop.go`。
- 推奨: (b)。predicate は「その layer のすべてのインスタンスが満たすべき条件」と読むのが `vlan[tci==100]?` の既存挙動 (`vlan_tagflex_test.go:42-54`) と整合する。bpf_loop 経路は issue として報告する (Go の挙動は変えない)。
- 状態: 承認済 (2026-10-01)
- 反映先: `Eval/Layer.lean` `iterate` (`.error .pred => throw e`), vectors `quant-pred-mid-fail` (goStatus mismatch), `quant-pred-mid-fail-static`, `quant-pred-first-fail`, `quant-pred-all-hold`

## D-002: greedy / バックトラック無し
- 論点: `eth/mpls{1,8}/mpls/ipv4` は greedy なら決してマッチしない。仕様として確定するか。
- 候補: (a) greedy 確定 / (b) バックトラック
- 現行 Go 実装の挙動: greedy。`eth/mpls{1,8}/mpls/ipv4/tcp` (3 ラベル) → reject、`eth/mpls{1,2}/ipv4/tcp` (3 ラベル) → reject (2 個消費後 ipv4 を 3 個目のラベルで parse して version 不一致)。
- 推奨: (a)。BPF で backtracking は現実的でなく、§13.5 の k の決め方 (最初の失敗で停止) も greedy を含意する。resolver に到達不能警告を出す issue を起票する。
- 状態: 提案中
- 反映先: `Eval/Layer.lean` `iterate`, vectors `quant-greedy-unreachable`, `quant-range-greedy-overrun`

## D-003: 不在レイヤの field 参照
- 論点: `eth/vlan?/ipv4 where vlan.tci == 10` で vlan が無いとき。
- 候補: (a) 比較 (atom) は false / (b) filter は reject / (c) 型エラー
- 現行 Go 実装の挙動: **コンパイル時 `ErrNotImplemented`** ("where-clause field on quantified layer" / "past quantified layer")。`eth/vlan?/ipv4/tcp where tcp.dport == 80` は通る (ipv4 が可変長 slot 境界になるため)。`README.ja.md:18` の例 `eth/mpls{1,8}/ipv4/tcp where ipv4.total_length > 100` は **コンパイルできない** (要修正)。
- 推奨: (a)。atom 単位で false にする。(b) は `not (vlan.tci == 1)` を書けなくし、(c) は実装制限を仕様に昇格させる。ユーザー決定 (2026-10-01): 仕様は純粋に書き、Go の制限は vector の `goStatus: notImplemented` で表す。注意: `not (vlan.tci == 1)` は不在時に true になる。
- 状態: 承認済 (2026-10-01、フラグ分離の方針のみ。(a) 自体は提案中)
- 反映先: `Eval/Where.lean` `loadField` (`none`), `evalWhere` `.arith`/`.litCmp` (`| pure false`), vectors `where-absent-layer-false`, `where-absent-layer-not`, `where-past-quantified-ok`

## D-004: alternation の順序と重なり
- 論点: `(vlan|qinq)` で両方の dispatch が一致するとき先勝ちか。alt 枝の同サイズ制約 (§11, T-LayerAlt) が何を保証するか。
- 候補: (a) 先勝ち commit (後続枝は試さない) / (b) 一意一致を要求 / (c) 失敗時に次の枝を試す
- 現行 Go 実装の挙動: (a)。`eth/(vlan|qinq)/ipv4/tcp` と `(qinq|vlan)` はどちらも vlan パケットに accept、`(vlan[tci == 200]|qinq)` は tci=100 で reject (predicate 失敗後に qinq を試さない)。同一 proto を 2 枝に書く `(ipv4[ttl == 1]|ipv4[ttl == 255])` は **ロード時に "duplicate symbol" で失敗** (Go bug、issue)。同サイズ制約は `codegen/alternation.go` に無く、`dsl-grammar.md:56` / `dsl-usage.md:257` もサイズ差を許す。
- 推奨: (a)。§13 に [E-Layer-Alt-First] を追加し、T-LayerAlt の uniform-size 制約は削除する (dsl-types.md 修正提案)。
- 状態: 提案中
- 反映先: `Eval/Layer.lean` `evalAlt`, vectors `alt-first`, `alt-second`, `alt-none`, `alt-first-pred-fails`

## D-005: `?` の skip 条件と Range-Step の停止条件
- 論点: [E-Quant-Optional] case B は dispatch miss だけを skip にしている。dispatch は一致するが bounds で L(1) が失敗する場合は skip か ✗ か。また [E-Quant-Range-Step] は bounds 失敗を停止条件に含めているため、文字どおりだと `?` ≢ `{0,1}` になる。
- 候補: (1) 仕様書どおり非対称のまま (`?` は ✗、`{0,1}` / `*` は k=0 ✓) / (2) Range-Step の停止条件から bounds を外し、すべての quantifier で「skip / 停止は dispatch miss のみ、bounds 失敗は ✗」に揃える
- 現行 Go 実装の挙動: **経路により異なる。** `eth/vlan?` も `eth/vlan*` も eth + vlan 2 バイトのパケットを reject (`codegen.go:1040-1062` は親の dispatch field だけを peek し、以後の bounded load 失敗は `dslReject`)。一方 bpf_loop 経路は反復途中の bounds 失敗を「そこで停止」と扱う: `eth/mpls{1,8}` に 2 個目のラベルが 2 バイトで切れたパケット → accept (k=1)。`{0,1}` は `ErrNotImplemented`。案 1 でも案 2 でも Go のどちらかの経路とは食い違う。
- 推奨: (2)。dispatch が一致しているのにヘッダが壊れているパケットを accept するのは説明できず、Go の実測とも一致し、`?` ≡ `{0,1}` が定理になる。
- 状態: 承認済 (2026-10-01、案 2)
- 反映先: `Eval/Layer.lean` `iterate` (bounds は `throw`), `Laws.lean: opt_eq_range`, vectors `quant-opt-bounds-reject`, `quant-range01-bounds-skip` (goStatus notImplemented), `quant-star-bounds-skip`, `quant-range-truncated-mid-chain` (goStatus mismatch), `dsl-types.md` §13.5

## D-006: 切り詰めパケットと where
- 論点: chain は通ったが where の field が packet 末尾を越える場合。
- 候補: (a) reject / (b) false
- 現行 Go 実装の挙動: reject (`ranged_predicate_test.go:20` "truncated TCP predicate field")。Phase 2 の範囲 (primary field のみ) では chain の bounds 検査が先に効くため到達不能。
- 推奨: (a)。
- 状態: 提案中
- 反映先: `Eval/Where.lean` `loadField` (`throw .reject`)。vector は Phase 5 (aux field) で追加

## D-007: `any` / `all` の空 stack
- 論点: §13.8 注記どおり any → false, all → true。
- 現行 Go 実装の挙動: 同じ (`dsl-types.md:1136`, §6.5)。
- 推奨: 採用。Phase 2 では stack を扱わないため `any`/`all` は `illTyped "unsupported: aux stacks"`。
- 状態: 提案中 (実装は Phase 5)
- 反映先: `Eval/Where.lean` `evalWhere` `.any`/`.all`

## D-008: host により意味が変わる箇所
- 論点: `packetStartsAtL3` のとき `eth` root は警告だが reject ではない。Lean ではどう扱うか。
- 候補: (a) illTyped / (b) バイト列上で評価して結果に任せる
- 現行 Go 実装の挙動: 警告のみ。`Compile("eth/ipv4", {PacketStartsAtL3: true})` はエラーなし。
- 推奨: (b)。警告は意味論の外。cursor 0 から評価し、L3 パケットに `eth` を当てれば普通に reject される。
- 状態: 提案中
- 反映先: `Eval.lean` (host は dispatch に関与しない), vectors `host-l3-ipv4-root`, `host-l3-eth-root`

## D-009: 算術の幅 (定数同士)
- 論点: `mod 2^max(width(e₁), width(e₂))` の width が定数由来のとき。
- 候補: (a) 64 / (b) 文脈 (兄弟 operand) の幅、無ければ 64
- 現行 Go 実装の挙動: 定数は兄弟 field の幅で fit-check される ("value 256 does not fit in bit<8> (in arithmetic context)")。定数同士は fold (`300 > 200` → true)。`-1 == 255` は `ErrNotImplemented` (int32 immediate)。
- 推奨: (b) を narrow (fit check) に使い、演算自体は D-015 により 64 bit。
- 状態: 提案中
- 反映先: `Eval/Where.lean` `sideWidths`, `evalArith` `.const`, vectors `where-literal-fit-ttl`, `where-const-fold`

## D-010: alternation の評価規則が §13 に無い
- 論点: §13 には `alt(L̄)` の E-rule が無い (T-LayerAlt のみ)。
- 推奨: [E-Layer-Alt-First] を追加 (D-004)。枝は field dispatch 必須 (NO_CHECK / self-validating 枝は illTyped)、quantifier 不可、root 不可 (いずれも Go の `validateAlternatives` と同じ)。
- 状態: 提案中
- 反映先: `Eval/Layer.lean` `evalAlt`, vector `alt-root-illtyped`

## D-011: bracket `in` の規則が §13 に無い
- 論点: §13.7 は [E-Pred-Cmp] のみ。`in [v…]`, `in @set`, `range` の規則が無い。
- 現行 Go 実装の挙動: `in [80, 8000..8080]` は `ErrNotImplemented` (range)、`in @set` は SetSlots が要る。
- 推奨: `in [v…]` = いずれかの v と `==`。range は `lo ≤ n ≤ hi`。`in @set` は Phase 2 では illTyped。
- 状態: 提案中
- 反映先: `Eval/Layer.lean` `evalPred`, vectors `pred-in-list`, `pred-in-range` (goStatus notImplemented)

## D-012: Phase 2 のプロトコル簡略化
- 論点: vocab を手で写す際に落としたもの。
- 内容: ipv6 拡張ヘッダ (next_header ∈ {0,44,60} で Go は `ipv6_ext_h` を walk し cursor が進む)、ipv4 options の kind 検査 (Go は EOL/NOP/RR/RA 以外を reject; Lean は IHL 分を読み飛ばすだけ)、tcp options の walk (Go は MSS/WS/SACK/TS の length 検査で reject しうる)、srv6/gre/gtp/geneve/qinq/esp/icmp。vector はこれらを踏まないパケットだけを使う (ipv4 options は NOP、tcp options は NOP)。
- 状態: 提案中 (Phase 5 で解消)
- 反映先: `Vocab.lean`

## D-013: 同一 proto が複数ある chain での無ラベル参照
- 論点: `eth/ipv4/ipv4/tcp where ipv4.ttl` や `eth/mpls{1,8}/… where mpls.label` の解決。
- 現行 Go 実装の挙動: 静的重複は "protocol is ambiguous (2 instances); qualify with an @label"。量化 layer は D-003 の `ErrNotImplemented`。
- 推奨: 静的に 2 個以上になりうる (重複、または上限 ≠ 1 の quantifier) なら illTyped。ラベルは `Λ ⊕ {ℓ ↦ inst}` どおり最後の束縛が勝つ。
- 状態: 提案中
- 反映先: `Eval/Where.lean` `staticCount`, `resolveRef`, vectors `where-ambiguous`, `where-label-inner-outer`

## D-014: shift 量
- 論点: `<<` / `>>` の RHS が 64 以上のとき。
- 現行 Go 実装の挙動: BPF の masked shift (64 bit ALU なので `& 63`)。`ipv4.ttl << 65 == 0` → false (= `<< 1`)。
- 推奨: `b % 64`。
- 状態: 提案中
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
- 状態: 提案中
- 反映先: `Eval/Layer.lean` `extract` (`if l < spec.fixedLen then throw .pred`), vectors `chain-ipv4-ihl4`, `chain-tcp-dataoffset4`

## D-017: self-validation (parser-block reject) の失敗種別
- 論点: `select(version) { 4: …; default: reject }` の ⊥ を dispatch miss と見るか predicate 失敗と見るか (`ipv4?` の skip 判定に影響)。
- 現行 Go 実装の挙動: `eth/ipv4/tcp` に version=5 → reject。`eth/ipv4?/tcp` は **verifier で load 失敗** ("math between map_value pointer and register with unbounded min value") — Go bug、issue。
- 推奨: §14.4 のとおり Fail-Pred 系統 (skip しない)。
- 状態: 提案中
- 反映先: `Eval/Layer.lean` `extract` (`requires`), vector `chain-ipv4-version5`

## D-018: quantified layer のラベル再束縛
- 論点: `mpls@m{1,8}` は反復ごとに `m` を束縛し直す。
- 現行 Go 実装の挙動: `where m.label` は `ErrNotImplemented`。
- 推奨: `Λ ⊕` どおり最後の束縛が勝つ (D-013)。
- 状態: 提案中
- 反映先: `Eval/Layer.lean` `extract` (labels に cons), `Eval/Where.lean` `resolveRef`

## D-019: `and` / `or` の評価順
- 論点: §6.3 は short-circuit、§13.8 [E-W-And]/[E-W-Or] は両辺評価。差が出るのは第 2 項が reject (D-006) するとき。
- 現行 Go 実装の挙動: codegen は jump による short-circuit。Phase 2 の範囲では観測不能 (primary field は chain で bounds 済)。
- 推奨: 両辺を評価するが、第 1 項で結果が決まるなら第 2 項の動的 reject は無視する (short-circuit と同じ結果)。型エラーは隠さない。
- 状態: 提案中
- 反映先: `Eval/Where.lean` `logic`

## D-020: capture の対象 layer が不在
- 論点: `eth/vlan?/ipv4 capture vlan` で vlan が無いとき。
- 推奨: その capture 句は省く (gate false と同じ)。
- 状態: 提案中
- 反映先: `Eval/Where.lean` `evalCapture` `.toLayer`

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
- 状態: 提案中
- 反映先: `Laws.lean`

## Go 側への issue 候補 (この作業では変更しない)

1. bpf_loop 経路の quantifier predicate が初回反復にしか適用されない (D-001)。
2. `README.ja.md:18` の例 `eth/mpls{1,8}/ipv4/tcp where ipv4.total_length > 100` がコンパイルできない (D-003)。
3. 同一 proto を含む alternation `(ipv4[…]|ipv4[…])` がロード時 "duplicate symbol" (D-004)。
4. `eth/ipv4?/tcp` が verifier で落ちる (D-017)。
5. `{0,1}` が `ErrNotImplemented` (D-005)。
6. 到達不能 chain `mpls{1,8}/mpls` に警告が無い (D-002)。
7. `dsl-types.md` §13.9 の wrap 記述 (D-015) と `%` の 0 除算 (D-022) が実装と異なる、§11/T-LayerAlt の uniform-size 制約が grammar/usage と矛盾 (D-004)、§13.6 の capture gate が grammar/usage と矛盾 (D-021)。
8. bpf_loop 経路が反復途中の bounds 失敗を「停止」と扱い、peek 経路 (`?`, `*`) の reject と一致しない (D-005)。
