# F8 (SRv6) master 再測の論文反映 提案メモ（2026-06-24）

- 対象: `paper/sections/05_evaluation.tex`（§5.3 datapath cost の prose + Fig.~datapath caption + §5.4 結論文）。`.md` 作業ノート（`5_eval.md` / `hand_draft_ja_reviewed.md`）は副次。
- 由来: main `4915d9b`（PR #42、aux-walk bpf_loop + SRv6 explicit walk）で F8 を再測。`benchmark/results/b4_srv6_rep{1..10}.csv`（n=10、srv6 stream のみ）→ 既存 `b4_xdp_drop_rep*.csv` の F8/accept_srv6 行に splice 済み、`b4_xdp_drop_stats.csv` と `figures/fig_datapath.pdf` も再生成済み。pre-rework の元データは `benchmark/results/attic/*_prebpfloop_20260624_183005`。
- 凡例: 🔴 必須（現行 master と論文の整合）/ ⚪ 任意 / ⚠ 判断が要る

---

## 0. 何が起きたか（1 段落）

aux-walk の bpf_loop 化 + #42 の SRv6 explicit walk で、**F8 だけ** datapath cost が動いた。他 9 本は bytecode 完全同一（F1-F10 を改修前 76bf81c と現 main でコンパイルして命令数一致を確認済み）なので据え置き。命令数（表 §5.1）は既に F8=332 に更新済み（sec33 メモで反映済み）。残るのは **§5.3 の datapath cost prose と結論**。

| | 改修前（canonical n=10） | 改修後 master（n=10） |
|---|---|---|
| F8 cost | −4.11% （2.51 Mpps） | **−7.42 ± 0.19%（4.50 Mpps）** |
| F8 insns | 450 | 332（既に反映済み） |

baseline（accept_srv6）はほぼ不動（61.03→60.58）なので、これは session drift でなく **F8 自体が実際に重くなった**。命令数は減ったが bpf_loop の per-iteration call overhead で per-packet は増えた、という構図。

---

## 1. ⚠🔴 中心主張への影響（このメモの本題）

現行 §5.4 は次の 3 点を主張している。**F8=7.4% でいずれも崩れる**。

1. 「F7--F10 were 3.9--6.6\%, ... F7 ... the largest at 6.6\%」（L176-177）
   → 新範囲は **3.9--7.4%**、最大は **F8（7.4%）**。F7（6.6%）ではない。
2. caption「The most complex filter F7 (6.6\%) is within the 6.7\% window-copy cost」（L185-186）
   → F8（7.4%）が最複雑になり、かつ **固定費 6.7% を超える**。「within」は成り立たない。
3. 結論「The cost is therefore dominated by the fixed per-packet work ... not by filter evaluation」（L194-195）
   → F8 では filter 評価コストが固定費を上回るので、「固定費が支配」が普遍では無くなる。

### 修正案（3 択）

**案 A（推奨）: 正直リフレーム。** F8 を「固定費と同程度〜やや上」の唯一の例外として明記し、残り 9 本で thesis を維持する。F7 を既に「内側」→「同程度」にリフレーム済（[[b4_f7_fixed_cost_reframe]] / 2026-06-21 user 判断 B）なので、それを F8 に拡張する形で一貫する。thesis（in-kernel filter は不可避の copy コストと同オーダーで安い）は保たれる。差分（旧 unrolled との比較）は書かない方針どおり、現行値だけで記述。

- L176-177:
```diff
-filters F7--F10 were 3.9--6.6\%, with
-F7, which entails a full chain walk, the largest at 6.6\%. For
+filters F7--F10 were 3.9--7.4\%, with
+F8, whose SRv6 segment list is walked by a \texttt{bpf\_loop} callback,
+the largest at 7.4\%. For
```
- caption L185-186:
```diff
-  baseline, box plot, $n{=}10$). The most complex filter F7 (6.6\%) is
-  within the 6.7\% window-copy cost (dashed); triangles are means.}
+  baseline, box plot, $n{=}10$). The heaviest filters (F7 chain walk
+  6.6\%, F8 SRv6 loop 7.4\%) are comparable to the 6.7\% window-copy
+  cost (dashed); triangles are means.}
```
- 結論 L194-195:
```diff
-deviation. The cost is therefore dominated by the fixed per-packet work
-every program on the datapath shares, not by filter evaluation.
+deviation. Except for the SRv6 segment loop (F8), whose cost is on par
+with the copy, the cost is dominated by the fixed per-packet work every
+program on the datapath shares rather than by filter evaluation.
```

**案 B: full suite を 1 セッションで測り直してから確定。** 後述「§3 cross-session caveat」のとおり、現状の F8(新)vs 固定費(旧)は別セッション比較。`REPS=10 DURATION=30 bash benchmark/pipelines/b4_run_full.sh` で floor/accept_all/F1-F10 を同一セッションで取り直せば、「F8 が固定費を超える」が drift 込みでも言えるか確定する。確定後に案 A の文言を同一セッション数字で書く。最も堅いが時間と box 占有がかかる（先に srv6 だけにした経緯あり）。

**案 C: F8 を bench から外す / unrolled 版で測る。** master は bpf_loop 版が出荷済みなので、論文が出荷システムと食い違う。非推奨。

→ 推奨は **A**（必要なら B で裏打ち）。

---

## 2. 🔴 機械的に直る箇所（案 A に含まれるが単独でも必要）

| 場所 | 現在 | 修正 |
|---|---|---|
| `05_evaluation.tex` L176 | `3.9--6.6\%` | `3.9--7.4\%` |
| `05_evaluation.tex` L177 | `F7 ... largest at 6.6\%` | `F8 ... largest at 7.4\%` |
| `05_evaluation.tex` caption L185-186 | `most complex F7 (6.6\%) ... within` | 案 A の caption |
| `05_evaluation.tex` 結論 L194-195 | `dominated by fixed ... not by filter` | 案 A の結論 |

命令数表（F8=332）と §5.1 の insns 範囲は .tex では既に反映済み（確認: L38 F7=405 / L39 F8=332 / L41 F10=231）。

---

## 3. ⚠ caveat（案 A を採るなら本文 or 脚注で要注意）

1. **cross-session**: 今回 splice したのは srv6 cell のみ。window-copy 固定費 6.7%（floor + accept_udp64 由来）と b2 baseline は **改修前セッションのまま**。よって「F8 7.4% > 固定費 6.7%」は別セッション比較で、drift ~0.5pp の不確かさを含む（[[b4_f7_fixed_cost_reframe]] と同じ注意）。「同程度（comparable）」表現なら drift 内で安全、「超える（exceeds）」と断言するなら案 B の同一セッション再測が要る。
2. **b2（per-packet ns）が未更新**: L190-193「each filter added at most +15\,ns/pkt (under 3\%)」は `BPF_PROG_TEST_RUN` の b2 由来で、**F8 は再測してない**。SRv6 を bpf_loop 化したので F8 の per-packet ns も上がっている可能性が高く、「+15ns max / under 3%」が今の F8 と矛盾しうる（b4 は 7.4% と言っているのに b2 は全 filter 3% 未満、となる）。整合させるなら b2 の F8（と固定費）も再測する（`BENCHTIME=3s bash benchmark/microbench/run_runtime_reps.sh` 系）か、b2 は pre-rework F8 と明記する。

---

## 4. ⚪ 副次: `.md` 作業ノートの stale 値

実体は .tex なので優先度低。整合させるなら:

| 場所 | 現在 | 修正 |
|---|---|---|
| `5_eval.md:193` | `cost%:kunai_F8_vs_accept_srv6 = −3.94 ± 0.13` | `−7.42 ± 0.19`（※旧 -3.94 は n=5 期の更に古い値） |
| `5_eval.md:133` | 「F7-F10 は 231〜450 命令」 | 「231〜405」（最大が F8→F7 に） |
| `5_eval.md:207` | 「命令数（199…450）」 | 「199…405」 |
| `5_eval.md:135` | 「PR #36 で F8 425→450 …」 | 二重に stale（今 F8=332）。#36 の diff 注記自体が古い。削除 or 注記更新（差分書かない方針なら削除寄り） |
| `hand_draft:290`（表） | F8 insns `450` | `332` |
| `hand_draft:332`（methodology comment） | F8 `-4.11±0.18` + 「全 cell が旧比 ~0.5pp 重く」 | F8 を -7.42 にすると comment 内 narrative（0.5pp drift 話）と矛盾。comment ごと整理が要る |

---

## 5. データ所在（再現用）

- 新 reps: `benchmark/results/b4_srv6_rep{1..10}.csv`（srv6 stream のみ、n=10、DURATION=30、master 4915d9b）
- splice 後: `benchmark/results/b4_xdp_drop_rep{1..10}.csv`（F8/accept_srv6 のみ master 値、他 9 本据え置き）
- stats: `benchmark/results/b4_xdp_drop_stats.csv`（`cost%:kunai_F8_vs_accept_srv6 = -7.42 ± 0.186`）
- 図: `paper/figures/fig_datapath.pdf`（11 filters, n=10、再生成済み）
- pre-rework 退避: `benchmark/results/attic/*_prebpfloop_20260624_183005`
- 再測手順: TRex box（`ocxma-trex`）で hugepage 掃除 → `cd /opt/trex/v3.08/scripts && sudo nohup ./t-rex-64 -i -c 20 --cfg /etc/trex_cfg.yaml &` → srv6 のみは scoped runner、full は `REPS=10 DURATION=30 bash benchmark/pipelines/b4_run_full.sh`

---

## 推奨アクション

1. §1 案 A で §5.3/caption/結論を現行値にリフレーム（🔴）。
2. §3-1 の cross-session を踏まえ、F8 vs 固定費は「comparable（同程度）」表現にとどめる（断言は案 B 後）。
3. §3-2 の b2 を再測 or「pre-rework F8」明記（⚠ 放置すると b2 と b4 が矛盾）。
4. 余力で §4 の .md ノート整理（⚪）。

---

## 適用結果（2026-06-24）

**b2（per-packet ns）を master で再測した（F0 baseline + F8、BPF_PROG_TEST_RUN、count=10、ハード不要）:**

| | 旧 | master 再測 |
|---|---|---|
| F0 baseline | 611.2 | 613.9 ± 5.8 ns |
| F8 | 626.5 | 627.7 ± 5.3 ns |
| **F8 delta** | +15.3 ns | **+13.8 ns（2.25%）** |

→ **F8 の素の per-packet コストは不変**（σ 内、むしろ微減）。命令数も 450→332 で減っている。つまり filter の intrinsic cost は増えておらず、**b4 の 7.4% は line-rate（飽和時の bpf_loop callback 負荷）でのみ顕在化**する効果。よって §3-2 の懸念は解消: **b2 段落「+15ns max / under 3%」は master でもそのまま有効**（F8 +13.8ns）なので変更不要。

**case A を `05_evaluation.tex` に適用済み（comparable 表現、b2 段落は据え置き）:**
- L176-177 result prose: `3.9--6.6\%` → `3.9--7.4\%`、最大を F7→F8（bpf_loop callback）に
- caption: 「most complex F7 ... within」→「heaviest (F7 6.6\%, F8 7.4\%) are comparable to the 6.7\% window-copy cost」
- 結論: 「dominated by fixed ... not filter」→「Save for the SRv6 loop (F8), whose line-rate cost is on par with the copy, ...」

**残（任意）:** §4 の `.md` 作業ノートの stale 値（5_eval.md / hand_draft）。実体 .tex は反映済みなので優先度低。
