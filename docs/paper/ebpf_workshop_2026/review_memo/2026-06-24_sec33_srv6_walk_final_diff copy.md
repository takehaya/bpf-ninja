# §3.3 SRv6 explicit-walk 反映 Diff（最終マージ版, 2026-06-24）

- 対象: `sections/03_design.tex`(§3.3 / `fig:p4srv6` + 直後の段落) / `sections/04_codegen.tex`(§4.2) / `sections/05_evaluation.tex`(§5 Table F8 + §5.4 prose)
- 由来: main `4915d9b`(PR #42 squash merge 済み・全 green)の `pkg/kunai/protocols/srv6.p4`。AFTER = マージ済みコードに一致(header の `flags,tag` と extern 本体のみ紙面用に中略)。
- `-` 適用前 / `+` 適用後、折り返しは非本質（LaTeX reflow）。
- **supersede**: 中間版 `2026-06-24_sec33_srv6_redesign_diff.md`(D1/D2/D3/D5) を本メモで置換。中間版は byte-driven seed・`@kunai_stack_count` 残し・`KUNAI_SRV6_ROUTING_TYPE`・F8 330 で、最終(element-driven・注釈ゼロ・素 `SRV6_ROUTING_TYPE`・F8 332)とズレている。
- 凡例: 🔴 必須（code↔paper 整合）/ ⚪ 任意

---

## D1 — `fig:p4srv6` を element-driven explicit walk へ 🔴

`sections/03_design.tex` L173-198（listing）:

```diff
 header srv6_h {
     bit<8>  next_header;
     bit<8>  hdr_ext_len;    // in 8-byte units
     bit<8>  routing_type;   // 4 = SRH
     bit<8>  segments_left;
-    bit<8>  last_entry;
-    bit<8>  flags;
-    bit<16> tag;
+    bit<8>  last_entry;      // index of the last segment
+    // ...                   (flags, tag)
 }
 header srv6_seg_h { bit<128> addr; }
-const bit<8> SRV6_IPV6_NEXT_HEADER = 43;
-parser SRv6Parser(packet_in pkt, out srv6_h hdr,
-    @kunai_layout[after=primary]
-    @kunai_stack_count[field=last_entry, offset=1]
-    out srv6_seg_h[8] segments) {
-  state start {
-    pkt.extract(hdr);
-    transition select(hdr.routing_type) {
-      4: skip_segments;  default: reject;
-    }
-  }
-  state skip_segments {
-    pkt.advance(((bit<32>)(hdr.hdr_ext_len & 0x0F)) << 6);
-    transition accept;
-  }
-}
+const bit<8> KUNAI_SRV6_IPV6_NEXT_HEADER = 43;
+const bit<8> SRV6_ROUTING_TYPE = 4;
+extern ParserCounter { /* set, decrement, is_zero */ }
+parser SRv6Parser(packet_in pkt, out srv6_h hdr,
+    out srv6_seg_h[8] segments) {
+  ParserCounter() pc;
+  state start {
+    pkt.extract(hdr);
+    pc.set((bit<8>)(hdr.last_entry + 1));   // segment count
+    transition select(hdr.routing_type) {
+      SRV6_ROUTING_TYPE: walk;  default: reject;
+    }
+  }
+  state walk {
+    transition select(pc.is_zero()) { true: accept; false: consume_seg; }
+  }
+  state consume_seg {
+    pkt.extract(segments.next);   // push one 16-byte segment
+    pc.decrement(1);
+    transition walk;
+  }
+}
```

**日本語訳（新コメント）**: `// segment count`=セグメント数 / `// push one 16-byte segment`=16B セグメントを 1 つ push。構造は「`skip_segments` の単発スキップ」→「`start`(数を seed)→`walk`(0 か判定)→`consume_seg`(1 要素 extract して 1 減算)の明示ループ」。

→ `skip_segments` の単発 `pkt.advance` を廃し、`start → walk → consume_seg` の明示ループへ。seed は `last_entry+1`(要素数)・decrement は `1`(1 要素ずつ)なので count が seed から落ち、`@kunai_layout`/`@kunai_stack_count` を両方削除。dispatch const は `KUNAI_SRV6_IPV6_NEXT_HEADER`(層間)、routing は値照合のみで素の `SRV6_ROUTING_TYPE`(value-only)。header は末尾 `flags,tag` を中略・extern 本体は 1 行コメントに圧縮(現図 ~28 行 → ~26 行)。

---

## D2 — §3.3「three constructs」段落を walk 明示・annotation-free へ 🔴

`sections/03_design.tex` L204-217:

```diff
  through three constructs. First, the \texttt{header} declarations give
  the offset and bit width of each field. Second, the \texttt{const} and
  \texttt{transition select} give the dispatch from IPv6 to SRv6 and the
  acceptance test on \texttt{routing\_type}.
- Third, the annotations give
- the walk metadata for the variable-length part: \texttt{@kunai\_layout}
- indicates that the \texttt{segments} list begins immediately after the
- fixed header fields of the protocol, and \texttt{@kunai\_stack\_count} that the element
- count is read as \texttt{last\_entry + 1}; the bounded walk of
- \S\ref{sec:codegen} uses these. The capacity 8 of
- \texttt{srv6\_seg\_h[8]} bounds the iteration
- count, and the masked \texttt{pkt.advance} in
- \texttt{skip\_segments} caps the variable-length advance
- at 120 bytes, both exposing static bounds to the verifier.
+ Third, the parser walks the segment list explicitly, extracting one
+ element per iteration and counting down from \texttt{last\_entry + 1};
+ the element count and the \texttt{segments} base then follow from the
+ walk itself, with no kunai annotation. The capacity 8 of
+ \texttt{srv6\_seg\_h[8]} bounds the iteration count for the verifier.
```

**日本語訳（要点のみ）**:
```diff
- 第三: annotation が walk メタデータを与える（@kunai_layout=segments 開始位置、
-       @kunai_stack_count=要素数 last_entry+1）。masked pkt.advance が 120B に制限し、
-       capacity 8 と併せ静的境界を verifier に見せる。
+ 第三: parser が segment リストを明示的に walk する（1 要素ずつ抽出し
+       last_entry+1 から数え下げる）。要素数も segments の base も walk 自体から
+       落ち、kunai annotation は不要。srv6_seg_h[8] の capacity 8 が反復回数を縛る。
```

→ 第三を「annotation が walk metadata」→「parser state が walk を明示し、count も base も walk 自体から落ちる(注釈ゼロ)」へ。`@kunai_layout`/`@kunai_stack_count` 言及と masked `pkt.advance` の一文を削除、代わりに capacity 8 が反復境界という静的上界を一言(verifier 論旨は不変)。⚪「`srv6_seg_h[8]` の一言も削る」なら末尾文を落として §4 の compile-time bound に委ねる。

---

## D3 — §4.2 の SRv6 count 出典を seed 由来へ 🔴

`sections/04_codegen.tex` L110-113:

```diff
 \S\ref{sec:dsl}, \texttt{base = srh\_start + SRH\_FIXED\_SIZE},
-\texttt{stride = width = 16}, \texttt{count = last\_entry + 1} (from the
-\texttt{@kunai\_stack\_count} annotation of \S\ref{sec:p4subset}), and
+\texttt{stride = width = 16}, \texttt{count = last\_entry + 1} (the SRv6
+parser's segment-walk seed in \S\ref{sec:p4subset}), and
 \texttt{target = fc00::1}.
```

**日本語訳**:
```diff
- count = last_entry+1（§p4subset の @kunai_stack_count annotation 由来）
+ count = last_entry+1（§p4subset の SRv6 parser の segment-walk seed）
```

→ annotation 名を出さず、D1 図で見せた walk の seed を指す。

---

## D4 — §5 Table F8 と per-walk コスト（再測定で確定）🔴

`sections/05_evaluation.tex` L39（Table 1）:

```diff
-    F8  & \texttt{eth/ipv6/srv6 where any(srv6.segments.addr == fc00::1)} & 316 & \na \\
+    F8  & \texttt{eth/ipv6/srv6 where any(srv6.segments.addr == fc00::1)} & 332 & \na \\
```

`sections/05_evaluation.tex` L149-152（§5.4 prose）:

```diff
 unrolls, then flattens once it lowers to a \texttt{bpf\_loop} callback,
 and each stacked SRv6 segment walk, itself such a callback, adds a fixed
-${\approx}70$. Even eight stacked walks stay near 800 instructions, three
+${\approx}68$. Even eight stacked walks stay near 800 instructions, three
```

**日本語訳**:
```diff
- F8（SRv6 any クエリ）= 316 命令。各 stacked SRv6 walk は固定 ≈70 命令を足す。
+ F8（SRv6 any クエリ）= 332 命令。各 stacked SRv6 walk は固定 ≈68 命令を足す。
  （8 walk でも ~800 命令付近で据え置き）
```

→ F8 316→332、per-walk ≈70→≈68（実測 +68）。「near 800」据え置きで可（8 walk = 808）。axisA(~16/unit→bpf_loop で 254 にフラット化)は変更なし。

---

## 計測エビデンス（②・実施済み, merged `4915d9b`）

- 命令数 F1–F10（`BenchmarkFilterSet`）: 論文と差は **F8 のみ 316→332**、他一致。
- envelope axisB（stacked walks, `b5_envelope.csv` 更新済）: 1=**332**, **+68/walk**, 8=**808**。axisA 不変。
- §5.2 correctness 再実行: 6.1/6.6/6.12/6.15/6.18/7.0 全 6 カーネルで dsltest(XDP)+internal/program とも **ok**（6.6 owner-walk 修正も再確認）。
- `benchmark/results/{b1_insns,b5_envelope}.csv` 更新済。`fig_insns`/`fig_envelope` は paper 未 include なので図編集不要。
- 未計測(要ハード): §5.4 datapath(TRex+E810) と per-packet ns。

## 優先度

| # | 項目 | 優先 | 適用先 |
|---|------|------|--------|
| D4 | §5 Table F8 316→332 + prose ≈68 | 🔴 | `05_evaluation.tex` L39, L151-152 |
| D1 | `fig:p4srv6` を explicit walk へ | 🔴 | `03_design.tex` L173-198 |
| D2 | §3.3 段落を walk 明示・注釈ゼロへ | 🔴 | `03_design.tex` L204-217 |
| D3 | §4 count 出典を seed 由来へ | 🔴 | `04_codegen.tex` L110-113 |

**未適用**。tex 反映は承認後。
