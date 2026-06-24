# ayako レビュー対応 Diff（2026-06-25, 未適用 / 英語・日本語とも文脈広め）

- 由来: `2026-06-25_ayako_review.md`（A1–A9）
- 対象: `sections/01_introduction.tex`（A1–A3）/ `sections/02_related.tex`（A4–A9）
- 各 diff は段落の前後文脈付き（無印=unchanged、`-` 適用前 / `+` 適用後）。英語=実際に当てる版、日本語=同じ箇所の訳。折り返しは非本質（reflow）。
- 凡例: 🔴 採用推奨 / 🟡 user 判断

---

## ☐ A1 🔴 「User studies … open problems」を移設＋`likewise` 削除（§1 para2）

```diff
  SYN of nearly every connection. A kernel capture tool therefore
- encounters them. Filter languages
+ encounters them. User studies of packet-analysis tools report protocol
+ coverage and the expressiveness of the filter language as open
+ problems~\cite{sultana2024survey}. Filter languages
  that can follow these structures by field name exist; the
  Wireshark display filter~\cite{wireshark_dfref} is one. These
  languages, however, evaluate a fully parsed packet held in user-space
  memory, where any field can be read by random access; the kernel data
  path offers no such parsed view and requires every read to be proven in
  bounds.
- These languages therefore cannot run early in the data path. User studies of packet-analysis tools likewise
- report protocol coverage and the expressiveness of the filter
- language as open problems~\cite{sultana2024survey}.
+ These languages therefore cannot run early in the data path.
```
**日本語訳**:
```diff
  …ほぼ全接続の SYN に現れる。kernel capture tool はこれらに遭遇する。
- フィルタ言語で
+ user studies は packet 解析ツールの protocol カバレッジ/フィルタ言語の表現力を
+ open problem と報告している[25]。フィルタ言語で
  これらの構造をフィールド名で辿れるものは存在する（Wireshark display filter が一例）。
  だがそれらは user 空間のフルパース済みパケットを評価する方式で、kernel data path
  には parse 済みビューが無く、全読み出しを境界内と証明する必要がある。
- よってこれらの言語は data path で早期に実行できない。user studies も同様に
-   (likewise) protocol カバレッジ/フィルタ言語の表現力を open problem と報告[25]。
+ よってこれらの言語は data path で早期に実行できない。
```
→ 狙い: 「open problems」を Wireshark(userland=柔軟)の直後から外し、表現力ギャップ側（encap が common の直後）へ。`likewise` の誤接続を解消。

---

## ☐ A2 🔴 「Expressiveness alone is not enough」を前段落から接続（§1 para3 冒頭）

```diff
  accepts. To our knowledge, no system offers both field-name
  expressiveness over these structures and a form the in-kernel verifier
  accepts.

- Expressiveness alone is not enough. To run such a filter inside the
- kernel, it must also be compiled to eBPF bytecode that the verifier
- accepts~\cite{kernel_verifier, ebpf_loops, gershuni2019prevail}.
+ Running such an expressive filter in the kernel is the other half of the
+ problem: it must compile to eBPF bytecode that the verifier
+ accepts~\cite{kernel_verifier, ebpf_loops, gershuni2019prevail}.
  Compilers from P4 to eBPF, such as p4c-xdp~\cite{tu2018p4cxdp},
  already emit verifier-accepted code, but they lower fixed protocol
  pipelines rather than filter expressions whose target field sits past
```
**日本語訳**:
```diff
  …我々の知る限り、これらの構造へのフィールド名表現力と、in-kernel verifier が受理する
  形式の両方を備えたシステムは無い。

- 表現力だけでは不十分。kernel 内でフィルタを動かすには、verifier が受理する eBPF
- bytecode へコンパイルする必要もある[…]。
+ こうした表現力あるフィルタを kernel で動かすのが「もう半分」の課題：verifier が
+ 受理する eBPF bytecode へコンパイルしなければならない[…]。
  P4→eBPF コンパイラ（p4c-xdp など）は既に verifier 受理コードを出すが、固定プロトコル
  pipeline を下ろすだけで、nested encap や可変長リスト越しの対象フィールドを持つ式は扱わない。
```
→ 狙い: 前段落（表現力ある手法はあるが kernel で動かない）から「では in-kernel 化が残る半分」へ橋渡し。「表現力を達成した」前提を読者に求めない。

---

## ✅ A3 🟡 言い訳ヘッジ「not as a formal guarantee (§6)」削除（§1 para4末）— 適用済み 2026-06-25（latexmk OK）

```diff
  \emph{verifier-safe} in the sense of Solleza et
  al.~\cite{solleza2025verifiersafe}: a well-formed filter should compile
  to bytecode the verifier accepts. We establish it empirically across
- six kernels (\S\ref{sec:eval}), not as a formal guarantee
- (\S\ref{sec:limitations}).
+ six kernels (\S\ref{sec:eval}).
```
**日本語訳**:
```diff
  …Solleza ら[…]の意味で verifier-safe という語を使う：well-formed なフィルタは
  verifier 受理 bytecode へコンパイルされるべき、という立場。
- これを 6 カーネルで経験的に確立する(§5)。形式的保証ではない(§6)。
+ これを 6 カーネルで経験的に確立する(§5)。
```
→ 狙い: §6 にあるので intro での但し書きは冗長＝ayako「言い訳くさい」。A8 と同じヘッジ削減。**user 判断**: 残すなら理由を一語に圧縮。

---

## ✅ A4 🔴 §2 先頭に topic sentence を追加（§2 para1 冒頭）— 適用済み 2026-06-25（latexmk OK）

> 適用文は短縮版: `Existing packet filters trade expressiveness for in-kernel execution.`（`kernel-side`/`available today` の冗長を除去）。

```diff
+ The kernel-side packet filters available today trade expressiveness for
+ in-kernel execution.
  tcpdump/libpcap's pcap-filter descends from the Packet
  Filter~\cite{mogul1987packetfilter} and the BSD Packet
  Filter~\cite{mccanne1993bpf} and runs L2--L4 conditions in the kernel.
  As \S\ref{sec:intro} noted, it has no syntax for repeated protocols or
  for walking variable-length lists such as an SRv6 segment list or TCP
```
**日本語訳**:
```diff
+ 現在の kernel 側 packet フィルタは、表現力と in-kernel 実行をトレードオフしている。
  tcpdump/libpcap の pcap-filter は Packet Filter / BSD Packet Filter の系譜で、kernel
  内で L2–L4 条件を動かす。§1 で述べたとおり、繰り返しプロトコルや SRv6 セグメント/
  TCP オプションのような可変長リストをフィールド名で辿る構文は持たない…
```
→ 狙い: 段落主題（in-kernel フィルタの表現力 vs 実行可能性のトレードオフ）を先頭に。後続の pcap-filter/Wireshark/xdpcap/xdpdump 列挙が主題に沿って読める。

---

## ✅ A5 🔴 xdpcap の一文を読みやすく（§2 para1 中盤, ayako 提案採用）— 適用済み 2026-06-25（latexmk OK）

```diff
  options by field name; the more expressive Wireshark display
  filter~\cite{wireshark_dfref} runs only in userspace. Tools that capture
- at the XDP layer do not close this gap. xdpcap filters in the kernel but
- with a pcap-filter~\cite{cloudflare2019xdpcap}, inheriting the same
- limit; xdpdump has no in-kernel filter, capturing via fentry/fexit and
+ at the XDP layer do not close this gap. xdpcap runs filters in the
+ kernel, but its filter language is still
+ pcap-filter~\cite{cloudflare2019xdpcap}, inheriting the same limit;
+ xdpdump has no in-kernel filter, capturing via fentry/fexit and
  leaving matching to tcpdump~\cite{xdptools_xdpdump}. Neither selects
  packets in the kernel by a field condition past nested encapsulation.
```
**日本語訳**:
```diff
  …より表現力のある Wireshark display filter は user 空間でしか動かない。XDP 層で
  capture するツールもこのギャップを埋めない。
- xdpcap は kernel でフィルタするが pcap-filter で行うため[4]、同じ限界を継ぐ。
+ xdpcap は kernel でフィルタを動かすが、フィルタ言語は依然 pcap-filter[4] で、
+ 同じ限界を継ぐ。
  xdpdump は in-kernel フィルタを持たず fentry/fexit で capture し照合は tcpdump に任せる。
  いずれも nested encap 越しのフィールド条件で kernel 内選別はしない。
```
→ 狙い: 「filters in the kernel but with a pcap-filter」の圧縮表現を、主語＋言語の形へ（ayako 提案）。

---

## ✅ A6 🔴 "Honey for the Ice Bear" を著者引用へ（§2 para3 中盤）— 適用済み 2026-06-25（latexmk OK）

```diff
  Among combinations of P4 and eBPF, p4c-ebpf and p4c-xdp compile a P4
  data-plane program to Linux eBPF / XDP /
- tc~\cite{p4c_ebpf, tu2018p4cxdp}, and Honey for the Ice Bear embeds
- dynamically loaded eBPF inside a P4 pipeline~\cite{simon2024honey}.
+ tc~\cite{p4c_ebpf, tu2018p4cxdp}, and Simon et
+ al.~\cite{simon2024honey} embed dynamically loaded eBPF inside a P4
+ pipeline.
  These move an entire P4 pipeline to the target rather than returning
  per-packet match/reject from a filter expression; \kunai instead uses P4
```
**日本語訳**:
```diff
  P4 と eBPF の組合せでは、p4c-ebpf/p4c-xdp が P4 データプレーンプログラムを Linux
  eBPF/XDP/tc にコンパイルし、
- Honey for the Ice Bear は動的ロードした eBPF を P4 pipeline 内に埋め込む[23]。
+ Simon ら[23] は動的ロードした eBPF を P4 pipeline 内に埋め込む。
  これらは P4 pipeline 全体を target に移す方式で…
```
→ 狙い: 論文タイトルを地の文に生で出さず `Simon et al.~\cite{}` に統一。

---

## ☐ A7 🟡 「P4 を部分的にしか使わない」印象を課題適合で語り直す＋`p4spec` 外す（§2 para3末）

A6 と同段落（context の Honey 行は A6 適用後 Simon et al. になる）:
```diff
  tc~\cite{p4c_ebpf, tu2018p4cxdp}, and Honey for the Ice Bear embeds
  dynamically loaded eBPF inside a P4 pipeline~\cite{simon2024honey}.
- These move an entire P4 pipeline to the target rather than returning
- per-packet match/reject from a filter expression; \kunai instead uses P4
- only as a protocol definition, not as a data-plane language~\cite{p4spec}.
+ These compile an entire P4 pipeline to the target rather than returning
+ per-packet match/reject from a filter expression, so they do not address
+ filtering past nested encapsulation. \kunai uses P4 only to declare
+ protocol headers and parsing, keeping the filter itself a DSL expression.
```
**日本語訳**:
```diff
  …Simon ら[23] は動的ロードした eBPF を P4 pipeline 内に埋め込む。
- これらは P4 pipeline 全体を target に移すだけで per-packet match/reject を返さない。
-   Kunai は代わりに P4 を protocol 定義としてのみ使い data-plane 言語にはしない[19]。
+ これらは P4 pipeline 全体を target にコンパイルするだけで per-packet match/reject を
+   返さず、nested encap 越しのフィルタには応えない。Kunai は P4 を protocol
+   header/parser 宣言にだけ使い、フィルタ自体は DSL 式のまま。([19] はここから外す)
```
→ 狙い: ayako「既存研究は我々の課題に解を提供できるのか」を明示。「only…not…」の自己限定調を肯定形に。`p4spec` はここから外す（§1 L49・§3.3 で既出なので失われない）。**user 判断**: 引用整理。

---

## ☐ A8 🔴 先回り否定「rather than restricting an existing DSL,」削除（§2 para4末）

```diff
  We adopt the recent \emph{verifier-safe} goal argued by Solleza et
  al.~\cite{solleza2025verifiersafe}: a kernel-extension DSL should
  compile every well-formed program to bytecode the verifier accepts.
  \kunai is a concrete instance of that position for packet filtering over
- nested encapsulation: rather
- than restricting an existing DSL, we identify the code-generation
+ nested encapsulation: we identify the code-generation
  patterns the goal demands when a filter reaches past variable-length
  structure (\S\ref{sec:codegen}).
```
**日本語訳**:
```diff
  …kernel 拡張 DSL は全 well-formed プログラムを verifier 受理 bytecode へコンパイル
  すべき、という最近の verifier-safe 目標（Solleza ら）を我々は採る。Kunai は nested
  encap 越しのパケットフィルタにおけるその立場の具体例である：
- 既存 DSL を制限するのではなく、目標が要求する code-generation パターンを、フィルタが
-   可変長構造を越えて到達するときに同定する(§4)。
+ 目標が要求する code-generation パターンを、フィルタが可変長構造を越えて到達する
+   ときに同定する(§4)。
```
→ 狙い: ayako「先回り否定が多発・言い訳がましい」。肯定形だけ残す（A3 と合わせ横断のヘッジ掃除）。

---

## ☐ A9 🟡 まとめ段落(§2 para5) — 圧縮 or 削除

ayako「各段落末で限界を述べているなら、この段落は不要では」。**case 1: 圧縮（推奨）**:
```diff
  patterns the goal demands when a filter reaches past variable-length
  structure (\S\ref{sec:codegen}).

- The work above has separately addressed packet-filter execution, filter
- expression over nested encapsulation, P4-to-eBPF compilation, and the
- goal of verifier-safe lowering. \kunai joins two of these: it brings
- nested encapsulation and variable-length structure into the filter
- expression and compiles the result into bytecode the verifier accepts,
- generalized across the protocols declared in the P4 subset
- (\S\ref{sec:codegen}).
+ \kunai brings nested encapsulation and variable-length structure into the
+ filter expression and compiles the result into bytecode the verifier
+ accepts, generalized across the protocols declared in the P4 subset
+ (\S\ref{sec:codegen}).
```
**case 2: 段落ごと削除**（上記 `+` も消す。ayako の趣旨に最も忠実）。
**日本語訳（case1 圧縮）**:
```diff
  …フィルタが可変長構造を越えて到達するときに同定する(§4)。

- 上記研究はフィルタ実行/nested encap 上の式/P4→eBPF/verifier-safe を別々に扱ってきた。
-   Kunai はそのうち 2 つを繋ぐ：nested encap と可変長構造を式に取り込み verifier 受理
-   bytecode へコンパイルし、P4 subset で宣言した protocol 全体に一般化(§4)。
+ Kunai は nested encap と可変長構造をフィルタ式に取り込み、verifier 受理 bytecode へ
+   コンパイルする。P4 subset で宣言した protocol 全体に一般化(§4)。
```
→ **user 判断**: positioning 再掲として残す価値があるか。case1 は列挙の重複だけ落として positioning 1 文を残す折衷。

---

## 横断 ☐ ヘッジ一掃（A3・A8 の方針確定後）

`rather than` / `is not enough` / `not as a` / `we do not claim` 等を grep で洗い、1 件ずつ採否（機械置換しない）。

## 適用順
1. 即採用（🔴）: A1, A2, A4, A5, A6, A8 → まとめて当てる。
2. user 判断（🟡）: A3, A7, A9。
3. ヘッジ一掃: A3/A8 確定後に横断 grep。

**未適用**。承認後に tex 反映 → `latexmk` ビルド確認。
