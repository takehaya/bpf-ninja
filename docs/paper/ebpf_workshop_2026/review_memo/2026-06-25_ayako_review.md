# ayako_iwasaki レビュー 整理（2026-06-24 workshop 論文コメントスレ）

対象: §1 Introduction（`sections/01_introduction.tex`）/ §2 Related Work（`sections/02_related.tex`）
9 件。種別: 🧱構成 / 🔀流れ・論理 / ✍表現・可読性 / 📚引用作法 / 🛡ヘッジ（言い訳・先回り否定）

> 横断テーマ: ayako は **A3 と A8** で「先回り否定・言い訳くさい・LLM 臭い保険」を 2 度指摘。ヘッジ表現は方針として一度まとめて削る/弱める判断をしておくと、他にも効く。

---

## §1 Introduction

### ☐ A1 🧱🔀 「likewise」で異質な 2 文を繋いでいる + 段落の置き場所
- 場所: `01_introduction.tex` L29-31
- 引用: "User studies of packet-analysis tools likewise report protocol coverage and the expressiveness of the filter language as open problems [25]."
- 指摘: 直前文（Wireshark など userland は柔軟）と本文は別のことを言っているのに `likewise` で繋がっている。userland はいくらでも柔軟にできるはずで、この段落にこの文があるのが妙。**「現状柔軟になっていない側（pcap-filter 等）」の説明に置くべき**。
- 対応案: `likewise` を外し、この一文を「pcap-filter の表現力の限界」を述べる箇所（段落前半 or §1 para1 末）へ移設。"open problems" は pcap-filter 側の課題として接続。

### ☐ A2 🔀 「Expressiveness alone is not enough.」が前段落から繋がらない
- 場所: `01_introduction.tex` L33（para3 冒頭）
- 指摘: 前段落が「表現力ある手法はあるが kernel path で実行できない」で終わっているので、「表現力だけでは不十分」が論理的に繋がらない。前段落が「我々は表現力を実現した！」で終わるなら自然だが、そうではない。
- 対応案: para3 冒頭を「表現力は(既存研究で)あるが、それを kernel で verifier 通過させるのが残課題」と橋渡しする一文に。例: "Even where such expressiveness exists, running it in the kernel requires bytecode the verifier accepts." 系へ。

### ☐ A3 🛡 「not as a formal guarantee (§6)」が言い訳くさい
- 場所: `01_introduction.tex` L57-59
- 引用: "We establish it empirically across six kernels (§5), not as a formal guarantee (§6)."
- 指摘: 残したいなら止めないが、やはり言い訳くさい。limitation(§6) に書いてあるので intro で断る必要はないのでは。
- 対応案: `, not as a formal guarantee (\S\ref{sec:limitations})` を削除（§6 に委ねる）。→ A8 と同じ「ヘッジ削減」方針で処理。**user 判断**（残すなら理由を一言に圧縮）。

---

## §2 Related Work

### ☐ A4 🧱 先頭段落に topic sentence がない
- 場所: `02_related.tex` L4（para1 冒頭）
- 指摘: 冒頭が tcpdump/libpcap の pcap-filter の話かと思って読むと別ツール(xdpcap 等)が出てくる。段落の主題を示す topic sentence が要る。
- 対応案: para1 の頭に「この段落は『kernel で動く既存フィルタ』とその限界を概観する」と分かる一文を足す。例: "Existing in-kernel packet filters either lack the expressiveness this paper targets or do not run past nested encapsulation." 系。

### ☐ A5 ✍ xdpcap の一文が読みにくい
- 場所: `02_related.tex` L11-12
- 引用: "xdpcap filters in the kernel but with a pcap-filter [4], inheriting the same limit;"
- 指摘: 読みにくい。提案: "xdpcap runs filters in the kernel, but the filter language is still pcap-filter, inheriting the same limit" 系。
- 対応案: ayako 提案文をほぼそのまま採用。"filters in the kernel but with a pcap-filter" → "runs filters in the kernel, but its filter language is still pcap-filter,"。

### ☐ A6 📚 "Honey for the Ice Bear" を生でタイトル出ししている
- 場所: `02_related.tex` L30-31
- 引用: "...and Honey for the Ice Bear embeds dynamically loaded eBPF inside a P4 pipeline [23]."
- 指摘: 何事かと思った（論文タイトルをそのまま地の文に出している）。`Simon et al. [23] embed...` の形にすべき。
- 対応案: "Honey for the Ice Bear embeds" → "Simon et al.~\cite{simon2024honey} embed"。著者引用に統一。

### ☐ A7 🔀📚 「P4 を部分的にしか解釈しない」と読めてしまう + 引用位置
- 場所: `02_related.tex` L33-34
- 引用: "\kunai instead uses P4 only as a protocol definition, not as a data-plane language [19]."
- 指摘: これだと「我々は P4 を部分的にしか解釈できません」と主張しているように見える。**大事なのは「解こうとしている課題に対して、それら既存研究(P4 系)は解を提供できるのか」**。あと P4 spec([19]/`p4spec`) をここで引くのが適切か疑問。
- 対応案: 言い回しを「P4 系は pipeline 全体を target に移すので、フィルタ式から per-packet match/reject を返すという我々の課題には応えない。Kunai は P4 を protocol 定義としてのみ使う」と、**課題に対する既存研究の不足→Kunai の立ち位置**の順に。`\cite{p4spec}` はこの文から外す（既に §3.3 で引いている／必要なら p4c 系の引用に）。**user 判断**: 引用先の整理。

### ☐ A8 🛡 「rather than restricting an existing DSL,」= 先回り否定
- 場所: `02_related.tex` L40-41
- 引用: "...\kunai is a concrete instance of that position...: rather than restricting an existing DSL, we identify the code-generation patterns..."
- 指摘: こうした**先回りして否定するパターンが多発**している。LLM 特有の保険？言い訳がましく印象が良くない。
- 対応案: `rather than restricting an existing DSL,` を削除し、肯定形だけ残す。例: "\kunai is a concrete instance of that position for packet filtering over nested encapsulation, identifying the code-generation patterns the goal demands ...". → **A3 と合わせ「ヘッジ一掃」として横断対応**。

### ☐ A9 🧱 まとめ段落（para5）が不要では
- 場所: `02_related.tex` L45-51
- 引用: "The work above has separately addressed packet-filter execution, ... \kunai joins two of these: ..."
- 指摘: 各段落の末尾で各既存研究の限界を既に述べているなら、この総括段落自体が不要なのでは。
- 対応案: 3 択を提示して **user 判断**:
  1. 段落ごと削除（各段落末の限界で十分、最も ayako の趣旨に沿う）。
  2. 1-2 文に圧縮して「Kunai は (execution × nested-encap expression) の 2 つを繋ぐ」という positioning だけ残す。
  3. 残す（contribution の再掲として機能している、と判断するなら）。

---

## 対応の進め方（提案）
1. **ヘッジ一掃（A3・A8）** を方針決定 → 機械的に削れる。横断で他のヘッジ表現も grep して同時掃除。
2. **§2 の局所修正（A5・A6）** は ayako 提案をほぼ採用で即対応。
3. **構成系（A1・A2・A4・A7・A9）** は文の移動・topic sentence 追加・段落削除を伴うので、1 件ずつ before/after を出して確認しながら。
4. 各件、確定したら別 `*_apply_checklist.md`（既存の慣習）に diff を起こして tex 反映。

---

## 原文（Slack スレ, ayako_iwasaki 2026-06-24）

```
ayako_iwasaki [22:30] workshop 論文のコメントスレ (20260624)  8 件の返信

[22:31] User studies of packet-analysis tools likewise report protocol
coverage and the expressiveness of the filter language as open problems [25].
この文とその前の文の言っていることは異なる気がするが、likewise となってしまっている。
userland でやる時はいくらでも柔軟にできるはずなので、この段落にこの分があるのがちょっと妙な気がする。
現状柔軟になっていないところ (pcap filter とか) の説明にこの文を置くべきだと思います

[22:34] Expressiveness alone is not enough.
もよくわかんなくて、前の段落が「我々の方法では表現力を持つようにできました！」ていう報告で
終わってるなら流れとしてわかるんだけど、その前の段落は「表現力のある方法はあるが kernel path
で実行できません」だからなあ。

[22:37] , not as a formal guarantee (§6).
これ残したいなら止めないけど、やっぱちょっと言い訳くさいです。limitation に書いてあるから十分なのでは？

[23:01] Related work 先頭段落
先頭に topic sentence がない気がする。tcpdump/libpcap's pcap-filter の話かと思ってよんでたら
違うツールの話が出てきた
xdpcap filters in the kernel but with a pcap-filter [4]
私の英語力の問題かもしれないが、xdpcap runs filters in the kernel, but the filter language is
still pcap-filter, inheriting... とかの方が読みやすい気がします

[23:05] Honey for the Ice Bear: これマジで何事かと思った、そういう論文タイトルなのね？
Simon et al. [23] embed... とかすべきでは？

[23:11] Kunai instead uses P4 only as a protocol definition, not as a data-plane language [19].:
これだと我々は P4 を部分的にしか解釈できませんと主張しているように見えてしまう。解こうとしている
課題に対してそれらの既存研究は解を提供できるのか？ が大事な気がしています。あと P4 の spec を
引用するのはここでいいのか？

[23:24] rather than restricting an existing DSL,: こういう先回りして否定するパーンがかなり
出てきてる、LLM 特有の保険？ 言い訳がましくてあまりいい印象はない

[23:25] The work above has separately addressed packet-filter execution,: 各段落の末尾で各既存
研究の限界を述べているなら、この段落自体が不要なのではという気がする
```
