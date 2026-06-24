# 論文ドラフト

このドラフトは `hand_skeleton_ja.md` を基準に本文化したものです。主役は Kunai DSL / bytecode 生成であり、xdp-ninja は Kunai が生成した filter bytecode を実際の datapath に載せる実行基盤・評価基盤としてのみ扱います。
最終的に英訳し、eBPF Workshop 2026向けに提出する予定です。
Workshopなので2段組6枚ぐらいになりそう。
ちなみに、サイテーションは6ページの制限外です。


8,000〜10,000字: 6ページ英語版にかなり寄せた日本語ドラフト
10,000〜12,000字: 内容を選別しながら英訳すれば収まりやすい
12,000〜15,000字: フルドラフトとしては良いが、英訳時に圧縮が必要
15,000字超: 6ページ workshop paper には長い。技術報告やextended draft寄り
今の書き方は説明が丁寧なので、日本語では 12,000字前後まで書いてから、英訳時に4,000 words前後へ圧縮する流れがよさそうです。

ざっくり配分するなら：

節	日本語目安
要旨	400〜600字
1. はじめに	1,800〜2,500字
2. 関連研究	1,200〜1,800字
3. 設計	2,000〜2,800字
4. Codegen	2,000〜2,800字
5. 評価	2,000〜2,800字
6. Limitation / Discussion	800〜1,200字
7. 結論	300〜600字
なので、日本語ドラフト段階では 10,000〜13,000字くらいを実用ラインに置くのが一番やりやすいと思います。今の原稿はすでに「論文に必要な材料を全部置く」方向なので、次は文字数を気にしすぎず一度完成させて、そのあと英語6ページ用に圧縮するのがよさそうです。

<comment></comment>で囲まれているのはメモです。レビューなどでは本文として解釈しないでください。ただし、レビューコメントとして考慮してもらう分には構いません。
<comment_img></comment_img> は図の配置マーカー兼メモです。本文の図参照 (「図 N」) が指す図ファイル・caption・配置位置を記録します。本文としては解釈せず、英語版で実際の図と \figref に置き換えます。書式は「図N | label | file: paper/figures/xxx.pdf | caption: ... | 英語版: \figref{label}」。
「手修正なしで」を禁止する。修正するワークフローをそもそも想定していないので。

サブセクション（サブセクションがない場合はセクション）の末尾には、そこでつまり何が言いたいかのまとめ文があるといい

<comment>
TODO
この論文によって、どんな知見が得られた？を書いておきたい。→評価に対応する一文が欲しい。
pcap-filterで書けない、→書けるようになった
それは、実際にverifierを通って、動いており、性能におけるオーバーヘッドのコストもほぼ変わらないねという話を確認した

書くときのポイントはabst/1章/結論にかけるといい感じ。なぜなら読む側が全部読むのが大変だから
行った話があるなら、その結果も併せて書きたい
</comment>

abst 7文ぐらい→まぁ改行潰せば・・・(一旦大丈夫)
https://www.researchrabbit.ai/articles/write-an-abstract-for-a-research-paper

適切なタイミングで社内手続きは必要。。。
NTTとかはそういうのが必要っぽい。

もらったコメント
INTRODUCTIONにこういうのは書けないよねを一個持ってきたい。そうすると課題がわかりやすい。
multi level encapの意義をちゃんと書きたい
[src==10.0.0.0/8] みたいなのって使い分けって何？、可読性のための糖衣構文です

full dslに関してはリンクがあるよみたいなのがあると嬉しいかも
\begin{lstlisting}[float, caption={途中で改ページされないコード}]
// ここにソースコード
// ページに収まらない場合は自動的に次のページに送られます
\end{lstlisting}

オーサーの順番こうかな...?
takemio
ternbusty-san
zin-san
kotani-san

---

## 要旨

Packet capture や network debugging では、目的に合う packet を Linux kernel 内の早い段階で選別する必要がある。しかし、広く使われる pcap-filter は、nested encapsulation、同一 protocol の複数出現、packet ごとに長さが変わる list や option を扱う構文を持たない。さらに、filter を kernel 内で実行するには、Linux eBPF verifier が受理する bytecode を生成する必要がある。

我々は、packet filter DSL の Kunai と、その式を eBPF bytecode に変換する compiler を提案する。Kunai は packet の層構造と field 条件を 1 つの式として記述し、P4 言語の subset で書かれた protocol 定義から field の位置と型を解決する。compiler は、各 header の開始位置を実行時に記録し、可変長構造の走査に定数上限を与え、すべての packet 読み出しの前に境界確認を置いた eBPF bytecode を生成する。

評価では、GTP-U や SRv6 を含む filter 条件を Kunai で記述できること、生成した bytecode が Linux kernel で verifier に受理され、期待した packet を match / reject すること、および packet あたりの実行コストが、両方で書ける filter では pcap-filter と同程度であることを確認した。これにより、pcap-filter では記述できなかった filter 条件を Linux kernel 内で実行することが可能になった。

## 1. はじめに

Packet capture は、network system の debugging や障害解析における基本操作である。link 帯域と traffic 量の増加により、すべての packet を userspace へ転送して保存する方式は成り立たない。そのため、packet capture tool には、目的に関係する packet だけを kernel 内の早い段階で選別することが求められる。この選別には tcpdump/libpcap の `pcap-filter` が広く使われてきた [2,3]。

`pcap-filter` は、L2-L4 の header field に対する条件を記述できる。一方で、nested encapsulation、同一 protocol の複数出現、packet ごとに長さが変わる list や option を扱う構文を持たない。例えば、GTP-U や Geneve tunnel の inner IPv4、SRv6 segment list、TCP options では、対象 field の位置が packet ごとに変わる [15,16,17,18]。これらの encapsulation は例外的なものではなく日常的に存在する。GTP-U は mobile network の user-plane traffic を運び、SRv6 や Geneve は datacenter や WAN の overlay を支え、TCP options は MSS や window scaling など、ほぼすべての connection の SYN に現れるため、kernel の capture tool はこれらに遭遇する。Wireshark の display filter [19] のように、これらの構造を field 名で辿れる filter language も存在する。ただし、これらは userspace 上で完全に parse 済みの packet を対象に任意の field を random access で読む評価器であり、parse 済みの view を持たず各読み出しに verifier への境界証明を要求する kernel datapath には、その評価モデルをそのまま持ち込めない。このため capture 後の userspace 評価に限られ、kernel datapath の早い段階では実行できない。packet analysis tool の利用者調査でも、対応 protocol の範囲と filter expression の表現力が課題として報告されている [1]。

表現力だけでは足りない。こうした filter を kernel 内で実行するには、verifier が受理する eBPF bytecode に compile する必要がある [12,13,21]。P4 を eBPF に変換する p4c-xdp [11] などの compiler は既に verifier が受理する code を生成するが、これらが変換するのは固定の protocol pipeline であり、nested encapsulation の奥や可変長 list 上に対象 field を持つ filter expression ではない。そのような field の offset は実行時まで定まらず、素直な変換は verifier が境界を確認できない位置を読むため、bytecode が拒否される。我々の知る限り、表現力と、in-kernel の verifier が受理する形の両方を同時に与える既存手法は無い。

我々は、この 2 つの要件を満たす filter DSL と compiler である Kunai を提案する。Kunai は packet の層構造を layer-chain として記述し、P4 言語の subset で書かれた protocol 定義から field の位置と型を解決し [9]、filter expression を eBPF bytecode に変換する。Kunai はこの変換を、各 header の開始位置を実行時に記録し、可変長構造の走査に compile 時の定数上限を与え、すべての packet 読み出しの前に verifier が確認できる境界確認を置くことで行い、その詳細を 4 章で述べる。本稿で用いる verifier-safe という語は Solleza らの意味、すなわち整形式の filter は verifier が受理する bytecode にコンパイルされるべきだ、という意味であり、本稿はこれを 6 つの kernel での empirical な evidence として示すものであって、formal な保証ではない（6 章）。

評価では、GTP-U や SRv6 を含む filter を Kunai で記述でき、生成した bytecode が Linux 6.1 から 7.0 の 6 つの kernel version にわたって verifier に受理され、期待どおりに match / reject し、packet あたりのコストが、両方で書ける filter では pcap-filter と同程度であることを確認した。

## 2. 関連研究

tcpdump/libpcap の `pcap-filter` は、Packet Filter [4] と BSD Packet Filter [3] に始まり、L2-L4 header の条件を kernel 内で実行する。ただし 1 節で述べたとおり、同一 protocol の複数出現や、SRv6 segment list・TCP options のような可変長要素を field 名で辿る構文を持たず、より表現力の高い Wireshark の display filter [19] は userspace 評価に限られる。XDP 層で capture するツールもこの gap を埋めない。xdpcap は XDP program の出口で kernel 内 filter を行うが、その言語は pcap-filter であり、同じ表現力の限界を継ぐ。xdpdump は kernel 内 filter を持たず、fentry/fexit で XDP の入口または出口で capture し、照合はすべて下流の tcpdump に委ねる。いずれも nested encapsulation の奥に達する field 条件で kernel 内選別を行わない。

Encapsulation を扱う filter の先行研究には、NetPDL / NetPFL と pFSA / xpFSA がある。NetPDL / NetPFL は、protocol header の記述と tunnel を含む filter expression を結びつける [5,6]。pFSA / xpFSA は、encapsulation 内で header が現れる順序を状態遷移として表し、filter の合成と field access を定式化する [7,8]。これらは、nested encapsulation を filter の表現に取り込む点で本稿と問題意識を共有する。一方で、これらの filter model は Linux kernel datapath に load できる eBPF bytecode を出力せず、本稿が前提とする in-kernel での実行を与えない。

P4 と eBPF の組合せでは、p4c-ebpf と p4c-xdp が P4 data-plane program を Linux eBPF / XDP / tc にコンパイルし [10,11]、Simon らの Honey for the Ice Bear（eBPF'24）は P4 pipeline の内側に動的にロードする eBPF を埋め込む。これらは P4 pipeline 全体、あるいはその内側の eBPF を target へ移すものであり、filter expression から packet ごとの match / reject を返す filter 言語ではない。Kunai は、P4 を data-plane language ではなく protocol 定義としてのみ用いる点でこれらと異なる [9]。

我々は、Solleza らが近年論じた verifier-safe というゴール、すなわち kernel 拡張の DSL は整形式の program をすべて verifier が受理する bytecode にコンパイルすべきだ、という立場を採用する（"Kernel Extension DSLs Should Be Verifier-Safe!", eBPF'25）。Kunai は、nested encapsulation を対象とする packet filter において、この立場を具体化した一例にあたる。既存の DSL を制限するのではなく、可変長構造の先まで届く filter が verifier の範囲に収まるために要求する code 生成パターンを特定した（4 節）。

以上の研究は、packet filter の実行機構、nested encapsulation を扱う filter の表現、P4 program の eBPF 化、verifier-safe な変換という目標をそれぞれ扱ってきた。Kunai はこのうち 2 つを結びつける。すなわち、nested encapsulation と可変長構造を filter expression に取り込み、その結果を verifier が受理する bytecode に compile し、P4 subset で宣言した protocol 全体に一般化する。

## 3. 設計

### 3.1 全体像

Kunai の全体像を図 1 に示す。Kunai compiler の入力は 2 つである。第一の入力は Kunai DSL expression であり、利用者が書く filter 条件である。第二の入力は P4 subset で書かれた protocol の定義集であり、protocol header と parser rule の database である。

Kunai compiler は、まず layer-chain を解釈する。具体的には、各 protocol が定義上接続できるかを確認し、同一 protocol が複数回現れる場合には label を layer slot に対応付ける。次に、field 参照を protocol 定義に対して解決し、各 field が属する layer、offset、bit 幅を得る。補助 header list や option への参照がある場合は、走査対象と走査に必要な情報も IR に記録する。また、存在しない field への参照、同一 protocol が複数回現れる場合の、`tcp.dport` のように protocol 名で field を指す `proto.field` 参照、型や bit 幅が合わない比較は、この解析段階で拒否する。

Kunai compiler の出力は、filter 条件を packet に対して評価し、match / reject の結果を返す eBPF bytecode である。実行時には、XDP [20]、tc [23]、fentry/fexit などの attach point に置く BPF program がこの bytecode を組み込む。この分担により、Kunai compiler は filter 条件の解析と bytecode 生成を担い、attach point 固有の context access と、capture や drop などの後続処理は実行側の BPF program が担う。

<comment_img>図1 | fig:arch | file: paper/figures/fig_arch.pdf | caption: Kunai の全体像。filter expression と P4 protocol 定義を入力に parse/resolve/codegen を経て match/reject の eBPF bytecode を生成し、host BPF program が attach point で組み込む。 | 配置: §3.1 冒頭 | 英語版: \figref{fig:arch}</comment_img>

### 3.2 DSL が表現するもの

Kunai DSL は、packet の層構造と field 条件を 1 つの filter expression として記述する。構文の抜粋を図 2 に示す。文法の全文は project の repository で公開している。

```ebnf
filter       ::= layer-chain where-clause?
layer-chain  ::= layer ('/' layer)*
layer        ::= layer-atom quantifier?
layer-atom   ::= proto-name ('@' label)? predicate?
               | '(' layer ('|' layer)+ ')'
quantifier   ::= '?' | '+' | '*' | '{' INT '}' | '{' INT ',' INT '}'
predicate    ::= '[' comparison (',' comparison)* ']'
where-clause ::= 'where' bool-expr
bool-expr    ::= comparison | quant-atom
               | '(' bool-expr ')' | bool-expr bool-op bool-expr
comparison   ::= field-ref op value
quant-atom   ::= ('any' | 'all') '(' bool-expr ')'
field-ref    ::= ident index? ('.' ident index?)*
```

<comment_img>図2 | fig:grammar | file: (listing、画像なし) | caption: Kunai filter 式の文法抜粋。 | 配置: §3.2 (この ebnf ブロックを figure 化) | 英語版: \figref{fig:grammar}。EN では lstlisting を figure[t] にして列跨ぎの分割を回避。</comment_img>

Layer-chain は、packet 内に現れる protocol の順序を `/` で並べた表現であり、optional layer、繰り返し、選択も表せる。`where` 句は、chain 内の layer や補助的な header / list の field に対する条件式である。Kunai は field reference を次の形に解決する。表中の `<stack>` は literal ではなく、`segments` や `exts` のように protocol 定義で付けられた補助 header list 名である。

| 形 | 例 | 意味 |
|---|---|---|
| `proto.field` | `tcp.dport` | chain 内で一意な protocol の primary header field |
| `label.field` | `inner.dst` | `@inner` のような label が付いた layer の field |
| `proto.aux.field` | `gtp.opt.next_ext` | optional header や補助 header の field |
| `proto.<stack>[N].field` | `srv6.segments[0].addr` | 補助 header list の静的 index |
| `proto.<stack>.field` | `srv6.segments.addr` | `any()` / `all()` 内で走査中の要素 |
| `proto.options.NAME.field` | `tcp.options.MSS.value` | TCP / IPv4 option lookup |

Kunai は、bracket predicate 内の field reference をその layer への相対参照として解釈する。`where` 句では、`proto.field` や `label.field` のように layer を明示する参照を用いる。

同一 protocol が chain 内に複数回現れる場合、`proto.field` だけでは読む layer が決まらない。例えば、chain 内に outer IPv4 と inner IPv4 がある場合、`ipv4.dst` はどちらの destination field か一意に決まらない。Kunai はこの参照を bytecode 生成前に拒否し、label による参照を要求する。例えば、GTP-U tunnel の内側 IPv4 destination に対する filter は次のように書く。

```kunai
eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where inner.dst == 10.0.0.1
```

`where` の前の chain は、辿る layer を Ethernet、outer IPv4、UDP、GTP、inner IPv4、TCP の順に並べる。`where` 句は、chain が match した後に確認する field 条件を与え、ここでは inner IPv4 の destination が 10.0.0.1 に等しいことを表す。この式では、`@outer` と `@inner` が 2 つの IPv4 layer を区別する。`inner.dst` は inner IPv4 の destination field を一意に指すため、同じ `ipv4` header が 2 回現れても、Kunai は読むべき field を決定できる。

可変長 list には `any()` や `all()` を使う。例えば、SRv6 segment list の中に特定の address が含まれる packet にマッチする filter は次のように書く。

```kunai
eth/ipv6/srv6 where any(srv6.segments.addr == fc00::1)
```

`any()` と `all()` の走査対象は、内側の式で index を省略して参照される補助 header list であり、走査対象はちょうど 1 つでなければならない。同じ list は式中で複数回参照してよい。例えば `any(srv6.segments.addr == fc00::1 or srv6.segments.addr == fc00::2)` のように書ける。index を省略した list を参照しない、あるいは異なる 2 つを参照する `any()` / `all()` は、どちらか一方を走査するのではなく解析段階で拒否する。このため、2 つの list を走査するように見える量化子は書けない。Kunai は、その list の各要素に対して内側の条件を評価する。この走査には、要素数を得る field、各要素の幅、次の要素へ進む方法、停止条件が必要であり、protocol 定義がこれらの情報を与える。TCP options や GTP extension headers も、protocol 定義がこの情報を持つ場合は同じ方法で扱える。

これらの構文により、Kunai DSL は、header の出現順、同一 protocol の複数出現の区別、可変長 list の走査対象を filter expression の中で指定する。bytecode 生成は、この情報を用いて各 field access を layer 開始位置からの offset と bit 幅に変換する。

### 3.3 P4 subset による protocol 定義

Kunai は、protocol header と parser rule の記述に P4 言語の subset を使う [9]。P4 は protocol header と parser transition を記述する構文を持つため、既存の P4 parser 記述を protocol 定義を書く際の参考にできる。また、独自の protocol 記述言語を新設する場合に必要となる syntax checker、parser、tooling、仕様の実装と保守を避けられる。

Kunai が扱う P4 subset は、header layout と parser transition を記述する部分に限られる。次の listing は SRv6 の protocol 定義であり、3.2 節の `any()` の例と 5 章の F8 はこの定義を用いる。

```p4
header srv6_h {
    bit<8>  next_header;
    bit<8>  hdr_ext_len;    // 8-byte 単位
    bit<8>  routing_type;   // 4 = SRH
    bit<8>  segments_left;
    bit<8>  last_entry;
    bit<8>  flags;
    bit<16> tag;
}
header srv6_seg_h { bit<128> addr; }
const bit<8> SRV6_IPV6_NEXT_HEADER = 43;
parser SRv6Parser(packet_in pkt, out srv6_h hdr,
    @kunai_layout[after=primary]
    @kunai_stack_count[field=last_entry, offset=1]
    out srv6_seg_h[8] segments) {
  state start {
    pkt.extract(hdr);
    transition select(hdr.routing_type) {
      4: skip_segments;  default: reject;
    }
  }
  state skip_segments {
    pkt.advance(((bit<32>)(hdr.hdr_ext_len & 0x0F)) << 6);
    transition accept;
  }
}
```

この定義は、Kunai compiler が必要とする情報を 3 つの構文で与える。第一に、`header` 宣言が各 field の offset と bit 幅を与える。第二に、`const` と `transition select` が、IPv6 から SRv6 への dispatch と、`routing_type` による受理判定を与える。第三に、annotation が可変長部分の走査メタデータを与える。`@kunai_layout` は `segments` list が protocol の固定長 header 部の直後から始まることを、`@kunai_stack_count` は要素数を `last_entry + 1` として読み出すことを示し、4 章の上限付き走査がこれらを用いる。`srv6_seg_h[8]` の容量 8 は、走査回数の compile 時上限になる。また、`skip_segments` の `pkt.advance` は、可変長部分の advance 量を mask により最大 120 byte に制限し、verifier に静的な上限を見せる。

このように、protocol 定義は、layout、dispatch、走査メタデータを P4 構文の範囲で記述する。protocol 定義を追加することで、compiler 本体を変更せずに対応 protocol を拡張できる。

## 4. Verifier 制約下の Bytecode 生成

本章では、Kunai DSL の filter expression を、Linux eBPF verifier が受理する packet access、loop、bounds check の形に変換する方法を述べる。nested encapsulation や可変長構造によって後続 header の開始位置が packet ごとに変わると、その runtime offset で field を読む素直な変換は読み出し範囲を verifier が確認できず拒否される。以下の bytecode 生成がこの拒否を避ける。

難しいのは offset が動的だと気づくことではなく、その読み出しを、可変長 layer 以降の全 layer でも、P4 subset の全 protocol でも同じやり方で、verifier が受理する形に落とすことにある。Kunai の bytecode 生成は、packet ごとに変わる後続 header の開始位置を実行時に記録し (4.1 節)、SRv6 segments や TCP options のような可変長構造を compile 時の上限付きで走査し (4.2 節)、すべての packet 読み出しの前に verifier が確認できる bounds check を置く。

### 4.1 Header の開始位置を明示的に記録する

Kunai は、各 header の開始位置を実行時に記録し、field をその開始位置からの相対 offset として読む。3.2 節の GTP-U inner IPv4 filter を再び考える。この filter では `inner.dst` は packet 先頭からの固定 offset ではなく、outer IPv4 header の長さ、GTP optional field の有無、encapsulation の構造によって inner IPv4 の開始位置が変わる。

固定の compile 時 offset では読めない。手前の可変長部分（GTP optional field や IPv4 options）が空でないと、位置がずれて別の場所を読んでしまうからだ。だから offset は実行時に計算する。ただし実行時 offset でそのまま読むと、native XDP の packet pointer (PTR_TO_PACKET) への読み出しが `data_end` に収まることを verifier が証明できず、bytecode は弾かれる。

Kunai はこの境界を resolve 段階で検出し、可変長 layout を持つ layer 以降のすべての layer を runtime-offset として印付ける。そのうえで生成された eBPF bytecode は、実行時に各 header を辿った時点で、その header の開始 offset を stack slot に記録する。この offset 記録と、記録した offset を用いた bounds-checked load の例を図 3 に示す。

```text
packet:
  eth | outer ipv4 | udp | gtp | inner ipv4 | tcp
        ^                     ^
        outer_ipv4_start      inner_ipv4_start

stack:
  layer_start[eth]        = 0
  layer_start[outer_ipv4] = 14
  layer_start[udp]        = outer_ipv4_start + outer_ipv4_hlen
  layer_start[gtp]        = udp_start + 8
  layer_start[inner_ipv4] = gtp_start + gtp_header_len
  layer_start[tcp]        = inner_ipv4_start + inner_ipv4_hlen
```

<comment_img>図3 | fig:layerstart | file: paper/figures/fig_layerstart.pdf | caption: 各 header の開始 offset を境界から stack slot に記録し、inner.dst を layer 開始 offset + field offset の bounds-checked load として読む例。 | 配置: §4.1 (この ASCII ブロックを置換) | 英語版: \figref{fig:layerstart}</comment_img>

すべての field access は、この例と同じ形を持つ。すなわち、Kunai は、field が属する layer の開始 offset の取得、field offset と width の加算、`data_end` を超えないことの確認、load、型に従った比較、という順序で命令を生成する。型の合わない比較や、同一 protocol が複数回現れる場合の `proto.field` 参照は 3.1 節の解析段階で拒否済みであるため、bytecode 生成は、後続 header の開始位置が runtime で変わる chain でも、この境界確認付きの load を生成するだけでよい。

### 4.2 可変長構造は上限付きの bytecode に変換する

SRv6 segments や TCP options のような可変長構造では、要素数や各要素の長さが packet ごとに変わるため、固定 offset では走査できない。Kunai は、この走査を compile 時の定数上限を持つ bytecode に変換することで、verifier が受理する形にする。

Kunai は、可変長構造の走査を上限の大きさに応じて 2 種類の bytecode として生成する。この使い分けは chain 量化子と `any()` / `all()` の aux-list walk の双方に一律に適用する。compile 時の上限が小さく閾値以内のものは、その場で固定回数展開する。上限が小さいうちは展開のほうがコンパクトだからである。上限が大きい、または無制限のもの、すなわち parser machine の self-loop、上限なしの chain quantifier、閾値を超える chain または aux-list の walk は、定数上限付きの `bpf_loop` callback に変換し、命令数を上限に応じて増やさず一定に保つ。SRv6 segment の walk と大きな MPLS stack は同じ lowering を取る。

この走査の共通骨格をアルゴリズム 1 に示す。下記の 2 つの lowering が、その stop・stride・step を具体化する。各 lowering はそれぞれの生成器が出力する。

```text
アルゴリズム 1  上限付き走査の共通骨格
入力:  data, data_end, base, cap; 構造ごとの stop, stride, step
出力:  r

1  r ← ⊥; off ← base
2  for i ← 0 to cap − 1 do                   // cap は compile 時の定数上限
3      if stop(i, off) then break            // 要素数到達、または末尾 / END / 不正
4      ptr ← data + off
5      if ptr + w > data_end then break       // w: 読む byte 数。bounds check
6      r ← step(ptr); r が確定したら break    // 比較、または option 位置を記録
7      off ← off + stride(ptr)                // 定数、またはその option の長さ
8  return r
```

<comment>英語版で algorithm + algpseudocode の float「Algorithm 1」にする。本文の「アルゴリズム 1」は \ref{alg:walk} に置換。</comment>

Kunai はこの骨格を、protocol ではなく構造に応じて 2 通りに具体化する。第一は counted aux-list walk で、SRv6 segment list のように実行時の要素数を持つ固定長要素の list を扱う。stop は `i ≥ count`、stride は要素の固定幅、step は要素 field を target と比較し、一致した時点で walk を確定する。3.2 節の SRv6 segment filter では `base = srh_start + SRH_FIXED_SIZE`、`stride = width = 16`、`count = last_entry + 1`（3.3 節の `@kunai_stack_count` annotation による）、`target = fc00::1` である。

第二は TLV self-loop で、TCP options のように kind と長さが option ごとに異なり、`tcp.options.MSS.value` のような参照が固定 offset を取れない構造を扱う。stride は cursor で読む各 option の length、stop は cursor が options 末尾に達した場合・END option を読んだ場合・壊れた option（`len < 2` または `cursor + len > options_end`）の場合・上限回数に達した場合に成立し、step は option の kind で分岐して参照対象の option の位置を記録する。where 句は walk の後にその位置から field を読む。option 固有の field は、その option header が packet window の終端を越えないことを確認してから load する。

いずれの具体化でも、固定回数展開と `bpf_loop` のどちらの形でも、上限は compile 時の定数であり、各 packet load の前に bounds check を置く。これにより verifier は loop の上限と packet access の範囲の双方を確認できる。

生成 bytecode が複数の kernel version で受理されるよう、Kunai は新しい version でのみ使える命令を避ける。例えば byte order の変換では、6.6 以降で導入された `BSWAP` 命令ではなく、より古い version でも使える `BPF_END` 命令を用いる [22]。

これらの仕組みは Kunai 固有のものではなく、nested で可変長な filter を verifier-safe に lower するために要求されるパターンであり、compiler は P4 subset で宣言した全 protocol に同じように適用する。第一の recorded-base addressing は、各 field の読み出しを、記録した layer 開始位置を基準とし、これに静的な field offset を加えた形で生成し、その基準位置を走査中に stack slot へ退避する。これにより、verifier が packet pointer から範囲を確定できない読み出しを、確定できる形に変える。第二の constant-bounded scanning は、可変長走査を無制限ループではなく compile 時の上限の下で lower し、反復回数と各読み出しの両方を verifier が確認できるようにする。上限の大きさが、展開か bpf_loop callback かを選ぶ。field 読み出しの間で変わるのは、基準位置が実行時値か compile 時定数かだけであり、境界確認付きの読み出しの形は共通である。lowering は protocol 名ではなく構造の形で選ぶため、GTP-U・SRv6・Geneve・TCP options のいずれも生成器に protocol ごとの分岐を要さない。

## 5. 評価

我々は、Kunai を 3 つの観点で評価した。第一に、Kunai が対象とする packet 構造を filter expression として記述できるかである (5.2)。第二に、生成された bytecode が eBPF verifier に受理され、かつ期待どおりに match / reject するかである (5.3)。第三に、生成 bytecode の命令数と実行時コストがどの程度かである (5.4)。

### 5.1 評価方法と filter set

評価には、下表に挙げる 10 個の filter F1-F10 を用いた。F1-F6 は Ethernet, VLAN, IPv4/IPv6, TCP, ICMP といった基本的な protocol header を対象とする filter であり、F7-F10 は固定 offset では開始位置が定まらない nested header と可変長構造を対象とする。各 filter の Kunai expression と、Kunai が生成する eBPF bytecode の raw instruction count を、同じ filter を pcap-filter から cBPF [3] にコンパイルし、それを eBPF に変換するライブラリ cbpfc で eBPF にしたときの命令数とあわせて同表に示す。以降、この pcap-filter 側の命令数を比較の baseline とする。

| ID | Kunai expression | Kunai 命令数 | pcap-filter 命令数 |
|---|---|---:|---:|
| F1 | `eth/ipv4/tcp where tcp.dport == 443` | 199 | 42 |
| F2 | `eth/ipv4[src==10.0.0.0/8]/tcp where tcp.dport == 80` | 209 | 36 |
| F3 | `eth/ipv6[src==2001:db8::/32]/tcp` | 338 | 23 |
| F4 | `eth/vlan[tci==100]/ipv4/tcp where tcp.dport == 80` | 215 | 51 |
| F5 | `eth/qinq/vlan/ipv4/tcp where tcp.dport == 80` | 217 | — |
| F6 | `eth/ipv4/icmp where icmp.type == 8` | 85 | 31 |
| F7 | `eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where inner.dst == 10.0.0.1` | 405 | — |
| F8 | `eth/ipv6/srv6 where any(srv6.segments.addr == fc00::1)` | 450 | — |
| F9 | `eth/ipv4@outer/udp/geneve/eth/ipv4@inner/tcp where inner.dst == 10.0.0.1` | 351 | — |
| F10 | `eth/ipv4/tcp where tcp.options.MSS.value == 1460` | 231 | — |

DSL の構文をより広く検証するため、各構文要素を最低 1 つずつ網羅するよう、77 個の filter expression からなる回帰スイートを手で作成した。回帰スイートは bracket predicate、where 句の算術、量化された layer、header size の異なる alternation、`@label` による区別、aux-walk を含み、F1-F10 より広い構文範囲を覆う。この回帰スイートに対する verifier 受理と、実 packet による match / reject の正しさは、5.3 節で報告する。

これらの filter の評価では、生成した bytecode を実行側の BPF program に組み込み、XDP と tc の attach point に配置した。以降の評価では、この filter set と回帰スイートを共通して用いた。

### 5.2 表現可能性

我々は、F1-F10 を、in-kernel で実行できる filter language である pcap-filter と Kunai のそれぞれで記述できるかを比較した。pcap-filter は byte offset による access を持つため、特定の packet layout に対しては手書きの条件式を作れる場合がある。一方で、header の並び、可変長 list の任意要素、同一 protocol の複数出現、inner header の名前付き参照は、filter 構文としては提供しない。比較の結果、F1-F6 は両者で記述できた。F5 の QinQ のみ、pcap-filter では動作が capture 環境に依存した。これは NIC の VLAN offload が tag を packet bytes から外しうるためである。両者の表現力は F7-F10 で分かれた。

F7 (GTP-U) と F9 (Geneve) の inner IPv4 は、GTP optional field / extension header や Geneve の inner Ethernet により位置が packet ごとにずれ、固定 offset を取れない。F8 (SRv6) は segment list の任意要素を loop する必要があり、F10 (TCP MSS) は byte offset 近似ではなく option walk を要する。いずれも pcap-filter の filter 構文では表現できないが、Kunai は F1-F10 のすべてを、表 (5.1 節) に示した label 付き layer-chain、`any()` / `all()` の量化、option field の走査として直接記述できた。

### 5.3 生成 bytecode の受理と正しさ

4 章の bytecode 生成について、2 つの確認を行った。第一に、生成された bytecode が eBPF verifier に受理されること、第二に、受理された bytecode が期待どおりに match / reject することである。

受理については、F1-F10 と回帰スイートから生成した bytecode を、Linux 6.1, 6.6, 6.12, 6.15, 6.18, 7.0 の 6 kernel に、XDP と tc の attach point で load した。eBPF verifier が受理する命令や helper は kernel version ごとに異なるが、4 章で述べたとおり Kunai は version 依存の命令を避けて bytecode を生成するため、同一の bytecode が 6 つの version すべてで無改変のまま受理された。

tc では、kernel が outer VLAN tag を skb metadata に抽出してから program が走るため、Kunai は VLAN / QinQ の field を packet bytes として読む filter を compile 時に拒否する。一方で、optional かつ field を読まない tag は tc でも match できる。tc に残る tag は高々 1 段であるため、`eth/vlan?/...` は、optional な vlan 層が skip され、剥がされた tag を読まずに untagged・単段・QinQ のいずれのフレームにも match する。この拒否は compile 時の制約であり、verifier による rejection ではない。tc の load 対象から除外したのは field を読む形のみで、F1-F10 のうち 2 件、回帰スイートのうち 3 件であった。除外後、6 kernel × 2 host で計 1014 回の load を行い、すべて受理された。

続けて、生成した bytecode に実際の packet を与え、期待した packet を match し、期待しない packet を reject するかを確認する packet-level test を行った。Test packet は protocol ごとに、match する場合、match しない場合、malformed な場合を構成した。例えば Geneve では、`opt_len` を 0 と正の値で変えて、option を skip した先の inner offset が正しく解決されることを確認し、truncated frame や malformed な packet も併せて与えた。すべての test case で、bytecode は期待した match / reject を返した。回帰スイートの検証は 2 段階に分かれる。77 個の expression はすべて verifier に load し、そのうち 74 個は packet レベルで match / reject の正しさも確認した。残る capture 句の 3 個は verdict が base chain と同じになるため load のみの確認とした。さらに、両方の言語で書ける F1 から F4 と F6 の 5 個の filter については、同じ packet を tcpdump の filter engine である libpcap にも与えて突き合わせ、両者の verdict がすべて一致することを確認した。これは手で与えた期待値に依らない独立した照合である。

これら 2 つの確認は、4 章の bytecode 生成が、対象 filter を 6 kernel × 2 host で受理される bytecode に変換し、かつ packet の header を正しく辿ることを示した。

### 5.4 命令数と実行時コスト

filter の cost を、まず生成される eBPF bytecode の命令数で評価した。各 filter の命令数は 5.1 節の filter set の表に示した。命令数は bytecode の静的な大きさを表し、測定環境に依らず比較できる。命令数では、64-bit 即値の load を Kunai・pcap-filter とも 2 命令と数えた。pcap-filter でも書ける F1-F4 と F6 では、Kunai は 2.7 倍から 14.7 倍の命令数を生成し、最大の差は F3 の IPv6 prefix match で生じた。

可変長の walk はすべて compile 時に上限が切られているため、filter の命令数は packet ではなくその上限に応じて増える。chain 量化子は unroll の間 1 段あたり約 16 命令ずつ増え、閾値を超えると bpf_loop callback に切り替わって反復回数に依存しなくなる。SRv6 の segment walk はそれ自体が callback であり、walk を 1 本重ねるごとに約 70 命令の固定費が加わる。SRv6 walk を 8 本重ねても命令数は約 800 にとどまり、verifier のおよそ 100 万命令の上限より 3 桁ほど小さい。

この差が実行時に現れるかを、実際の traffic を送出する datapath 上で測定した。traffic generator を測定対象の DUT に 100 GbE で直結し、filter を評価して全 packet を XDP_DROP する native XDP program を attach した。DUT は Linux 6.15・BPF JIT 有効で、Intel Xeon 8362 と E810 NIC を備える。この program は運用時の fentry / tc observer と同じく、packet 先頭を per-CPU scratch window に copy してから filter を評価する。この copy 自体が filter 無しの accept-all でも処理レートを 6.7% 下げたため、各 filter の cost は同じ copy を行う accept-all からの処理レート低下として測り、copy 分のコストを除いた filter 自体の cost を取り出した。

各 filter の処理レート低下を図 4 に示す。64 byte の line rate で測定し、各セルを 10 回繰り返した。標準偏差はいずれも 0.4 以下であった。基本 filter の F1-F6 の低下は 0〜1.7% であり、ICMP type を見る F6 ではほぼ 0% であった。Kunai 固有の F7-F10 は 3.9〜6.6% で、full chain walk を伴う F7 が最大の 6.6% であった。Kunai と pcap-filter の両方で書ける F1 では、両者の処理レートの差は 0.7% にとどまった。

この datapath の結果は、syscall 経由の `BPF_PROG_TEST_RUN` による packet あたりの実行時間測定とも整合した。filter を持たない accept-all を baseline とすると、その 611-612 ns に対する各 filter の増分は最大 +15 ns/pkt であり、baseline との差は 3% 未満であった。Kunai と pcap-filter の差は最大でも測定の標準偏差と同程度であり、実行時間が同等程度である事を確認した。

filter 評価は 611-612 ns の accept-all baseline に最大でも +15 ns しか加えず、その差は 3% 未満である。したがって packet あたりのコストは filter 評価ではなく、全 program に共通する固定的な処理に支配される。この固定分のうち window copy は単独で 6.7% を占めることを別途測定した。

<comment>b2 micro-bench (§5.4 para 3 の per-packet 実行時間の出典): F0 = accept-all baseline、BENCHTIME=3s × 10 reps、集計は benchmark/results/b2_runtime_stats.csv (mean±σ)。#38 後に再測定済 (2026-06-20): baseline 611-612 ns、最大増分 +15 ns/pkt (F8、F9=+15)。F9 は #38 で命令数 323→351 に増えたが、per-packet 実行時間は baseline 比 +14.9 ns で他の重い filter (F7/F8) と同程度。</comment>
<comment>b4 datapath (§5.4 results 段落 + 図3 箱ひげの出典): harness benchmark/xdpdrop (window-copy)、結果 benchmark/results/b4_xdp_drop_rep{1..10}.csv、集計 benchmark/analysis/b4_stats.py → b4_xdp_drop_stats.csv (n=10)、図 benchmark/analysis/b4_boxplot.py → paper/figures/fig_datapath.pdf。window-copy は運用の observer (fentry/tc) 経路の再現が理由であり reject 回避ではない。native 直接実行は PR #33 で verifier-safe 化済 (TestBpfXDPNativeFilterSet green)。datapath cell は全 F1-F10 + cbpfc_F1。F2-F6 の stream (tcp80/ipv6tcp/vlan/qinq/icmp) を scripts/trex/trex_b4_streams.py に追加 (2026-06-16、全 cell xdp_matched=100%)。F4/F5 は測定中 DUT の rxvlan/vlan-filter offload を off (測定後 on に復旧)。TRex は -c 20 で ~117 Mpps 飽和 (-c 無しだと 1 core で 49 Mpps なので注意)、port は forced 100G。</comment>
<comment>RR1 済 + n=10 全 F1-F10 化 (初出 2026-06-16)。#38 後に再計測 (2026-06-21): cost% は accept-all 比、F1 -1.69±0.15, F2 -1.72±0.11, F3 -0.58±0.30, F4 -1.73±0.11, F5 -1.71±0.07, F6 -0.01±0.04, F7 -6.64±0.29, F8 -4.11±0.18, F9 -4.01±0.16, F10 -3.95±0.17, kunai_F1 vs cbpfc_F1 gap -0.74±0.11, window-copy 固定費 -6.75±0.35 (図の破線ラベルは ratio-of-means で 6.7%)。F9 は #38 で命令数 323→351 だが datapath cost は不変 (-4.01≈旧 -4.20) ＝ 命令数増は実行時間に出ないことを再確認。ただし今 session は全 cell が旧比 ~0.5pp 重く (b2 baseline も 608→611ns drift ＝ NIC 非依存の session レベル要因)、F7 (6.64) と固定費 (6.75) が σ 内で重なった (F7 が固定費超過 4/10 rep)。このため本文を「F7 < 固定費」から「F7 ≈ 固定費 (同程度)」にリフレーム済 (2026-06-21 user 判断 B)。旧 n=10 (F7 -6.11/固定 -6.30) は results/attic/ に退避。再計測は `REPS=10 DURATION=30 bash benchmark/pipelines/b4_run_full.sh` (offload off→trap で復旧→集計まで)、図は `python3 benchmark/analysis/b4_boxplot.py benchmark/results/b4_xdp_drop_rep*.csv -o docs/paper/ebpf_workshop_2026/paper/figures/fig_datapath.pdf`。</comment>
<comment_img>図4 | fig:datapath | file: paper/figures/fig_datapath.pdf | caption: 全 F1-F10 の datapath 処理レート低下 (accept-all 比、n=10 の箱ひげ)。最重の F7 (6.6%) も window-copy 固定費 (6.7%, 破線) と同程度。緑三角は平均。 | 配置: §5.4 results 段落 | 英語版: \figref{fig:datapath}。本文 citation「各 filter の処理レート低下を図 4 に示す」済。データ b4_xdp_drop_rep{1..10}.csv、生成 benchmark/analysis/b4_boxplot.py。命令数比較の旧 fig:insns は Table 2 の pcap-filter 列に吸収し削除。</comment_img>

<comment>
min/max/標準偏差/中央値
棒グラフではなく箱ひげ図的に書けば、一応これが示せるか？
</comment>


## 6. Limitation

Kunai は packet filtering に特化した DSL であり、汎用の eBPF language ではない。stateful filtering、deep packet inspection、aggregation は対象外である。また、P4 は header layout と parser transition の定義としてのみ用い、action や table などの pipeline 実行機構は扱わない。

Kunai は field を名前で参照し、pcap-filter の `ip[14:2]` のような生の byte offset を読む逃げ道を持たない。これは意図的な設計である。名前で解決した access だからこそ code generator は各読み出しを上限付きにして verifier が受理できる形にでき、任意の実行時 offset ではそれができない。生の byte offset の逃げ道は一方向の gap であり、設計上のもので不足ではない。SYN flag 判定のような byte 境界に揃わない field も `where tcp.flags & 0x02 != 0` のように名前で書け、生成器が byte 整列した covering window を mask して取り出す。

本稿が示した verifier 受理は経験的な確認であり、形式的な保証ではない。F1-F10 と回帰スイートについて 6 kernel で受理と match を確認したが、任意の Kunai expression と任意の kernel version に対する受理は今後の課題である。また、可変長走査を上限付き bytecode に変換するため、走査できる要素数には compile 時の上限があり、`bpf_loop` を用いる filter は kernel version の下限の制約を受ける。

生成 bytecode の正しさは、protocol 定義の正しさに依存する。p4c による parse check は P4 syntax の検査であり、対応 RFC に対する field offset や parser transition の正しさは保証しない。現行の定義が扱う範囲にも制限があり、例えば Geneve の option TLV は filter 対象として公開しておらず、これは今後の課題である。最後に、Kunai の bytecode は packet window 上の host 非依存な評価器であり、各 host adapter がその attach point で見える layout を与える。tc では kernel が outer VLAN tag を skb metadata に移すため、その tag の値を読むことは今後の課題である (5.3)。

## 7. 結論

我々は、nested encapsulation、同一 protocol の複数出現、可変長 list / option の走査を含む、pcap-filter では書けない packet filter 条件を、Linux kernel 内で実行可能にする DSL と compiler である Kunai を示した。XDP と tc の両 host で、生成した同一 bytecode が Linux 6.1 から 7.0 の 6 つの kernel version にわたって無改変で受理され、期待どおりに match / reject し、packet あたりの増分は最大 +15 ns であった。両方で書ける filter では、この差は pcap-filter の測定誤差の範囲に収まった。

<comment>
TODO
この論文によって、どんな知見が得られた？を書いておきたい。→評価に対応する一文が欲しい。
pcap-filterで書けない、→書けるようになった
それは、実際にverifierを通って、動いており、性能におけるオーバーヘッドのコストもほぼ変わらないねという話を確認した

書くときのポイントはabst/1章/結論にかけるといい感じ。なぜなら読む側が全部読むのが大変だから
</comment>
<comment>済 (2026-06-15): 上記の知見文を §7 に反映。骨子は「設計した手法の妥当性を確認 (確認/検証)」＋「表現力の静的命令数増が実行時コストには現れない点だけ測定で示した (示した)」の二段構え。無改変受理は発見ではなく、version 依存命令を避ける設計上の選択 (BSWAP 回避・bpf_loop 下限) が十分だったことの検証、と位置づけ直した。残: 同趣旨の1文を要旨と §1 にも展開 (要旨=動く＋pcap 同等コスト、§1=contribution として)。</comment>

## 参考リンク

[1] Noa Sultana et al., "A Survey on Packet Filtering", ACM SIGCOMM Computer Communication Review, 2024. https://ccronline.sigcomm.org/2024/a-survey-on-packet-filtering/

[2] `pcap-filter(7)` manual page. https://man7.org/linux/man-pages/man7/pcap-filter.7.html

[3] Steven McCanne and Van Jacobson, "The BSD Packet Filter: A New Architecture for User-level Packet Capture", USENIX Winter Technical Conference, 1993. https://www.tcpdump.org/papers/bpf-usenix93.pdf

[4] Jeffrey C. Mogul, Richard F. Rashid, and Michael J. Accetta, "The Packet Filter: An Efficient Mechanism for User-level Network Code", ACM SOSP, 1987. https://research.google/pubs/the-packet-filter-an-efficient-mechanism-for-user-level-network-code/

[5] Fulvio Risso and Mario Baldi, "NetPDL: An Extensible XML-based Language for Packet Header Description", Computer Networks, 2006. https://doi.org/10.1016/j.comnet.2005.05.029

[6] Olivier Morandi, Luigi Ciminiera, Marco Leogrande, Ju Liu, and Fulvio Risso, "A Tunnel-aware Language for Network Packet Filtering", IEEE GLOBECOM, 2010. https://iris.polito.it/retrieve/handle/11583/2381239/e384c42e-0b5c-d4b2-e053-9f05fe0a1d67/10Globecom-NetPFL.pdf

[7] Marco Leogrande, Fulvio Risso, and Luigi Ciminiera, "Modeling Complex Packet Filters with Finite State Automata", IEEE/ACM Transactions on Networking, 2015. https://doi.org/10.1109/TNET.2013.2290739

[8] Ivano Cerrato and Fulvio Risso, "Enabling precise traffic filtering based on protocol encapsulation rules", Computer Networks, 2018. https://doi.org/10.1016/j.comnet.2018.02.027

[9] P4 Language Consortium, "P4-16 Language Specification". https://p4.org/p4-spec/docs/P4-16-v1.2.5.pdf

[10] P4C documentation: eBPF backend. https://p4lang.github.io/p4c/ebpf_backend.html

[11] VMware, `p4c-xdp`: backend for the P4 compiler targeting XDP. https://github.com/vmware-archive/p4c-xdp

[12] Linux kernel documentation: eBPF verifier. https://www.kernel.org/doc/html/latest/bpf/verifier.html

[13] eBPF Docs: loops in BPF. https://docs.ebpf.io/linux/concepts/loops/

[14] eBPF Docs: `bpf_loop` helper. https://docs.ebpf.io/linux/helper-function/bpf_loop/

[15] 3GPP TS 29.281, "General Packet Radio System (GPRS) Tunnelling Protocol User Plane (GTPv1-U)". https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1699

[16] RFC 8754, "IPv6 Segment Routing Header (SRH)". https://www.rfc-editor.org/rfc/rfc8754.html

[17] RFC 8926, "Geneve: Generic Network Virtualization Encapsulation". https://www.rfc-editor.org/rfc/rfc8926

[18] RFC 9293, "Transmission Control Protocol (TCP)". https://www.rfc-editor.org/rfc/rfc9293

[19] Wireshark Foundation, "Wireshark Display Filter Reference". https://www.wireshark.org/docs/dfref/

<!-- NOTE: この JA mirror の参考リンクは [1]-[19] までしか整備されておらず、本文は [20]=XDP / [21]=PREVAIL / [22]=BPF-ISA / [23]=tc を既に未登録のまま使っている（pre-existing の番号ずれ）。§2 で追加した Simon "Honey for the Ice Bear"(eBPF'24, doi:10.1145/3672197.3673436) / Solleza ら "Kernel Extension DSLs Should Be Verifier-Safe!"(eBPF'25, doi:10.1145/3748355.3748368) / K2 / Marple は番号衝突を避けるため本文では著者名で参照している。正本の引用は EN `paper/refs.bib`。JA 側の参考リンク全体の番号再整備は別タスク。 -->


[20] Toke Høiland-Jørgensen, Jesper Dangaard Brouer, Daniel Borkmann, John Fastabend, Tom Herbert, David Ahern, and David Miller, "The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel", ACM CoNEXT, 2018. https://doi.org/10.1145/3281411.3281443

[21] Elazar Gershuni, Nadav Amit, Arie Gurfinkel, Nina Narodytska, Jorge A. Navas, Noam Rinetzky, Leonid Ryzhyk, and Mooly Sagiv, "Simple and Precise Static Analysis of Untrusted Linux Kernel Extensions", ACM PLDI, 2019. https://doi.org/10.1145/3314221.3314590

[22] "BPF Instruction Set Architecture (ISA)", Linux Kernel Documentation. https://docs.kernel.org/bpf/standardization/instruction-set.html

[23] iproute2 project, `tc(8)`: show / manipulate traffic control settings. https://man7.org/linux/man-pages/man8/tc.8.html

