# トンネル内部の式を確認する

多段 header を含む式をロード前に確認する例です。
Linux で build 済みの repository root から実行します。
root、送信機、interface は不要です。

```sh
./bpf-ninja --dsl-help vxlan
./bpf-ninja --dsl-help gtp
./bpf-ninja --dsl-help srv6
./bpf-ninja --dump-asm filter \
  'eth/ipv4/udp/vxlan/eth/ipv4/tcp[dport==443] capture headers+64'
./bpf-ninja --dump-asm filter \
  'eth/ipv4@outer/udp/gtp[teid==4096]/ipv4@inner/tcp[dport==443]'
./bpf-ninja --dump-asm filter \
  'eth/ipv6/srv6/tcp where any(srv6.segments.addr == fc00::1)'
```

protocol help で dispatch と field を確認し、三つの式が命令列を出して正常終了することを確認します。
VXLAN の内側には Ethernet、GTP の例では直接 IPv4 があるため、chain が異なります。
同じ protocol を複数回参照するときは label を付けます。
`capture headers+64` は保存長の指定で、parser が読める範囲を広げる指定ではありません。

## 実機で確認する範囲

実際の frame の header 順序、port、TEID、SRH の有無が式と一致するかを packet fixture で確認してください。
observer の packet window、host の L2/L3 始まり、kernel の機能条件も必要です。
このページの command は compile の確認までであり、実パケット取得を検証した手順ではありません。
既存の [DSL vectors](../../../pkg/kunai/dsltest/) と [program tests](../../../internal/program/)は、compile、kernel load、packet の判定を別に検査します。

各 command は自動終了します。
ファイルと kernel resource を作らないため cleanup は不要です。
実際の capture の開始、readiness、停止、pcap 確認は [隔離 recipe](capture-recipes.md)、既存 target の entry/exit は [手動試験](../handtest.md)を参照してください。
