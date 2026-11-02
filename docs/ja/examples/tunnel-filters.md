# トンネル内部の式を確認する

多段のヘッダーを含む式を、ロード前に確認する例です。
Linux でビルドしたリポジトリのルートから実行します。
root 権限、送信機、インターフェースは不要です。

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

プロトコルのヘルプでディスパッチとフィールドを確認します。3 つの式が命令を出力し、正常に終了することも確認します。

- VXLAN の内側には Ethernet があり、GTP の例では直接 IPv4 が続きます。そのためチェーンが異なります。
- 同じプロトコルを複数回参照するときは、`@outer` のようなラベルを付けます。
- `capture headers+64` は保存する長さの指定です。パーサーが読める範囲は広がりません。

## 実際のトラフィックで確認すること

このページのコマンドで分かるのは、式がコンパイルできることです。
実際のフレームでヘッダーの順序、ポート、TEID、SRH の有無が式と一致するかは、パケットフィクスチャで確かめます。
パケットが L2 と L3 のどちらから始まるかは hook ごとに異なります。この開始位置と必要なカーネル機能も確認します。
フィルタが読むのはパケットの先頭 512 バイトまでです。深いトンネルでは、読む field がこの範囲に収まるかどうかも確認します。
[DSL vectors](../../../pkg/kunai/dsltest/) と [program tests](../../../internal/program/) では、コンパイル、カーネルへのロード、パケットの判定をそれぞれ検査します。

各コマンドは自動で終了し、ファイルやカーネルのリソースを作成しません。
キャプチャの開始や停止、pcap の確認は [隔離 recipe](capture-recipes.md) を参照してください。既存のターゲットの entry と exit は [手動試験](../handtest.md) を参照してください。
