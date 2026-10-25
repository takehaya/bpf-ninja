# 導入と最初の確認

フィルタの確認だけなら、BPF のロードも root 権限も不要です。
まず Linux 上でビルドし、[offline の例](examples/inspect-filter.md)を実行してください。

## ビルド

リポジトリのルートディレクトリで実行します。
Go の版は `go.mod` に従い、C compiler と libpcap の開発用ヘッダを用意してください。
Ubuntu では libpcap の開発パッケージは `libpcap-dev` です。
配布バイナリを使う場合は [Install](../../README.md#install) を参照してください。

```sh
make build
./bpf-ninja --version
./bpf-ninja --help
git rev-parse HEAD
```

ソースからビルドした場合、version は通常 `dev` です。
不具合報告や測定記録には commit と `uname -r` も残してください。

## パケットを取得するための条件

基本要件は Linux 5.8 以降、`/sys/kernel/btf/vmlinux`、root または必要な BPF/network capability です。
capability だけで動かせるかは、kernel と環境の制限にも依存します。
entry/exit では BTF 付きの対象 BPF program が既にロードされている必要があります。
xdp mode は対象 interface に既存 XDP がない場合に使います。

機能によって要件が増えます。
一部の DSL 繰り返し等は Linux 5.17 以降、netfilter は 6.4 以降、hardware timestamp は 6.8 以降と driver 対応が必要です。
gated capture には kernel の修正状況による制約もあるため、[現在の要件](../../README.md#prerequisites)と[mode の説明](../../README.md#modes)を確認してください。
これらの最低条件と、各レシピを実際に検証した環境は区別します。

初めてパケットを取得するときは、使い捨ての Linux VM を使ってください。
手動試験は namespace と veth を作成するため、[前提と cleanup](handtest.md)を先に確認します。
運用中の interface や既存 XDP を試験の都合で変更しないでください。

## 次に読む資料

- [Examples](examples/README.md)：目的と期待結果から選ぶ。
- [DSL](dsl-overview.md)：packet layout に合う式を書く。
- [利用ガイド](dsl-usage.md)：mode、set、出力の操作を調べる。
- [終了の意味](../capture-lifecycle.md)：停止後に何を確認するか。

[Docs に戻る](README.md)
