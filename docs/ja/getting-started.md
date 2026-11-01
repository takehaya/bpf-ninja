# 導入と最初の確認

フィルタの確認だけなら、BPF のロードも root 権限も不要です。
まずは Linux 上でビルドし、[offline の例](examples/inspect-filter.md)を実行してください。

## ビルド

リポジトリのルートディレクトリで実行します。
Go のバージョンは `go.mod` に従います。
通常のビルドに C コンパイラや libpcap は不要です。
配布バイナリを使う場合は [Install](../../README.md#install) を参照してください。

```sh
make build
./bpf-ninja --version
./bpf-ninja --help
```

ソースからビルドした場合、バージョンは通常 `dev` になります。
不具合を報告する際は、`git rev-parse HEAD` のコミットと `uname -r` の出力も添えてください。

従来の tcpdump 構文（`--cbpf`）を使う場合のみ、libpcap を有効にしてビルドします。
Ubuntu では `libpcap-dev`、Fedora では `libpcap-devel` をインストールしてから実行してください。

```sh
make build-libpcap
```

## パケットを取得するための条件

- Linux 5.8 以降と `/sys/kernel/btf/vmlinux`
- root 権限、または `CAP_BPF` と `CAP_NET_ADMIN`
- entry モードと exit モードでは、BTF 付きの対象 BPF プログラムがロード済みであること
- xdp モードでは、対象のインターフェースに XDP がアタッチされていないこと

使用する機能によって追加の要件があります。
DSL の一部の繰り返しとポインタ引数の読み取りには Linux 5.17 以降が必要です。
netfilter には 6.4 以降、ハードウェアタイムスタンプには 6.8 以降とドライバの対応が必要です。
詳細は [Prerequisites](../../README.md#prerequisites) と [Modes](../../README.md#modes) を参照してください。

## 最初のキャプチャ

初めてパケットを取得するときは、使い捨ての Linux VM を使ってください。
[隔離 capture recipe](examples/capture-recipes.md)では、namespace と veth を作成してフィルタの一致と不一致を確認します。
既存のターゲットを観測する手順は[手動試験](handtest.md)にあります。
試験のために、運用中のインターフェースや既存の XDP を変更しないでください。

XDP プログラムがアタッチされたインターフェースでは、次のコマンドで entry のパケットを取得できます。

```sh
sudo ./bpf-ninja -i eth0 -c 10 'eth/ipv4/tcp[dport==443]' | tcpdump -n -r -
```

## 次に読む資料

- [Examples](examples/README.md)：目的と期待する結果から選びます。
- [DSL](dsl-overview.md)：パケットの構造に合わせた式を書きます。
- [capture guide](cli/capture.md)：モードとターゲットを選びます。
- [inject-run](../en/inject-run.md)と[実行例](../en/inject-walkthrough.md)：`--list-progs --list-maps` でマップ操作を調べ、ロード時に観測用のフックを追加します（英語、Linux x86-64 の実験的機能）。
- [終了の意味](../capture-lifecycle.md)：停止した後に何を確認するかを説明します。

[Docs に戻る](README.md)
