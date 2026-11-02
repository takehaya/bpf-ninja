# フィルタをロードせず確認する

式の解釈と生成される命令を確認する例です。
BPF をロードしないため、root 権限、対象プログラム、インターフェース、パケット送信は不要です。
Linux で `make build` を実行したあと、リポジトリのルートで次のコマンドを実行します。

## 実行

```sh
./bpf-ninja --dsl-help
./bpf-ninja --dsl-help ipv4
./bpf-ninja --dump-asm filter 'eth/ipv4/tcp[dport==443]'
./bpf-ninja --dump-asm full --dump-hook xdp --mode exit 'eth/ipv4/tcp where action == XDP_DROP'
```

- 最初の 2 つは、簡易構文とプロトコルのフィールドを表示します。
- `filter` はフィルタ本体の命令を表示します。`full` は、entry と exit では tracing プログラム、`--mode xdp` では XDP プログラムとして組み立てた命令を表示します。
- `--dump-hook` は、ターゲットを探さないオフライン処理で hook を指定します。
- 警告は stderr に出力されます。stdout には命令だけが出力されます。

## legacy 構文

tcpdump 構文の `tcp port 443` には `--cbpf` が必要です。
`--cbpf` は libpcap 付きのビルドでのみ使えます。ビルドには C コンパイラと libpcap の開発用パッケージが必要です。

```sh
make build-libpcap
./bpf-ninja --cbpf --dump-asm filter 'tcp port 443'
```

既定のビルドで `--cbpf` を指定すると、ビルド方法を示すエラーを出して終了します。`--dump-asm` と組み合わせても同じです。

## エラーの確認

```sh
./bpf-ninja --dump-asm filter 'eth/ipv4/tcp[dport==65536]'
```

65536 は 16 bit のポート番号に収まりません。
エラー内容が表示され、0 以外の終了コードが返ることを確認します。
DSL で Ethernet フレームを扱う場合は `eth` から記述します。
L3 から始まる hook では IP ヘッダから記述します。

## 結果の読み方

各コマンドは自動で終了し、ファイルやカーネルのリソースを作成しません。
命令の表示で分かるのは、コンパイルが成功したことまでです。
verifier による受理と実パケットへの一致は、[隔離 recipe](capture-recipes.md) または [privileged tests](../../privileged-tests.md) で確認します。

[Examples に戻る](README.md)
