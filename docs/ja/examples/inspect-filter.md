# フィルタをロードせず確認する

式の解釈と生成命令を調べる例です。
BPF をロードしないため、root 権限、対象プログラム、インターフェース、パケットの送信は不要です。
Linux で `make build` を実行した後、リポジトリのルートディレクトリで次のコマンドを実行します。

## 実行

```sh
./bpf-ninja --dsl-help
./bpf-ninja --dsl-help ipv4
./bpf-ninja --dump-asm filter 'eth/ipv4/tcp[dport==443]'
./bpf-ninja --dump-asm full --dump-hook xdp --mode exit   'eth/ipv4/tcp where action == XDP_DROP'
./bpf-ninja --cbpf --dump-asm filter 'tcp port 443'
```

最初の二つは簡易構文と protocol/field の説明を表示します。
`filter` はフィルタ本体、`full` は host に組み込んだ program の命令を表示し、正常終了します。
warning がある場合は stderr も確認してください。
`--dump-hook` は target を探索しない offline 処理で host を指定するために使います。

## エラーの確認

```sh
./bpf-ninja --dump-asm filter 'eth/ipv4/tcp[dport==65536]'
```

65536 は 16 bit のポート番号に収まらないため、エラーの説明を表示して非ゼロの終了コードを返すことを確認します。
legacy の `tcp port 443` には `--cbpf` が必要です。
DSL の Ethernet frame は `eth` から書き、L3 始まりの host では IP header から書きます。

## 結果の解釈と片付け

各コマンドは自動終了し、この例ではファイルや kernel resource を作成しません。
命令列の表示で確認できるのは、コンパイルが成功したことまでです。
verifier に受理されるか、実パケットが式に一致するかは、[privileged tests](../../privileged-tests.md) と packet fixture で別に確認します。
対応する回帰試験は `cmd/bpf-ninja` の DSL help と dump-asm tests です。

[Examples に戻る](README.md)
