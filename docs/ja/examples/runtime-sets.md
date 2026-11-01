# 実行中の set を更新する

[隔離 capture recipe](capture-recipes.md) では、ICMP type を key にした専用の map を使い、一つの capture の途中で条件を変更します。
実行には root 権限、mount 済みの bpffs、pin の書き込み権限が必要です。
以下の `$PIN` と `$BINARY` は、script が用意する pin と build 済みの binary を表します。

## set を作って capture する

```sh
"$BINARY" set create "$PIN" --key 'type:u8'
"$BINARY" set add "$PIN" type=8 tag=7
"$BINARY" set schema "$PIN"
"$BINARY" set list "$PIN"
```

capture は `--set "types=$PIN" 'eth/ipv4/icmp[type in @types]'` で開始します。
起動の表示を待ってから、echo request を 3 件送ります。
次に entry を削除して 3 件送り、同じ key を再度追加してさらに 3 件送ります。
最終的な pcap と summary の件数は 6 件になります。

```sh
"$BINARY" set del "$PIN" type=8
"$BINARY" set add "$PIN" type=8 tag=7
```

`set list` は現在の map の内容を表示します。
パケットがフィルタに一致したかどうかは、pcap で確認します。

## tag ごとに完成させる

別のケースでは `--split-by-tag --finalize-on-del` を指定し、3 件送ってから `set del` を実行します。
script は、新しい出力先に tag=7 の合算ファイルが作られるのを時間制限付きで待ちます。
このファイルの出現が完成の合図です。
一定時間の経過や live shard の存在だけでは、完成と判断しません。
一度 finalize した tag は、同じ capture の中では再利用しません。

## 容量の変更と終了

- `set resize` を実行する前に、capture と更新中の writer を止めます。
- pin を置き換えても、既存の capture は古い map を参照し続けます。新しい map を使うには attach し直します。
- entry の削除と unpin は別の操作です。
- script は capture を止めた後、自分で作った pin だけを外します。共有の map は削除しません。

一連の実行、期待件数、停止、後片付けは、次のコマンドで確認できます。
script は `--cbpf` も試すため、libpcap 付きで build します。

```sh
make build-libpcap
sudo bash scripts/test/docs-capture.sh
```

複合 key、IPv6 key、cap については、[set guide](../cli/sets.md) と [output guide](../cli/output.md) を参照してください。
cap は tag 単位で共有され、その state は pin に残ります。再利用する前に状態を確認してください。
