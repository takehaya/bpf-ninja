# 実行中の set を更新する

[隔離 capture recipe](capture-recipes.md)は ICMP type を key にした専用 map を使い、一つの capture 中に条件を変えます。
root、mount 済み bpffs、書込み権限が必要です。
以下の `$PIN` と `$BINARY` は script が確保する pin と build 済み binary です。

```sh
"$BINARY" set create "$PIN" --key 'type:u8'
"$BINARY" set add "$PIN" type=8 tag=7
"$BINARY" set schema "$PIN"
"$BINARY" set list "$PIN"
```

capture は `--set "types=$PIN" 'eth/ipv4/icmp[type in @types]'` で開始します。
readiness 後に echo request を 3 件送り、entry を削除して 3 件送り、同じ key を戻して 3 件送ります。
最終 pcap と summary は 6 件です。
`set list` は map の内容であり、一致した証拠は pcap で確認します。

```sh
"$BINARY" set del "$PIN" type=8
"$BINARY" set add "$PIN" type=8 tag=7
```

別ケースでは `--split-by-tag --finalize-on-del` で 3 件送信後に `set del` します。
新規出力先の tag=7 の合算ファイルを制限時間付きで待ちます。
固定秒数や live shard の存在を完了 ack にしません。
finalize した tag は同じ capture 中に再利用しません。

## 容量変更と終了

`set resize` の前には capture と更新 writer を止めます。
pin の置換後も既存 capture は古い map を参照するため、再 attach が必要です。
entry の削除と unpin は別の操作です。
script は capture 停止後に自分で作成した pin だけを外します。
共有 map は削除しません。

一連の実行、期待件数、停止、cleanup は次で確認できます。

```sh
make build
sudo bash scripts/test/docs-capture.sh
```

複合 key、IPv6 key、cap は [set guide](../cli/sets.md) と [output guide](../cli/output.md)を参照してください。
cap は tag 単位で共有され、state は pin に残るため、再利用前に状態を確認します。
