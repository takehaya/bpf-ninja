# 保存済み出力を変換する

capture の正常終了を待つか、終了したプロセスの shard を作業用ディレクトリにコピーしてから実行します。
入力と出力は別パスにし、過去の出力を上書きしないでください。
root は不要ですが、入力の読取りと出力先の書込み権限が必要です。

## Raw-dump の変換

`--raw-dump -w session` の出力があるディレクトリで実行します。
同じ basename の別実行を混ぜないでください。

```sh
ls session.W*.cpu*.raw
bpf-ninja convert -r 'session.W*.cpu*.raw' -o converted.pcapng
tcpdump -n -r converted.pcapng
```

convert は件数を stderr に表示します。
入力には現在の raw V2 形式を使います。
V1 は拒否されるため、作成時の対応版で変換してください。
pcap-ng の `.cpuN` shard は raw ではありません。
[隔離 recipe](capture-recipes.md)でも 3 件の ICMP で変換を検査します。

## Tag shard の救出

`--split-by-tag -w out.pcap` の capture が停止済みで、`out.cpuN.TAG.pcap` が残っている場合に使います。
元の shard は保持されます。

```sh
bpf-ninja merge --base out.pcap
# exit mode の shard なら、代わりに:
# bpf-ninja merge --base out.pcap --fexit
tcpdump -n -r out.7.pcap
```

`out.7.pcap` は tag=7 の例です。
存在する shard の破損や切り詰めはエラーです。
欠けた shard があっても merge は成功する場合があるため、終了コードだけでは全パケットが揃ったと判断できません。
merge と convert の出力には `epb_packetid` が残らないため、対応づけには元 shard または raw を保持してください。

両コマンドは自動終了します。
結果を確認してから、この作業で作成した出力だけを片付けます。
元データは自動削除しません。
対応試験は `cmd/bpf-ninja/convert_test.go` と `internal/output` の merge tests です。

[出力 guide](../cli/output.md)
