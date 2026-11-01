# 保存済み出力を変換する

capture の正常終了を待ってから実行します。
終了したプロセスの shard を作業用ディレクトリにコピーしてから実行しても構いません。
入力と出力は別のパスにし、過去の出力を上書きしないでください。
root 権限は不要です。入力の読み取りと出力先への書き込みの権限が必要です。

## raw-dump を pcap-ng にする

`--raw-dump -w session` の出力があるディレクトリで実行します。
同じ basename を使った別の実行の出力を混ぜないでください。

```sh
ls session.W*.cpu*.raw
bpf-ninja convert -r 'session.W*.cpu*.raw' -o converted.pcapng
tcpdump -n -r converted.pcapng
```

- `convert` は処理した件数を stderr に表示します。
- 入力は raw V3 形式です。0.26 から 0.32 が書いた V2 形式も読めますが、V2 は元のパケット長を持たないため、元の長さは captured length と同じ値になります。
- V1 形式の raw は拒否されます。V1 は 0.25 以前の bpf-ninja で変換してください。
- pcap-ng の `.cpuN` shard は raw ではないため、`convert` には渡せません。

## tag shard を合算する

`--split-by-tag -w out.pcap` の capture が停止し、`out.cpuN.TAG.pcap` が残っている場合に使います。
実行後も元の shard は残ります。

```sh
bpf-ninja merge --base out.pcap
# exit mode の shard の場合
bpf-ninja merge --base out.pcap --fexit
tcpdump -n -r out.7.pcap
```

- `out.7.pcap` は tag=7 の出力例です。
- 壊れた shard や切り詰められた shard はエラーになります。
- 一部の shard が欠けていても merge は成功することがあります。終了コードだけでは、全パケットが揃ったと判断できません。
- merge と convert の出力には `epb_packetid` が残りません。entry と exit の対応づけには、元の shard か raw を残してください。

どちらのコマンドも自動で終了し、元のデータを削除しません。
結果を確認してから、この作業で作った出力だけを片付けます。
[隔離 recipe](capture-recipes.md)でも、3 件の ICMP で変換を確認します。

[出力 guide](../cli/output.md)
