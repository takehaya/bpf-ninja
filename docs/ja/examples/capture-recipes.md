# 隔離環境で ICMP を取得する

専用の network namespace 二つと veth を作成し、xdp mode での一致と不一致、legacy 構文、raw-dump、set の更新を確認します。
既存の interface や XDP program は操作しません。
一連の手順は [docs-capture.sh](../../../scripts/test/docs-capture.sh) にまとまっています。

## 必要条件

- 使い捨ての Linux VM と root 権限
- kernel BTF（`/sys/kernel/btf/vmlinux`）と mount 済みの bpffs
- iproute2、ping、tcpdump、GNU timeout、nsenter
- libpcap の開発用パッケージ（Ubuntu では `libpcap-dev`）

不足している項目があると、script はそれを検出して停止します。
mount やパッケージのインストールは自動で行いません。
[対応条件](../../../README.md#prerequisites)もあわせて確認してください。

## 実行

script は legacy の `--cbpf` もテストするため、libpcap を有効にして build します。
既定の `make build` で作成した binary を使うと、ネットワークを作成する前に script が停止します。
repository root で次のコマンドを実行します。

```sh
make build-libpcap
sudo bash scripts/test/docs-capture.sh
```

## 期待結果

script は一意な名前の namespace に 192.0.2.1/30 と 192.0.2.2/30 を設定します。
受信側の `doc0` に attach し、`capturing (...)...` の表示を待ってから送信側で ping を送信します。

| ケース | 式と指定 | 結果 |
|---|---|---|
| DSL 一致 | `eth/ipv4/icmp[type==8]`、`-c 3` | summary と pcap が 3 件 |
| DSL 不一致 | `eth/ipv4/tcp[dport==80]` | ping の後に SIGTERM で停止し、summary と pcap が 0 件 |
| legacy 一致 | `--cbpf 'icmp'`、`-c 3` | ICMP が 3 件 |
| raw-dump | 同じ ICMP 式と `--raw-dump` | `convert` の後に pcap が 3 件 |
| set 更新 | [runtime set](runtime-sets.md) | 同じ capture 中の del と add を反映して 6 件 |
| tag finalize | 同じ set の tag=7 | 削除後に合算ファイルから 3 件を読み取れる |

起動の成功は、経過時間ではなく `capturing (...)...` の表示で判定します。
不一致のケースでは指定した count に達しないため、signal で停止します。
timeout、起動失敗、summary の欠落、pcap の読み取り失敗がある場合は、正常な 0 件の結果として扱いません。
最後に `Documentation capture examples passed` が表示されます。

## 停止と片付け

各 capture には時間制限があります。
終了時や中断時には、script が実行中の子プロセスを停止し、作成した namespace と pin を削除します。
pcap と stderr は、表示された `/tmp/bpf-ninja-docs.*` ディレクトリに残ります。
内容を確認した後、このディレクトリだけを手動で削除してください。
不具合を報告する際は、commit、`uname -r`、終了時の summary も添えてください。

より広範囲の回帰試験は `make test-bpf` と `make test-integration` で実行できます。

[capture guide](../cli/capture.md) · [出力 guide](../cli/output.md)
