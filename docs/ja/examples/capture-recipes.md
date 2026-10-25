# 隔離環境で ICMP を取得する

専用の二つの network namespace と veth を作り、xdp mode の一致、不一致、legacy 構文、raw-dump を確認します。
既存の interface や XDP program は操作しません。
実行手順は [docs-capture.sh](../../../scripts/test/docs-capture.sh) にあり、既存の readiness/停止 helper を使います。

## 必要条件と準備

使い捨て Linux VM、root、kernel BTF、iproute2、ping、tcpdump、GNU timeout、nsenter、mount 済み bpffs が必要です。
[対応条件](../../../README.md#prerequisites)と[試験環境](../../privileged-tests.md)を確認してください。
script は不足条件を検査し、mount やパッケージ導入を自動では行いません。
repository root で実行します。

```sh
make build
sudo bash scripts/test/docs-capture.sh
```

## 実行と期待結果

script は一意の namespace 名を確保し、その中だけに 192.0.2.1/30 と 192.0.2.2/30 を設定します。
受信側の `doc0` に attach し、`capturing (...)...` を待って送信側から ping を送ります。

| ケース | 式と指定 | 結果 |
|---|---|---|
| DSL 一致 | `eth/ipv4/icmp[type==8]`、`-c 3` | summary と最終 pcap が 3 件 |
| DSL 不一致 | `eth/ipv4/tcp[dport==80]` | ping 後に SIGTERM、summary と pcap が 0 件 |
| legacy 一致 | `--cbpf 'icmp'`、`-c 3` | ICMP 3 件 |
| raw-dump | 同じ ICMP 式と `--raw-dump` | 正常終了後に convert、pcap が 3 件 |
| set 更新 | [runtime set](runtime-sets.md) | 同じ capture 中に add/del を反映 |
| tag finalize | 同じ set の tag=7 | delete 後の合算 ack から 3 件を読める |

固定 sleep を起動成功の判定にしません。
不一致ケースは count に達しないので signal で止めます。
timeout、起動失敗、summary 欠落、pcap 読取失敗は 0 件の成功とは扱いません。

## 停止と片付け

各 capture には時間制限があります。
終了時と中断時は、この実行の子プロセスを止めてから namespace と pin を削除します。
pcap と stderr は表示された一意の `/tmp/bpf-ninja-docs.*` ディレクトリに残します。
内容を確認した後、そのディレクトリだけを手動で削除してください。
再現記録には commit、`uname -r`、終了 summary も残します。

## 検証範囲

この smoke test は小規模な ICMP の取得と出力を検査します。
高負荷性能、全 hook、全 protocol の保証には使いません。
広い回帰試験は `make test-bpf` と `make test-integration` です。
script は既存 Integration Tests job でも実行します。

[capture guide](../cli/capture.md) · [出力 guide](../cli/output.md)
