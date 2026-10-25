# キャプチャの問題を切り分ける

実行した commit または release、kernel、command、stderr、終了コードを最初に残します。
pcap に機密な payload がある場合は、そのまま公開 issue に添付せず、再現用 fixture を用意してください。

| 症状 | 最初に確認すること | 次の資料 |
|---|---|---|
| 式の解析で失敗する | tcpdump 構文には `--cbpf`。DSL は packet の L2/L3 始まりに合う chain にする | [DSL](dsl-overview.md) |
| target が見つからない | `-i` は XDP、TC は `-p`。BTF、権限、現在のIDと関数名を確認 | [capture guide](cli/capture.md) |
| xdp mode が既存 XDP を拒否する | 既存 program の観測には entry/exit を使う。観測のために無条件 detach しない | [mode 選択](cli/capture.md) |
| 0 件で終わらない | count は一致した記録で増える。不一致は Ctrl-C で止める | [一致と不一致](examples/capture-recipes.md) |
| `capturing (...)...` が出ない | 起動失敗と setup 待ちを区別。終了 summary がない状態を0件の成功としない | [高負荷 attach の過去の調査](attach-under-load-rcu-finding.md) |
| set 更新が反映されない | 同じ pin/key を参照しているか。resize 後は再 attach。capped/finalized の state と tag 再利用も確認 | [set guide](cli/sets.md) |
| tag の完成ファイルがない | live shard と ack を区別。全 entry の削除、stderr、drain、出力エラーを確認。固定秒数で成功扱いしない | [output guide](cli/output.md) |
| convert が拒否する | raw V2 か。pcap-ng shard や raw V1 を渡していないか | [offline 出力](examples/offline-output.md) |
| 件数が少ない | filter、NIC、ring、hold、writer の計数を分ける。終了コードだけで無損失と判断しない | [lifecycle](../capture-lifecycle.md)、[tuning](tuning.md) |

kernel load や attach の問題は、実際の kernel と権限がある環境で再現を確認します。
`--dump-asm` が成功しても verifier acceptance や runtime の一致は保証しません。
