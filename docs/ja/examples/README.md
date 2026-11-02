# Examples

各例には、必要条件、コマンド、期待される結果、停止と片付けの手順があります。

| 目的 | 手順 | 権限 |
|---|---|---|
| ロードせずに DSL と生成命令を確認する | [フィルタの offline 確認](inspect-filter.md) | 一般ユーザー |
| veth で一致、不一致、出力を確認する | [隔離 capture recipe](capture-recipes.md) | 専用 Linux 環境の root |
| 実行中に set を更新する | [runtime set](runtime-sets.md) | 専用 Linux 環境の root |
| トンネル内部の式を確認する | [tunnel filters](tunnel-filters.md) | 一般ユーザー（compile のみ） |
| raw を変換し、tag shard を合算する | [offline output](offline-output.md) | 入出力ファイルへのアクセス権限 |
| fentry/fexit と subfunction を手動で確認する | [手動試験](../handtest.md) | 隔離 Linux 環境の root |
| map 操作の列挙から inject-run と fentry 観測までを試す | [injection walkthrough](../../en/inject-walkthrough.md)、[ソース](../../../examples/inject-walkthrough/README.md)（英語、実験的機能） | 専用 Linux x86-64 環境の root |
| inject hook で集計、CPU ID、経過時間を観測する | [observer examples](../../en/inject-observers.md)、[ソース](../../../examples/inject-observers/README.md)（英語） | 専用 Linux x86-64 環境の root |
| set map を手動で操作する | [set guide](../cli/sets.md#手元で動きを確かめる) | Linux の BPF map 操作権限 |
| 自動試験の環境を用意する | [privileged tests](../../privileged-tests.md) | 専用 Linux 環境の root |

legacy の `--cbpf` を使う例では、`make build-libpcap` で作成した binary が必要です。
一致しないことを確かめる試験では、count に達するのを待たずに停止します。
正常終了の summary と、取得件数が 0 件であることを確認してください。

[Docs に戻る](../README.md)
