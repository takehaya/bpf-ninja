# Examples

各例には、実行に必要な前提とコマンド、期待する結果、停止と片付けの手順を記載しています。
実行前に対象の checkout と必要条件を確認してください。

| 目的 | 手順 | 権限 |
|---|---|---|
| DSL と生成命令をロードせず確認する | [フィルタの offline 確認](inspect-filter.md) | 一般ユーザー |
| vethで一致と不一致、出力を検証する | [隔離capture recipe](capture-recipes.md) | 専用Linux環境のroot |
| 実行中にsetを更新する | [runtime set](runtime-sets.md) | 専用Linux環境のroot |
| トンネル内部の式を確認する | [tunnel filters](tunnel-filters.md) | 一般ユーザー（compileのみ） |
| rawを変換しtag shardを救出する | [offline output](offline-output.md) | 入出力ファイルへの権限 |
| fentry/fexit と subfunction を手動検証する | [手動試験](../handtest.md) | 隔離 Linux 環境の root |
| map 操作の列挙から inject-run と fentry 観測まで試す | [injection walkthrough](../../en/inject-walkthrough.md)、[ソース](../../../examples/inject-walkthrough/README.md)（英語、実験的機能） | 専用 Linux x86-64 環境の root |
| set map の操作を確認する | [既存 set 手順](../dsl-usage.md#hand-test-として-set-map-を手元で叩く) | Linux の BPF map 操作権限 |
| 自動試験の環境を用意する | [privileged tests](../../privileged-tests.md) | 専用 Linux 環境の root |

コンパイルだけを確認した例を、実パケット取得済みとは扱いません。
フィルタに一致しないことを確かめる試験では、count に達するのを待たずに停止します。
正常な終了 summary と取得件数 0 件を確認してください。

[Docs に戻る](../README.md)
