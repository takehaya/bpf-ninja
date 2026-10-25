# Examples

各例は前提、実行、期待結果、停止と片付けを一組として扱います。
実行前に対象の checkout と必要条件を確認してください。

| 目的 | 手順 | 権限 |
|---|---|---|
| DSL と生成命令をロードせず確認する | [フィルタの offline 確認](inspect-filter.md) | 一般ユーザー |
| fentry/fexit と subfunction を手動検証する | [手動試験](../handtest.md) | 隔離 Linux 環境の root |
| set map の操作を確認する | [既存 set 手順](../dsl-usage.md#hand-test-として-set-map-を手元で叩く) | Linux の BPF map 操作権限 |
| 自動試験の環境を用意する | [privileged tests](../../privileged-tests.md) | 専用 Linux 環境の root |

コンパイルだけを確認した例を、実パケット取得済みとは扱いません。
負の試験では count 到達を待たず、明示停止して正常な終了 summary と 0 件を確認します。

[Docs に戻る](../README.md)
