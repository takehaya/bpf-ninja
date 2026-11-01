# CLI リファレンスの読み方

[command と flag の全一覧](generated/commands.md)と[protocol と field の一覧](generated/protocols.md)は、コードから生成されています。
protocol の一覧は `--dsl-help` の出力と同じ内容です。

## 操作上の制約

- フィルタの既定は DSL です。tcpdump 構文を使うには `--cbpf` を指定します。`--cbpf` は libpcap 付きの build（`make build-libpcap`）でのみ使えます。
- ルートコマンドの slice flag は値をカンマで分割しません。`--prog-id 1 --prog-id 2` のように繰り返し指定します。下位 command は既定の区切り文字を使います。
- `--mode` を二つ指定すると、同じ実行の entry と exit の両方に一致したパケットだけを取得します。`--emit both` の場合、`-c` は入口と出口のパケットをそれぞれ 1 レコードとして数えます。
- flag 表の必須列は、flag の宣言上の属性を示します。`convert --read` や `merge --base` のように、実行時に必須かどうかを検査する入力もあります。
- `set create` には key schema が必須です。`set resize` は writer を止めてから実行してください。新しい map の容量は次の attach から有効になります。
- `--list-progs --list-maps` は、各関数の呼び出しと map 操作を tree で表示します。ロード済み program の命令を読み取るため、root 権限が必要です。`--lookups-json` には、同じロードで `inject-run --lookups-json` が出力したファイルを渡します。
- `inject-run --config rules.json -- <target> [args...]` は、無変更の BPF loader を起動し、ロード時に hook を注入します。Linux x86-64 限定の実験的な機能です。設定と制約は [inject-run](../../en/inject-run.md) を参照してください。
- `capture status=complete` は、記録の drain と出力が完了したことを示します。wire 上の全パケットを取得したことや、fsync で永続化したことは意味しません。

mode、hook、target の選び方は [capture guide](capture.md) を、終了と損失の指標は [capture lifecycle](../../capture-lifecycle.md) を参照してください。

## 生成物の更新

生成ファイルは直接編集しないでください。直接編集すると `make docs-check` が失敗します。
更新の手順は [CONTRIBUTING.md](../../../CONTRIBUTING.md#command-and-protocol-references) にあります。
文言や制約を変更するときは、生成元のコードと手書きの説明の両方を更新してください。

[DSL 利用ガイド](../dsl-usage.md) · [Repository README](../../../README.md)
