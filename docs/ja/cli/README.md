# CLI リファレンスの読み方

[command と flag の全一覧](generated/commands.md)は既存 constructor から、[protocol と field](generated/protocols.md)は `--dsl-help` と同じ公開 API から生成します。
手元のバイナリと、この文書を含むソースの版を揃えて参照してください。

## 操作上の制約

- DSL が既定です。tcpdump 構文には `--cbpf` を付けます。
- ルートコマンドの slice flag はカンマで分割しません。`--prog-id 1 --prog-id 2` のように繰り返します。下位 command は既定の separator を使います。
- `--mode` を複数指定すると、同じ実行の entry と exit を組み合わせて観測します。`--emit both` の `-c` は、入口と出口のパケットをそれぞれ 1 レコードとして数えます。
- flag 表の「必須」は宣言上の属性です。`convert --read` と `merge --base` など、Action 内で必須確認する入力もあります。
- `set create` は key schema が必須です。`set resize` は writer を止めて行い、新 map の容量は次の attach から有効になります。
- `--list-progs --list-maps` は各関数の呼出しと map 操作を tree で表示します。load 済み program の命令を読むため root が必要です。`--lookups-json` には `inject-run --lookups-json` が同じ load で出力したファイルを渡します。
- `inject-run --config rules.json -- <target> [args...]` は未変更の BPF loader を起動し、load 時に hook を注入します。Linux x86-64 限定の実験機能です。設定と制約は [inject-run](../../en/inject-run.md) を参照してください。
- `complete` は drain と出力完了の状態です。全 wire packet の取得や fsync の耐久性を保証する表示ではありません。

mode、hook、target の選択は[利用ガイド](../dsl-usage.md)、終了と損失指標は[capture lifecycle](../../capture-lifecycle.md)を参照してください。

## 更新と検査

command の生成と比較には Linux x86-64 と通常の build 依存（Go と libpcap の開発環境）が必要です。
他の platform では command の比較を skip し、更新はエラーにします。
root や BPF load は不要です。

```sh
make docs-update
make docs-check
go test -count=2 -shuffle=on ./cmd/bpf-ninja
```

`cmd/bpf-ninja/docs_test.go` は通常テストで比較のみを行います。
更新時だけ生成ファイルを書き換えます。
コマンドごとに help を実行して urfave を初期化し、公開される help/version も記録します。
非表示の completion command は一覧の対象外です。
application の Action は生成用にエラーへ置き換え、capture、injection、map 操作を実行しません。
時刻や build の識別情報は生成物に含めません。

文言や制約を変更するときは、生成元と手書きの操作説明の両方を確認してください。
生成物の直接編集は次の検査で失敗します。

[DSL 利用ガイド](../dsl-usage.md) · [Repository README](../../../README.md)
