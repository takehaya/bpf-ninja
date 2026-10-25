# CLI リファレンスの読み方

[command と flag の全一覧](generated/commands.md)は既存 constructor から、[protocol と field](generated/protocols.md)は `--dsl-help` と同じ公開 API から生成します。
この checkout と同じ版の binary で読むことを前提とします。

## 操作上の制約

- DSL が既定です。tcpdump 構文には `--cbpf` を付けます。
- root の slice flag は comma で分割しません。`--prog-id 1 --prog-id 2` のように繰り返します。下位 command は既定の separator を使います。
- `--mode` の複数指定は entry/exit の組合せです。単なる複数 capture の列挙ではありません。`--emit both` の `-c` は画像のレコード数を数えます。
- flag 表の「必須」は宣言上の属性です。`convert --read` と `merge --base` など、Action 内で必須確認する入力もあります。
- `set create` は key schema が必須です。`set resize` は writer を止めて行い、新 map の容量は次の attach から有効になります。
- `complete` は drain と出力完了の状態です。全 wire packet の取得や fsync の耐久性を保証する表示ではありません。

mode、hook、target の選択は[利用ガイド](../dsl-usage.md)、終了と損失指標は[capture lifecycle](../../capture-lifecycle.md)を参照してください。

## 更新と検査

Linux の通常の build 依存（Go と libpcap の開発環境）が必要です。
root や BPF load は不要です。

```sh
make docs-update
make docs-check
go test -count=2 -shuffle=on ./cmd/bpf-ninja
```

`cmd/bpf-ninja/docs_test.go` は通常テストで比較のみを行います。
更新時だけ生成ファイルを書き換えます。
command ごとの help で urfave の初期化を通し、公開 help/version も記録します。非表示の completion command は一覧の対象外です。
application の Action は生成用にエラーへ置き換え、capture や map 操作を実行しません。
時刻や build の識別情報は生成物に含めません。

文言や制約を変更するときは、生成元と手書きの操作説明の両方を確認してください。
生成物の直接編集は次の検査で失敗します。

[DSL 利用ガイド](../dsl-usage.md) · [Repository README](../../../README.md)
