# 注入後の命令列の独立検査

`injectcheck.Check` は元の命令列、変換後の命令列、対応位置を示す certificate を受け取り、検査結果とエラーを返す。
`pkg/inject` を import せず、変換器の site 選択、再配置、liveness の判定を使用しない。
certificate は検査対象を示すヒントであり、各対応命令の内容と挿入された全命令を検査する。

```go
counts, err := injectcheck.Check(original, transformed, injectcheck.Certificate{
    Original: originalIndices,
    Hooks: hookRanges,
    LowestOffset: auditedFloor,
})
```

`Original[i]` は元命令 i に対応する変換後の decoded instruction index である。
`Hooks` は挿入関数本体の半開区間である。
`LDIMM64` は decoded instruction としては 1 要素、再配置計算では raw slot 2 個として扱う。
メタデータを保持する変換器では、変換前の `Label` と変換後の `FromLabels` で対応位置を抽出できる。
ラベルの欠落と重複を拒否し、ラベルで指した命令の一致は `Check` が別途検査する。

検査項目は次のとおりである。

- 元命令が順序を保って各 1 回現れ、opcode、register、offset、constant、map reference が保存されること。
- 分岐、BPF call、callback 参照の宛先が、同じ元命令または helper 前の spill 列の先頭に移ること。
  元の先頭への後退辺は一度だけ実行する入口 spill を飛ばす。
- 入口、helper 前の spill、u32 注入、hook 本体が許可された形式であること。
- helper 後の処理が限定された命令集合と前方分岐で構成され、各経路で R0 を 64 bit のまま復元すること。
  tail call の失敗経路では R0 の復元を要求せず、R0–R5 の死を確認する。
- 挿入 store が監査床より下の予約領域を使い、R6–R10 を変更しないこと。
  map 値のコピーは R0 から R1 を介して予約領域へ書く load/store 対に限る。
- hook が許可された引数読み出しと return だけを持つこと。
  hook 内の store、helper、kfunc、別の BPF call は拒否する。
- 元命令の直接 RFP アクセスが監査床以上であること。

helper 後と u32 注入位置での liveness は、元の CFG の固定点から求める。
helper の既知の引数数と元の callee の使用レジスタを使い、未知の helper と kfunc は R1–R5 をすべて使用すると扱う。
到達不能な分岐を値解析で除外しないため、安全な変換も拒否しうる。
helper 後の処理は最大 4096 ステップで全経路を調べ、未知の形式と予算超過を拒否する。

## 命令対をファイルから検査する

```sh
go build -o inject-check ./cmd/inject-check
./inject-check pair.json
```

JSON の必須フィールドは `original`、`transformed`、`certificate` である。
命令のフィールドは `asm.Instruction` の `OpCode`、`Dst`、`Src`、`Offset`、`Constant` に加え、文字列の `Symbol` と `Reference` である。
`asm.Metadata` は JSON に保存できないため、symbol と reference を明示する。
`certificate` は Go API と同じフィールドを持つ。
標準出力に `Accepted`、`Counts`、`Reason` を出力し、受理時は終了コード 0、拒否時は 1、入力エラー時は 2 を返す。

検査は BPF をロードせず、attach と pin も行わない。

## 保証の範囲

受理は、元プログラムと変換後プログラムが有効な BPF であり、呼び出し規約と stack-alias audit が正しいことを前提とする。
スタックエイリアス、callee を通じた予約領域へのアクセス、観測者の map 更新、並行実行、時刻と乱数の影響は証明しない。
BTF、CO-RE、kernel verifier の受理、JIT の正しさも判定対象に含めない。
helper 後の引数設定は許可された命令集合と保存条件を検査するが、観測者へ渡す site ID と引数値の正しさは検査しない。
検査済みの命令保存条件と、観測チャネルの値の正しさは別の性質である。

通常のテストは `go test ./pkg/injectcheck ./pkg/inject` で実行する。
既存の同値性 fixture の検査は `go test ./pkg/inject -run '^TestTranslationValidation' -v` で実行する。
corpus の検査は `BPF_NINJA_VALIDATE_OBJECTS` に object ディレクトリ、`BPF_NINJA_VALIDATE_CENSUS` に既存の census 結果ディレクトリ、`BPF_NINJA_VALIDATE_OUTPUT` に保存先を指定する。
corpus テストは拒否を結果ファイルに保存し、チェッカーによる拒否があればテストを失敗させる。
