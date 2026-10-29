# 注入後の命令列の独立検査

[English](README.md)

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

`Instruction.Map()` が非 nil の命令は、元命令列と変換後命令列のどちらにあっても拒否する。
同じ map の関連付けも拒否対象であり、挿入領域と hook も例外にしない。
`AssociateMap` または map の書き換えを行う前に検査する。
map operand は両命令列で共有する変化のない外部対応表を前提とし、未解決の `Reference` または同一 FD 空間の数値として比較する。
同じ名前の map spec を別の実 map へ置換する処理は検査対象外である。

検査項目は次のとおりである。

- 元命令が順序を保って各 1 回現れ、opcode、register、offset、constant、map reference が保存されること。
- 分岐、BPF call、callback 参照の宛先が、同じ元命令または helper 前の spill 列の先頭に移ること。
  元の先頭への後退辺は一度だけ実行する入口 spill を飛ばす。
- 入口、helper 前の spill、u32 注入、hook 本体が許可された形式であること。
- helper 後の処理が限定された命令集合と前方分岐で構成され、各経路で R0 を 64 bit のまま復元すること。
  tail call の失敗経路では G3 A3 により R0–R5 が読めないことを前提とし、R0 の復元を要求しない。
- 挿入 store が監査床より下の予約領域を使い、R6–R10 を変更しないこと。
  map 値のコピーは R0 から R1 を介して予約領域へ書く load/store 対に限る。
- hook が許可された引数読み出しと return だけを持つこと。
  hook 内の store、helper、kfunc、別の BPF call は拒否する。
- 元命令の直接 RFP アクセスが監査床以上であること。

## 呼び出し規約と liveness

P2–P5 は G3 A3（呼び出し規約）を前提とする。
元プログラム P は verifier に受理される有効な BPF であり、helper の直後の R1–R5 は、実行可能な経路で再定義前に読まれない。
挿入領域は R6–R10 と元のスタックを保ち、通常の helper の R0 を全経路で復元するため、元命令の読める値と分岐条件は変わらない。
したがって P で実行不能だった経路が、scratch レジスタへの書き込みによって実行可能になることもない。
値域を使わない構文的 CFG の liveness は、そのような実行不能経路を含めて live と判定するため、P2–P5 の拒否条件には用いない。

P4 の tail call は成功すれば postlude を実行せず、helper の引数と転送先も不変である。
失敗して戻る場合は `RET_VOID` の規約により R0 も未初期化となるため、A3 の下で R0–R5 への書き込みは P の観測を変えない。
この判断は P の verifier validity と A3 に依存し、無効な P を入力した場合の保証はない。
ctx スロットは、検査した入口 spill がある入口 frame、または同じ site の prelude に ctx spill がある frame でのみ初期化済みと扱う。
subprogram と callback の開始位置は元の function reference の宛先から求め、入口 frame の spill を callee frame の初期化には使わない。

P6（u32 版）の挿入位置は通常の load の直後であり、A3 の helper 規約は適用できない。
P6 は R0 と R2 を保存して復元するが R1 と R3–R5 を壊すため、元 CFG の固定点から求めた liveness でこれらの死を要求する。
既知 helper の引数数と元 callee の使用レジスタを使い、未知 helper、kfunc、`trace_printk` などの可変引数 helper は R1–R5 の全読みと扱う。
値や書式を解析しないため、安全な P6 を拒否する場合がある。
certificate の未検証の到達不能宣言で CFG の辺を除外することはしない。
helper 後の処理は最大 4096 ステップで全経路を調べ、未知の形式と予算超過を拒否する。

## 命令対をファイルから検査する

```sh
go build -o inject-check ./cmd/inject-check
./inject-check pair.json
```

JSON の必須のトップレベルフィールドは `Original`、`Transformed`、`Certificate` である。
フィールド名の大文字小文字は区別せず、小文字の表記も受け付ける。
必須フィールドの欠落または null は入力エラー（終了コード 2）とし、メッセージにフィールド名を示す。
命令のフィールドは `asm.Instruction` の `OpCode`、`Dst`、`Src`、`Offset`、`Constant` に加え、文字列の `Symbol` と `Reference` である。
JSON 生成には `json.Marshal(injectcheck.Instructions(insns))` を使う。
この型は symbol と reference を保存し、関連付け済み map があれば直列化をエラーにする。
`asm.Instructions` を直接直列化すると map metadata が消えるため、その出力を CLI の入力にしてはならない。
CLI は命令の未知のフィールドを入力エラーにする。
`Metadata` も空かどうかを問わず拒否し、専用 encoder が保存するフィールドだけを扱う。
JSON 中の map 名と数値 FD は両命令列で共有する識別子であり、実 map やプロセスをまたぐ FD の有効性は保存しない。
`PseudoMapValue` の上位32 bit の offset も `Constant` に保存し、`Src` の pseudo kind とともに完全一致を要求する。
`certificate` は Go API と同じフィールドを持つ。
標準出力に `Accepted`、`Counts`、`Reason` を出力し、受理時は終了コード 0、拒否時は 1、入力エラー時は 2 を返す。

検査は BPF をロードせず、attach と pin も行わない。

## 保証の範囲

受理は、元プログラムと変換後プログラムが有効な BPF であり、呼び出し規約と stack-alias audit が正しいことを前提とする。
G3 §3.3 T2 の構文的十分条件を調べるものであり、kernel verifier や一般的な等価性の証明を提供するものではない。
スタックエイリアス、callee を通じた予約領域へのアクセス、観測者の map 更新、並行実行、時刻と乱数の影響は証明しない。
BTF、CO-RE、kernel verifier の受理、JIT の正しさも判定対象に含めない。
helper 後の引数設定は許可された命令集合と保存条件を検査するが、観測者へ渡す site ID と引数値の正しさは検査しない。
検査済みの命令保存条件と、観測チャネルの値の正しさは別の性質である。

通常のテストは `go test ./pkg/injectcheck ./pkg/inject` で実行する。
既存の同値性 fixture の検査は `go test ./pkg/inject -run '^TestTranslationValidation' -v` で実行する。
corpus の検査は `BPF_NINJA_VALIDATE_OBJECTS` に object ディレクトリ、`BPF_NINJA_VALIDATE_CENSUS` に既存の census 結果ディレクトリ、`BPF_NINJA_VALIDATE_OUTPUT` に保存先を指定する。
corpus テストは拒否を結果ファイルに保存し、チェッカーによる拒否があればテストを失敗させる。
