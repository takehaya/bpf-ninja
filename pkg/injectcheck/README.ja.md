# 注入後の命令列の独立検査

[English](README.md)

`pkg/injectcheck` は `pkg/inject` の変換結果を調べるオフラインのテスト用 oracle である。
`cmd/inject-check` は変換器への依存を含めず個別にビルドする開発ツールであり、`inject-run` やリリース用バイナリには組み込まれていない。
`Check` は元命令の比較、制御フロー辺の解決、挿入領域の導出、挿入された全命令の検査を独立に行う。
変換器の site 選択、再配置、liveness の判定は使用しない。

```go
counts, err := injectcheck.Check(original, transformed, injectcheck.Certificate{
    Original: originalIndices,
    Hooks: hookRanges,
}, injectcheck.Premises{LowestOffset: auditedFloor})
```

**certificate** は未信頼の対応ヒントである。
`Original[i]` は元命令 i に対応する変換後の decoded index、`Hooks` は挿入関数本体の半開区間を表す。
`LDIMM64` は decoded instruction では 1 要素、再配置計算では raw slot 2 個となる。
変換前の `Label` と変換後の `FromLabels` で保持された metadata からヒントを抽出でき、`Check` が内容を別途検査する。
別引数の **premise** である `LowestOffset` は、間接アクセスと callee からの caller-stack pointer の利用を含む、呼び出し側の信頼済み stack-alias audit である。
チェッカーは値の範囲と直接 RFP アクセスを検査するが、命令 projection から alias audit の正しさは確立できない。

## 検査する形式

コメント中のパターン名は次の挿入形式を指す。
「元プログラム」は変換対象のプログラムを指す。

| 名前 | 形式 | 検査する内容 |
| --- | --- | --- |
| P1 | 入口の context spill、任意の entry/dispatch hook と R1 復元 | スロット、dispatch 引数、hook 宛先、復元の一致 |
| P2 | lookup/per-CPU lookup の spill と条件付き observer postlude | 結果分岐 1 個、経路ごとに 1 回の call（分岐先を含め最大 2 個）、値コピー対、全経路での 64-bit R0 復元 |
| P3 | map update/delete の spill と observer postlude | helper 引数 spill、任意の符号付き結果分岐、1 回の call、64-bit R0 復元 |
| P4 | tail call 前の spill と失敗時の postlude | helper 引数と宛先の保存、失敗時の hook、local または入口 frame での context 初期化 |
| P5 | queue/stack の push/pop/peek の spill と observer postlude | helper ごとの spill、1 回の hook、64-bit R0 復元 |
| P6 | `ldxw R2, [R0+offset]` の後の u32 hook | 保存・call・復元の 6 命令、u32 hook 本体、元の継続位置での R1/R3–R5 の死 |
| P7 | observer 関数 | no-op return、u32 XOR return、または許可された context/pointer 読み出しとゼロ return。store と call を拒否 |

スタックスロットの定義は変換器の実装と独立している。
整列した床を `f = LowestOffset &^ 7` とする。
`f` からの相対位置は context が `f-8`、key または tail index が `f-16`、helper 結果が `f-24`、map が `f-32`、update value が `f-40`（map spill がなければ `f-32`）である。
`f-24` には意図的に update の R4/push の R3 の flags を先に置き、postlude が読み出した後に R0 で上書きする。
u32 領域は R0 を `f-8`、R2 を `f-16` に保存するため、入口 context と key のスロットに重なる。
u32 と helper の混在時に、後続 observer が元の context 値を受け取ることは保証しない。観測引数の正しさは受理条件の範囲外である。
挿入 store はすべて `f` より下、512-byte frame 内に収まる必要がある。

各元命令は順序を保って各 1 回現れ、opcode、register、offset、constant、辺以外の reference が一致する必要がある。
不一致の診断はフィールド名を示す。
分岐、BPF call、callback の宛先は対応する元命令または helper prelude の先頭へ再配置する必要がある。
元の入口への後退辺は一度だけ実行する入口 spill を飛ばす。
hook による元命令との重なり、挿入領域の分断、hook への fall-through は拒否する。
挿入命令は R6–R10 と元のスタックを保存し、map 値のコピーは R0 から R1 を介して予約領域へ書く load/store 対に限る。

## 呼び出し規約と保証の範囲

helper 後の処理は verifier-valid な元 BPF を前提とし、実行可能な経路では R1–R5 を再定義する前に読まない。
tail call の失敗時は `RET_VOID` 規約により R0 も読めない。
挿入命令は通常 helper の R0 を全経路で 64-bit 復元し、元命令が読める値と分岐条件を保存するため、読めない scratch register の変更で元の実行不能経路が実行可能になることはない。
構文的 liveness は実行不能経路も含むため、helper 後の拒否条件には使わない。
tail call 成功時は、保存された helper 引数により postlude より前に制御を移す。

u32 load では caller-saved register が読めるため、元 CFG の固定点解析で R1/R3–R5 の死を要求する。
既知 helper は引数数、元 BPF callee は live-in register を用い、未知 helper、kfunc、可変引数 helper は R1–R5 の全読みと扱う。
この保守的解析は安全な u32 site を拒否する場合がある。
helper 後の経路検査は最大 4096 ステップとし、超過時は拒否する。
入口 context spill は function-reference の subprogram/callback 宛先で区切る入口 frame だけを初期化し、callee frame の初期化には使わない。
参照辺を持たない例外 callback は、この frame 識別の前提外である。

受理が対象とする **比較 projection** は decoded instruction のフィールド、reference、解決した辺、検査済みの挿入規則である。
メモリ上の元命令と対応先では、CO-RE、kconfig、kfunc、ksym metadata の pointer identity も一致させる必要があり、hook を含む挿入領域には許可しない。
これは relocation の意味ではなく同一性の検査であり、共有 metadata object が検査中やロード中に変更されないことを前提とする。
固定した cilium/ebpf にはこれらの public iterator がないため private metadata key を読み、各種類の ELF fixture で検査する。
関連付け済み map は、両命令列が同じ関連付けを持っていても拒否する。
map 関連付け前に、両命令列で共有する変化のない外部 symbol/FD 対応表の下で検査する。
数値 FD はその名前空間の識別子であり、プロセスをまたぐ実 map の保存形式ではない。

受理は元プログラムと変換後プログラムの BPF validity、呼び出し規約、信頼済み stack audit を前提とする。
kernel の受理、BTF/CO-RE の意味、JIT の正しさ、observer noninterference、観測引数、並行実行、時刻、乱数は証明しない。
検査で BPF のロード、attach、pin は行わない。

## JSON とエラー分類

```sh
go build -o inject-check ./cmd/inject-check
./inject-check pair.json
```

writer と reader はタグ付きの `injectcheck.Pair` 型を共有する。
format 1 は cilium/ebpf v0.22 の decoded `asm.OpCode` 表現を固定するものであり、kernel の opcode byte とは異なる。
必須のトップレベルキーは `format`、`original`、`transformed`、`certificate`、`premises` で、大文字小文字を区別する。
`certificate.original` と `premises.lowest_offset` も必須で、`certificate.hooks` は空または省略してよい。
Span のフィールドは `start` と `end` である。
命令のフィールドは `opcode`、`dst`、`src`、`offset`、`constant`、`symbol`、`reference` である。
`PseudoMapValue` の offset は `constant` の上位 32-bit、pseudo kind は `src` に保持する。
未知のフィールドと規定外の大小文字表記は入力エラーとする。
任意の証拠 object も含め、すべての階層で大小文字違いを含む重複キーを拒否する。
トップレベルの任意キー `request`、`result`、`reason` は明示的に許可するが、判定には使用しない。

`Pair` の命令には `injectcheck.Instructions` を使い、metadata を黙って失う `asm.Instructions` の直接直列化は使わない。
専用 encoder は関連付け済み map と上記 4 種類の load-time metadata を拒否する。
projection を明示的に保存する producer は、先にメモリ上の metadata identity を検査し、JSON の再検査が projection だけを対象とすることを記録する必要がある。
local census harness はこの方式を使うため、JSON から metadata identity の検査は再現できない。

CLI は `accepted`、`kind`、`counts`、`premises`、`reason` を出力する。
`counts.sites` は検査した site 数で、拒否時は途中までの値となる。
判定に使った premise も出力する。
API エラーは `errors.As` で次のように区別でき、どちらも安定した `Kind` と診断用 `Detail` を持つ。

| 結果 | 型 | CLI 終了コード | 例 |
| --- | --- | --- | --- |
| 受理 | nil | 0 | 検査規則をすべて満たす |
| 入力エラー | `*InputError` | 2 | JSON 不正、必須フィールドの欠落・null（名前を診断）、元命令列・対応表の空値、対応表の長さ・順序不正、hook 範囲の不正・重なり、[-512,0] 外の床、不正な元 register、未対応 format |
| 変換の拒否 | `*Rejection` | 1 | 命令・reference・辺の変更、挿入 store・分岐・register effect・hook の違反、metadata の変更、関連付け済み map |

decode・file・usage エラーは stderr に出し、validation が見つけた構造上の入力エラーは JSON verdict も返す。
元命令列の空値、対応表の空値、長さ不一致、床の不正は別の kind を持つ。

## テストと local corpus の証拠

通常の実行は `go test ./pkg/injectcheck ./pkg/inject ./cmd/inject-check` である。
`TestPairCorpus` は CLI をビルドし、コミット済み命令対の期待値 `{accepted, kind}`、API、CLI の全 verdict を比較する。
対象は受理される 7 設定と 11 変異であり、コミット済み CLI/API 一致テストの主張はこの範囲に限る。
`TestTranslationValidationEquivalence` は予定 site/hook 数と検査数を照合し、site がある fixture とゼロの fixture を分けて記録する。
依存テストは checker と CLI から `pkg/inject` への直接・間接依存を拒否する。

privileged な `TestBpf*` fixture はロードと `BPF_PROG_TEST_RUN` だけを使い、`scripts/test/privileged.py` に登録している。
適切なテスト VM の root で `go test ./pkg/injectcheck -run '^TestBpf' -v` を実行する。
map identity と、lookup・delete・tail-call の postlude が前提とする verifier の挙動を検査する。

local-only census には `BPF_NINJA_VALIDATE_OBJECTS`、`BPF_NINJA_VALIDATE_CENSUS`、`BPF_NINJA_VALIDATE_OUTPUT` を指定する。
census 結果の `<object>--<program>/plain/load.json` に外部 stack-audit ツール由来の `Bound` が必要であり、このリポジトリはその audit を生成しない。
床ファイルが欠落した program は全 4 形式を `INPUT_REFUSED` として記録し、受理数に含めない。
raw 形式の数と plan は独立に計算し、typed 形式の変換拒否で raw を実行しなかった場合は `RAW_NOT_RUN` を明記する。
4 形式は同じ program の反復であり、独立標本ではない。
