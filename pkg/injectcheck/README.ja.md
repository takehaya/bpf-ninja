# 注入後の命令列の独立検査

[English](README.md)

`pkg/injectcheck` は `pkg/inject` の変換結果を独立に検査し、`pkg/inject` の通常コードも target binding の型を利用する。
`cmd/inject-check` は、変換器への依存を含めず個別にビルドする開発ツールである。
`inject-run` もこの package を使い、置換する `BPF_PROG_LOAD` を再開する直前に assemble 済みの命令列を検査する。
検査時点と保証範囲は、[load-stream check](../../docs/en/inject-run.md#load-stream-check)に示す。
`Check` は元命令の比較、制御フロー辺の解決、挿入領域の導出、挿入された全命令の検査を独立に行う。
変換器の再配置と liveness の判定は再利用しない。
命令形式だけでは site の意図を識別できないため、信頼済み入力 `Premises.Targets` で plan の site、結果、hook の対応を渡す。

```go
plannedSiteTargets, err := inject.BuildLookupTargets(transformed, result.Hooks)
if err != nil {
    if errors.Is(err, inject.ErrCheckerNotApplicable) {
        // checker が対応づけられない場合の方針を caller 側で適用する。
    }
    return err
}
counts, err := injectcheck.Check(original, transformed, injectcheck.Certificate{
    Original: originalIndices,
    Hooks: hookRanges,
}, injectcheck.Premises{
    Frames: verifierFloors,
    Targets: plannedSiteTargets,
})
```

**certificate** は対応情報を渡す。
`Original[i]` は元命令 i に対応する変換後の decoded index、`Hooks` は挿入関数本体の半開区間を表し、どちらも `Check` が内容を独立に検査する未信頼のヒントである。
`LDIMM64` は decoded instruction では 1 要素、再配置計算では raw slot 2 個となる。
変換前の `Label` と変換後の `FromLabels` で保持された metadata からヒントを抽出でき、`Check` が内容を別途検査する。
別引数の **premises** は呼び出し側の信頼済み入力である。
`Frames` は各関数の開始位置と、信頼済みの stack の床を渡す。
指定する場合は両 field を持たせ、元命令 0 から始め、開始位置の昇順で元の命令列全体を覆う必要がある。
`inject-run` は試行ロードに対する verifier の subprogram 別の計上値からこれを作り、より深い直接参照があればそちらを使う。
`Frames` が空の場合、`LowestOffset` はライブラリ API の単一床 fallback として残る。
`Targets` は plan の用語で `{Site, When, Hook, Ctx}`、すなわち元命令 index、`hit`、`miss`、`any`、`error` のいずれか、生成 hook の decoded 開始 index、任意の callee-frame context 由来を対応づける。
`Ctx` は R6-R9、audit 済み frame 内の整列 slot、または同期 callback 内の site では `{param, arg}` を指す。`param` は callback が `callback_ctx` を受け取る register（R2 または R4）、`arg` はそのポインタの entry frame 内 offset である。
チェッカーは prelude が指定された由来をコピーすることを検査するが、その由来が意味的に context を保持することまでは証明しない。
map call では省略時に既存の entry-frame 経路を使うが、従来の P4 tail-call 形式では helper R1 から callee frame を直接初期化する場合もある。
lookup の `any` は hit と miss の両方の経路で hook を呼ぶことを要求する。
lookup site の `Args` は、計画した hook が R1 から順に受け取るもの（`ctx`、続いて hook が持つ順に `site`、`key`、`value`、`map`）を、`SitePC` は `site` 引数の即値を表す。
有効なのは lookup hook が持ちうる 5 通りだけである。`site` の有無による typed の 2 通り、`value` のない typed miss の 2 通り、generic の `ctx, site, key, value, map` である。
lookup hook の各 call は、この役割をこの順で渡し、最後の引数より後の引数 register を設定してはならない。`inject.BuildLookupTargets` は plan からこれを埋める。
wrapper を使う site には `Args` が必須である。`Args` のない他の site には、下記の由来の規則だけを適用する。
caller は `inject.BuildLookupTargets` を使うか、同じ情報を変換後 call の reference ではなく plan から作る必要がある。
`BuildLookupTargets` は、宛先を対応づけられない indirect `callx` に `inject.ErrCheckerNotApplicable` を返す。
`inject-run` は既定では置換後 stream を未検査のままロードし、`--fail-closed` 指定時だけ拒否する。
チェッカーは値の範囲と直接 RFP アクセスを検査するが、命令 projection から alias audit の正しさは確立できない。
どちらかの stream に indirect jump (`BPF_JA|BPF_X`) があれば、宛先が両 stream の外の map にあるため `indirect_jump` で拒否する。

## 検査する形式

コメント中のパターン名は次の挿入形式を指す。
「元プログラム」は変換対象のプログラムを指す。

| 名前 | 形式 | 検査する内容 |
| --- | --- | --- |
| P1 | 入口の context spill、任意の entry/dispatch hook と R1 復元 | スロット、dispatch 引数、hook 宛先、復元の一致 |
| P1b | site を持つ同期 callback の入口での context load | plan が指名した register を通る load と、entry 床と `arg` から導いた offset、store の完全一致。関数辺はここに入り、分岐は飛ばす。元の参照から premise を導き直す |
| P1c | map helper 前の callee-frame context 初期化 | plan が指名した R6-R9 からの store、または audit 済み slot から R0 を介した load と context store の完全一致 |
| P2 | lookup/per-CPU lookup の spill と条件付き observer postlude | 結果分岐 1 個、経路ごとに 1 回の call（分岐先を含め最大 2 個）、plan の結果経路別宛先、R1 context、generic/dispatch の R3-R5 の由来と順序、値コピー対、全経路での 64-bit R0 復元 |
| P3 | map update/delete の spill と observer postlude | helper 引数 spill、任意の符号付き結果分岐、plan の結果別宛先、R1 context、generic/dispatch の R3-R5 の由来と順序、1 回の call、64-bit R0 復元 |
| P4 | tail call 前の spill と失敗時の postlude | helper 引数と宛先の保存、plan の hook、R1 context、dispatch の R4/R5 の由来、local または入口 frame での context 初期化 |
| P5 | queue/stack の push/pop/peek の spill と observer postlude | helper ごとの spill、plan の結果別宛先、R1 context、generic/dispatch の R3-R5 の由来と順序、1 回の hook、64-bit R0 復元 |
| P6 | `ldxw R2, [R0+offset]` の後の u32 hook | 保存・call・復元の 6 命令、u32 hook 本体、元の継続位置での R1/R3–R5 の死 |
| P8 | helper を wrapper 関数へ移した lookup site（`Certificate.Wrappers`） | 計画どおりの ctx を R4 へ読む 1 命令の prelude、wrapper と site の 1 対 1、結果経路ごとの計画した宛先と `Args` から組み立てた本体との完全一致（hit 先と miss 先のどちらの配置も可） |
| P7 | observer 関数 | no-op return、u32 XOR return、または許可された context/pointer 読み出しとゼロ return。store と call を拒否 |

スタックスロットの定義は変換器の実装と独立している。
命令を所有する関数の床を 8 byte 単位で切り下げた値を `f` とする。
`f` からの相対位置は context が `f-8`、key または tail index が `f-16`、helper 結果が `f-24`、map が `f-32`、update value が `f-40`（map spill がなければ `f-32`）である。
`f-24` には意図的に update の R4/push の R3 の flags を先に置き、postlude が読み出した後に R0 で上書きする。
u32 領域は R0 を `f-8`、R2 を `f-16` に保存するため、入口 context と key のスロットに重なる。
helper hook call は保存済み context を R1 に要求する。
generic と dispatch の map call は NULL 役の定数 0 を含む helper ごとの R3-R5 の役割を検査し、dispatch tail call は R3-R5 を検査する。
`Args` がなければ、R2 の site id または info word は site tag を持つすべての hook で未検査である。`Args` があれば lookup hook の役割と site 即値を検査する。update、delete、push、pop、peek、tail call、u32 の hook には `Args` がないので、それらの site id と info word は未検査のままである。
typed hook と static non-generic hook の key/value の役割も受理条件の範囲外である。
u32 と helper が混在する stream では、後続 observer が元の context を受け取ることまでは確立しない。
u32 領域は、後続 helper hook が R1 を reload する slot と同じ場所へ R0 を保存するためである。
挿入 store はすべて `f` より下、512-byte frame 内に収まる必要がある。
P1c が読めるのは、その関数の床以上にある premise 指名の整列 slot だけである。

各元命令は順序を保って各 1 回現れ、opcode、register、offset、constant、辺以外の reference が一致する必要がある。
不一致の診断はフィールド名を示す。
分岐、BPF call、callback の宛先は対応する元命令または helper prelude の先頭へ再配置する必要がある。
元の入口への後退辺は一度だけ実行する入口 spill を飛ばす。
hook による元命令との重なり、挿入領域の分断、hook への fall-through は拒否する。
挿入命令は R6–R10 と元のスタックを保存し、map 値のコピーは R0 から R1 を介して予約領域へ書く load/store 対に限る。

wrapper は、callee 内に置いた元の helper call として受理する。
prelude が書くのは R4 だけで、lookup は R4 を読まず、helper の後は R4 を読めない。
wrapper 本体は、許容テンプレートのどれかとの一致ではなく、site の target から組み立てた 1 つの本体との完全一致で検査する。
本体は R4、R2、および map を受け取る hook が計画されている場合の R1 を自分の R6、R7、R9 へ写し、元の引数のまま元の helper を実行し、R0 を R8 へ写す。
結果経路ごとに、計画した hook を計画した `Args` と site 即値で呼ぶ。計画にない経路では何も呼ばない。最後に R8 を R0 に戻して返る。
R10 を使わないので caller の stack は変わらず、BPF の呼び出し規約により caller の R6-R9 も保たれる。
元命令が位置を離れるのはこの場合だけである。`Original[i]` は wrapper への call を指し、チェッカーは wrapper 内の helper と元命令 i を比較する。
`Certificate.Wrappers` は `Hooks` と同じくヒントであり、どの site からも呼ばれない wrapper と、2 つの site から呼ばれる wrapper は拒否する。

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
入口 context spill は function-reference の subprogram/callback 宛先で区切る入口 frame だけを初期化する。
callee-frame の site は、信頼済み target premise が指名した register または slot から helper prelude 内で context slot を初期化する必要がある。
callback の site では、その関数の先頭が `ldx r0, [param + entry_floor - 8 - arg]; stx [floor - 8], r0` でなければならない。関数参照は load に、分岐は store の次に着地する必要がある。
この関数についてチェッカーは元の命令列から premise を導き直す。site が関数の先頭から call を経ずに到達できること、direct call がないこと、すべての参照が命令 0 から到達できること、R2 に load され次の call が同じ `bpf_loop` または `bpf_for_each_map_elem` であること、R3 が直線のコードで `arg` として作られ、その間に atomic や legacy packet load を含め R3 を書く命令がなく、分岐も入ってこないことを確かめる。
site と関数の先頭は同じ frame 床でなければならない。frame 床は entry の途中や callback の先頭より後で始まってはならず、`arg` は entry の床より下であってはならず、entry の site は context 由来を指定してはならない。program には u32 region があってはならない（u32 region は R0 を context slot に保存する）。
関数が static であること、entry の slot が context を保持することは、変換側の証明と stack 床に依存する。stack 床は callback が `callback_ctx` を通して entry frame に書く範囲も含まなければならない。
参照辺を持たない例外 callback は、この frame 識別の前提外である。

受理が対象とする **比較 projection** は decoded instruction のフィールド、reference、解決した辺、検査済みの挿入規則である。
メモリ上の元命令と対応先では、CO-RE、kconfig、kfunc、ksym metadata の pointer identity も一致させる必要があり、hook を含む挿入領域には許可しない。
これは relocation の意味ではなく同一性の検査であり、共有 metadata object が検査中やロード中に変更されないことを前提とする。
固定した cilium/ebpf にはこれらの public iterator がないため private metadata key を読み、各種類の ELF fixture で検査する。
nil metadata key はロード時の意味を持たないため checker と命令 encoder の両方で無視し、想定外の metadata layout は型付きの `MetadataUnsupported` 拒否として返す。
関連付け済み map は、両命令列が同じ関連付けを持っていても拒否する。
map 関連付け前に、両命令列で共有する変化のない外部 symbol/FD 対応表の下で検査する。
数値 FD はその名前空間の識別子であり、プロセスをまたぐ実 map の保存形式ではない。

受理は元プログラムと変換後プログラムの BPF validity、呼び出し規約、信頼済みの関数別 stack の床、plan 由来の信頼済み Targets を前提とする。
kernel の受理、BTF/CO-RE の意味、JIT の正しさ、observer noninterference、明記した検査以外の観測引数、並行実行、時刻、乱数は証明しない。
検査で BPF のロード、attach、pin は行わない。

## JSON とエラー分類

```sh
go build -o inject-check ./cmd/inject-check
./inject-check pair.json
```

writer と reader はタグ付きの `injectcheck.Pair` 型を共有する。
format 3 は、format 2 が固定した cilium/ebpf v0.22 の decoded `asm.OpCode` 表現に、任意の callee context 由来を追加する。
format 4 は `premises.frames` に関数別の床を追加する。
format 5 は `ctx` に `param` と `arg` を追加する。
reader は format 2 から 5 を受理し、format 番号は kernel の opcode byte とは異なる。
必須のトップレベルキーは `format`、`original`、`transformed`、`certificate`、`premises` で、大文字小文字を区別する。
`certificate.original`、`premises.lowest_offset`、`premises.targets` も必須で、format 4 では `start` と `lowest_offset` の両方を持ち、0 から始まる `premises.frames` も指定できる。
`certificate.hooks` は空または省略してよく、`premises.targets` を空にできるのは挿入 call がない場合だけである。
Span のフィールドは `start` と `end`、target のフィールドは `site`、`when`、`hook`、任意の `ctx`、`args`、`site_pc` である。
`ctx` は `reg`（6 から 9）または `slot`（整列した負の frame offset）のどちらかを持つ。
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
判定に使った Targets を含む premises も出力する。
API エラーは `errors.As` で次のように区別でき、どちらも安定した `Kind` と診断用 `Detail` を持つ。

| 結果 | 型 | CLI 終了コード | 例 |
| --- | --- | --- | --- |
| 受理 | nil | 0 | 検査規則をすべて満たす |
| 入力エラー | `*InputError` | 2 | JSON 不正、必須フィールドの欠落・null、元命令列・対応表の空値、対応表の長さ・順序不正、hook 範囲の不正・重なり、target plan の欠落・不正・重複、[-512,0] 外の床、不正な元 register・CFG、未対応 format |
| 変換の拒否 | `*Rejection` | 1 | 命令・reference・辺の変更、計画外の call または計画済み call の欠落、挿入 store・分岐・register effect・hook の違反、metadata の変更、関連付け済み map |

decode・file・usage エラーは stderr に出し、validation が見つけた構造上の入力エラーは JSON verdict も返す。
元命令列の空値、対応表の空値、長さ不一致、床の不正は別の kind を持つ。

## テストと local corpus の証拠

通常の実行は `go test ./pkg/injectcheck ./pkg/inject ./cmd/inject-check` である。
`TestPairCorpus` は CLI をビルドし、コミット済み format 2 命令対の期待値 `{accepted, kind}`、API、CLI の全 verdict を比較する。
対象は受理される 7 設定と 11 変異であり、コミット済み CLI/API 一致テストの主張はこの範囲に限る。
`TestTranslationValidationSubprogramContextPairCorpus` は register と slot の premise を format 3 で round-trip し、別 register、別 slot、対応する初期化の欠落を拒否する。
`TestTranslationValidationEquivalence` は検査済み site 数と certificate の hook 名を計画と照合し、site を持たない entry hook も対象に含め、site がある fixture とゼロの fixture を分けて記録する。
依存テストは checker と CLI から `pkg/inject` への直接・間接依存を拒否する。

privileged な `TestBpf*` fixture はロードと `BPF_PROG_TEST_RUN` だけを使い、`scripts/test/privileged.py` に登録している。
適切なテスト VM の root で `go test ./pkg/injectcheck -run '^TestBpf' -v` を実行する。
map identity と、lookup・delete・tail-call の postlude が前提とする verifier の挙動を検査する。

local-only census には `BPF_NINJA_VALIDATE_OBJECTS`、`BPF_NINJA_VALIDATE_CENSUS`、`BPF_NINJA_VALIDATE_OUTPUT` を指定する。
census 結果の `<object>--<program>/plain/load.json` に外部 stack-audit ツール由来の `Bound` が必要であり、このリポジトリはその audit を生成しない。
床ファイルが欠落した program は全 4 形式を `INPUT_REFUSED` として記録し、受理数に含めない。
raw 形式の数と plan は独立に計算し、typed 形式の変換拒否で raw を実行しなかった場合は `RAW_NOT_RUN` を明記する。
4 形式は同じ program の反復であり、独立標本ではない。
