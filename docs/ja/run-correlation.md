# hook の観測を実行に対応づける

`internal/program/run_state.go` の部品は、hook の観測を root の 1 回の実行に対応づけるためにある。
hook capture が per-CPU と ctx の locator を介して使う。
この lifecycle で共有する map の配置、ID の採番、診断を定める。
既存の gated の採番と出力形式は変わらない。

root の実行は観測対象の XDP/tc program の 1 回の呼出しを意味する。
段の参照には CPU ごとの LIFO stack `ninja_runs` と、root ctx pointer を key にする HASH `ninja_run_table` の二方式があり、同じ段の配置を使う。
段は待機中から、ID と引き継いだ出力 tag を持つ追跡中、または拒否状態へ進む。
状態の下位 2 bit より上は利用側の flag 用に予約し、残存検査では mask する。

## 配置を定義する

`ninja_runs` は CPU ごとに 272 byte の値を 1 つ持つ array だ。
先頭の 16 byte は、offset 0 に深さ、4 に poison の印を持ち、8〜15 は予約する。
offset 16 から 32 byte の段が 8 個続く。
各段の offset 0、8、16、20、24 に、診断用 owner PID/TID、packet ID、tag、状態、root ctx identity を置く。
深さ 1〜8 だけが段を選び、空、上限超過、poison のある stack では親の段を代用せず失敗する。
深さの更新、poison の印の寿命、診断 counter の置き場所は呼び出し側が決める。

## ID を採番する

別の map `ninja_run_seq` が、CPU ごとの counter と採番終了の印を持つ。
採番器は CPU 番号が 16 bit に収まることを確認してから、counter の取得と加算を atomic に行う。
通し番号は 1〜`2^48-1` とし、`cpu<<48 | sequence` を返す。
通し番号を使い切ると、その CPU では以降の採番を拒否する。
加算で得た旧値を直接使うため、入れ子の採番で他の実行の ID を借りない。
採番器は CPU 番号の読出しから map 参照まで CPU を移動しないことだけを必要とする。
LIFO を必要とするのは per-CPU stack の locator だけであり、対応する attach の範囲は利用側で確認する。

## レジスタと stack の契約を定める

段の参照は R0 に返し、R6〜R9 を保存する。
identity 検査の入力レジスタは呼び出し側で選び、R1 を作業用に使う。
map の参照は共有の `runLookupStack` の -16〜-13 byte を使う。
採番は `runCPUStack` の -208〜-201 byte を使い、ctx key は `runKeyStack` の -216〜-209 byte を予約する。
ctx locator は初期 frame に `runFrameStack` の -192〜-161 byte も使い、filter や hook prologue の前に寿命を終える。
`program.go` の配置表に定義し、tag、戻り値、引数、packet key、static XDP の slot と重ねない。
これらは一つの emitter の中だけで生存し、filter、hook prologue、identity sequence をまたがない。
filter の評価中は Kunai が同じ領域を再利用できる。
helper を呼ぶ前に生存値を保存し、見つけた段の pointer を直ちに R0 から R8 へ移す。
prologue や filter が R8 を data_end に使った後は段を引き直す。
identity の入力には作業用 R1 を使えない。
主 identity は root ctx とし、packet data/head の変更では拒否しない。
owner は診断専用で、poison の根拠にしない。
失敗先の label は理由を区別しないため、診断の方針を決める際には利用側で理由を分類する必要がある。

## 診断する

`inspectRunState` は実行が止まった状態を読み、上限超過を深さで報告し、最大 8 段を調べる。
追跡中の段には 0 以外の ID を求め、待機中と拒否された段には 0 を求め、tag 0 も有効とする。
`Probe.ObserverMisses` は attach した BPF program の recursion miss を合計し、版を判定できない kernel、6.1 未満の kernel、読み出しの失敗を error にする。
利用側は開始時、実行中、処理中の実行が終わった後、終了時の値を比較する必要があり、取りこぼしを検出しても出力は修復できない。

`runTableMapSpec` は key が 8 byte、value が 32 byte の事前割当て HASH を作る。
容量は `max(1024, 64 × possible CPU 数)` とする。
`inspectRunTable` は同じ frame 規則で HASH の残存 entry を検査し、拒否状態も数える。

対応づける hook は [inject observer](../en/inject-observers.md)（英語）を参照する。
`LoadHookCapture` が root の入口と出口、hook の記録、停止と drain、診断を一つの lifecycle として接続する。
使い方は [hook capture の説明](cli/hook-pcapng.md) にある。
