# キャプチャの問題を切り分ける

実行した commit または release、kernel、command、stderr、終了コードを最初に残す。
pcap に機密な payload がある場合は、そのまま公開 issue に添付せず、再現用 fixture を用意する。

| 症状 | 最初に確認すること | 次の資料 |
|---|---|---|
| 式の解析で失敗する | tcpdump 構文には `--cbpf`。DSL は packet の L2/L3 始まりに合う chain にする | [DSL](dsl-overview.md) |
| target が見つからない | `-i` は XDP、TC は `-p`。BTF、権限、現在のIDと関数名を確認 | [capture guide](cli/capture.md) |
| xdp mode が既存 XDP を拒否する | 既存 program の観測には entry/exit を使う。観測のために無条件 detach しない | [mode 選択](cli/capture.md) |
| 0 件で終わらない | count は一致した記録で増える。不一致は Ctrl-C で止める | [一致と不一致](examples/capture-recipes.md) |
| `capturing (...)...` が出ない | 起動失敗と setup 待ちを区別。終了 summary がない状態を0件の成功としない | [高負荷 attach の過去の調査](attach-under-load-rcu-finding.md) |
| set 更新が反映されない | 同じ pin/key を参照しているか。resize 後は再 attach。capped/finalized の state と tag 再利用も確認 | [set guide](cli/sets.md) |
| tag の完成ファイルがない | live shard と ack を区別。全 entry の削除、stderr、drain、出力エラーを確認。固定秒数で成功扱いしない | [output guide](cli/output.md) |
| convert が拒否する | raw V2 か。pcap-ng shard や raw V1 を渡していないか | [offline 出力](examples/offline-output.md) |
| 件数が少ない | filter、NIC、ring、hold、writer の計数を分ける。終了コードだけで無損失と判断しない | [lifecycle](../capture-lifecycle.md)、[tuning](tuning.md) |

kernel load や attach の問題は、実際の kernel と権限がある環境で再現を確認する。
`--dump-asm` が成功しても verifier acceptance や runtime の一致は保証しない。

## fentry/fexit の Subprog エラーを調べる

`Subprog <name> doesn't exist` が出た場合は、`sudo bpf-ninja -p "$PROG_ID" --list-funcs --json` で program ID と完全一致する BTF 関数名を確認する。
続いて `sudo bpf-ninja -p "$PROG_ID" --func "$FUNC" --list-params` で対象関数を確認する。
BTF に名前があるだけでは attach できるとは限らない。
`absent_from_loaded_func_info` は BTF FUNC が存在しても、この program の `func_info` にないことを示す。
その関数がこの program に属するなら、verifier が今回のロードで到達不能と判断して除去している。
設定で機能を無効にした場合などに起きる。
除去された関数内の処理は現在のロードでは一切実行されない。
その機能を有効にして program をロードし直すと観測できる。
global subprog の遅延検証がないカーネルでは、このような global 関数が保持される。
この仕組みは Linux v6.8 の [commit 2afae08c9dcb8ac648414277cec70c2fe6a34d9e](https://github.com/torvalds/linux/commit/2afae08c9dcb8ac648414277cec70c2fe6a34d9e) で初めてリリースされた。
今回のテストでは 6.1 で保持され、7.0 で除去されたが、保持の有無はカーネルとバックポートに依存する。
無効な static 関数は 6.1 でも除去され得る。
共有 BTF が別 program に本体のある関数を記述している場合は、その program を対象にする。
欠落だけでは、この二つの原因を区別できない。

`present` はその BTF type ID がロード済み `func_info` にあることを示し、attach 時にはカーネルの他の検査も受ける。
`missing_btf_func` は完全一致する BTF FUNC 名がないこと、`not_in_target_program` は本体のない外部宣言であることを示す。
`unknown` は権限不足や非対応などで `func_info` の所属を確認できないことを示す。
関数件数が0になる場合は、loader が `func_info` を渡していないか、呼出元の CAP_BPF が不足している可能性がある。
`unknown` の対象はカーネルで検証し、load に失敗した場合は元の verifier error とログ全体を保持する。
似た名前や別 program への付け替えは行わない。

単一 program で異なる関数名を一つ指定すると、同じ `--func` を繰り返しても、欠落時は詳しい説明付きで失敗する。
異なる複数の `--func` や複数 program の指定では、利用できない対象ごとに短い理由を警告し、`func_info` の欠落と外部宣言を分けてスキップ件数を stderr に出す。
一部の program の BTF にない関数名は従来どおり警告なしでスキップし、全 program にない関数名はエラーにする。
attach できる対象が残らない場合は、この切り分け資料へのリンクを一度示して失敗し、他の対象解決エラーと同じく stdout に JSON を出さない。
`--list-params --json` は attach できる対象の配列を維持し、各要素は `func`、`id`、`params` を持つ。
スキップした対象は stderr の警告だけに出す。
通常の capture 出力は packet data のままであり、`--json` は一覧表示だけに適用する。

`--list-funcs` は欠落した関数や外部宣言も一覧に残す。
前述のとおり、object の BTF を共有する別 program の関数も `absent_from_loaded_func_info` と表示されるため、この理由だけでは verifier による除去と判断できない。
各行は完全一致する BTF type ID で判定するため、同名の関数でもそれぞれの availability を保持する。
テキストでは短い availability の理由だけを示し、JSON では `availability` に `reason`、`btf_func_present`、既知の場合の `func_type_id`、判定できなかった場合の `detail` を含める。
availability が `unknown` の場合、テキストでは最初に得られた詳細を program ごとに一度表示する。
`--list-progs` と組み合わせた場合も同じ情報を出す。
