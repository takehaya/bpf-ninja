# キャプチャの問題を切り分ける

最初に、実行した commit または release、kernel、command、stderr、終了コードを記録する。
pcap の payload に機密情報が含まれる場合は、そのまま公開 issue に添付せず、再現用の fixture を用意する。

| 症状 | 最初に確認すること | 次の資料 |
|---|---|---|
| 式の解析に失敗する | tcpdump 構文には `--cbpf` が必要であり、libpcap 付きの build でのみ使える。DSL は packet の開始位置（L2/L3）に合う chain にする | [DSL](dsl-overview.md) |
| target が見つからない | XDP は `-i`、TC は `-p` を指定する。BTF、権限、現在の ID、関数名を確認する | [capture guide](cli/capture.md) |
| xdp mode が既存の XDP を拒否する | 既存 program の観測には entry/exit を使う。観測のために無条件で detach しない | [mode 選択](cli/capture.md) |
| 0 件のまま終わらない | count は一致した記録でのみ増える。一致しない場合は Ctrl-C で止める | [一致と不一致](examples/capture-recipes.md) |
| `capturing (...)...` が出ない | 起動失敗と setup 待ちを区別する。終了 summary がない状態を 0 件の成功とみなさない | [高負荷 attach の過去の調査](attach-under-load-rcu-finding.md) |
| set の更新が反映されない | 同じ pin/key を参照しているか確認する。resize 後は再 attach する。capped/finalized の state と tag の再利用も確認する | [set guide](cli/sets.md) |
| tag の完成ファイルがない | live shard と ack を区別する。全 entry の削除、stderr、drain、出力エラーを確認する。固定秒数の経過だけで成功とみなさない | [output guide](cli/output.md) |
| convert が拒否する | 入力が raw V3 か V2 か確認する。pcap-ng shard や raw V1 を渡していないか確認する | [offline 出力](examples/offline-output.md) |
| 件数が少ない | filter、NIC、ring、hold、writer の計数を分けて確認する。終了コードだけで無損失と判断しない | [lifecycle](../capture-lifecycle.md)、[tuning](tuning.md) |

kernel へのロードや attach の問題は、実際の kernel と必要な権限がある環境で再現する。
`--dump-asm` の成功が示すのは、コンパイルが通ったことだけである。

## fentry/fexit の Subprog エラーを調べる

`Subprog <name> doesn't exist` が出た場合は、program ID と、完全一致する BTF 関数名を確認する。

```sh
sudo bpf-ninja -p "$PROG_ID" --list-funcs --json
sudo bpf-ninja -p "$PROG_ID" --func "$FUNC" --list-params
```

BTF に名前があるだけでは、attach できるとは限らない。
`--list-funcs` は、関数ごとに availability の理由を示す。

| 理由 | 意味 |
|---|---|
| `present` | BTF type ID がロード済みの `func_info` にある。attach 時にはカーネルによる他の検査も受ける |
| `absent_from_loaded_func_info` | BTF FUNC はあるが、この program の `func_info` にはない。[次の節](#func_info-にない関数)を参照する |
| `missing_btf_func` | 完全一致する名前の BTF FUNC がない |
| `not_in_target_program` | BTF にあるのは外部宣言だけで、この target に関数の本体がない |
| `unknown` | 読み取りの拒否や非対応などにより、`func_info` に含まれるか確認できない |

関数の件数が 0 になる場合は、loader が `func_info` を渡していないか、呼び出し元の `CAP_BPF` が不足している。
`unknown` の対象もカーネルで検証する。ロードに失敗した場合は、元の verifier error とログ全体を残す。
似た名前の推測や、別の program への付け替えは行わない。

一部のカーネルでは、static または global BPF subprogram が `bpf_tail_call` と別の BPF subprogram 呼び出しを含むと、tail call の到達可能性を示す情報が失われ、ロードに成功しても attach 後の JIT code がクラッシュする。
以前の `inject-run` は hook 呼び出しの追加によってこの命令構造を作る場合があった。
現在は、元の program になかったこの構造を rewrite が作る場合だけ、attach しない native program を `BPF_PROG_TEST_RUN` で一度検査し、問題を検出した場合や結果を判定できない場合は該当する hook site を拒否する。
ほかの site は残し、一つも残らなければ通常の失敗時の方針に従う。

### func_info にない関数

理由だけでは、次の二つの原因を区別できない。

- verifier が今回のロードで到達不能と判断し、関数を除去した。これは設定で機能を無効にした場合などに起きる。
  除去された関数の処理は、今回のロードでは実行されない。
  該当する機能を有効にして program をロードし直すと観測できる。
  到達不能な static 関数は、どのカーネルでも除去され得る。
  到達不能な global 関数が除去されるのは、global subprog の遅延検証に対応するカーネルだけである。
  この仕組みは Linux 6.8 の [commit 2afae08c9dcb8ac648414277cec70c2fe6a34d9e](https://github.com/torvalds/linux/commit/2afae08c9dcb8ac648414277cec70c2fe6a34d9e) で導入された。古いカーネルに含まれるかはバックポートの有無による。
- 共有 BTF が、別の program に本体のある関数を記述している。
  この場合は、その program を対象にする。

### 複数の関数や program を指定した場合

- program と関数の組を一つだけ指定した場合、その関数が使えないときは詳しい説明を出して失敗する。同じ `--func` を繰り返した場合も同様である。
- 異なる複数の `--func` や複数の program を指定した場合は、利用できない対象をスキップする。
  対象ごとに短い理由を警告する。`func_info` にない関数と外部宣言を分けて、スキップした件数を stderr に出す。
- 一部の program の BTF にない関数名は、警告なしでスキップする。
  どの program にもない関数名はエラーにする。
- attach できる対象が残らない場合は、この資料へのリンクを一度示して失敗する。このとき stdout に JSON は出さない。
- `--list-params --json` は attach できる対象の配列を出す。各要素は `func`、`id`、`params` を持つ。
  スキップした対象は stderr の警告にだけ出る。
- `--json` は一覧表示だけに適用される。capture の出力は packet data のままである。

### --list-funcs の一覧

- `--list-funcs` は、`func_info` にない関数や外部宣言も含め、すべての BTF FUNC を一覧に出す。
- object の BTF を共有する別 program の関数も `absent_from_loaded_func_info` になる。そのため、この理由だけでは verifier が除去したとは判断できない。
- 各行は完全一致する BTF type ID で判定する。同じ名前の関数も、それぞれ固有の availability を持つ。
- テキストでは短い理由だけを示す。
  JSON では `availability` に `reason` と `btf_func_present` を含める。さらに、既知の場合は `func_type_id`、判定できなかった場合は `detail` を含める。
- availability が `unknown` の場合、テキストでは最初に得られた詳細を program ごとに一度表示する。
- `--list-progs --list-funcs` でも同じ情報を出す。
