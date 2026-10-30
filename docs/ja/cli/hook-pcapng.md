# inject hook 間のパケット相関

`--hook-pcapng` を指定すると、どのサブ関数が観測したパケットかを識別し、同じ XDP/tc プログラム実行の観測をまとめられる。
`inject-run` や `inject.TransformLookup` が生成する hook など、第 1 引数が `struct xdp_md *` または `struct __sk_buff *` である関数を選ぶ。

```sh
sudo bpf-ninja -p 42 --mode entry --hook-pcapng \
  --func hook_a --func hook_b --func hook_c -w hooks.pcapng
```

program id と関数名は、ロード済みプログラムに合わせて置き換える。
Ctrl-C で停止し、終了と shard の合算を待つ。
pcapng には、解決されたターゲット順に hook ごとの interface が入る。
`--start` だけで選んだ hook は `--func` の hook の後に名前順で並ぶ。

| フィールド | 値 |
| --- | --- |
| IDB `if_name` | hook の完全な BTF 関数名 |
| IDB `if_description` | `bpf-ninja capture site_id=N`。N は 1 始まり |
| EPB interface id | 観測した hook の interface |
| EPB `epb_packetid` | 同じプログラム実行で共有する opaque な ID |

site id は、この capture 設定内で hook を識別する番号である。
注入時の `SitePC` や hook 引数の `site` / `info` とは異なる。
生成された一つの hook が複数の ELF site を受け持つ場合があるため、ソース位置への対応には injection report も保存する。
Wireshark では interface 名と packet id（`frame.interface_name`、`frame.packet_id`）を確認できる。
同じ packet id の record は同じ実行に属し、途中でパケットの内容を書き換えても ID は変わらない。
同一内容のパケットでも、別の実行には新しい ID が付く。
同じ実行内で同じ hook を繰り返し呼ぶ場合は、その実行の ID を使い続ける。

## 開始条件を評価する

root の入口が 32 byte の frame を作る。
位置引数の条件は入口で、`--start 'NAME=FILTER'` は指定 hook で評価し、最初に当たった所から追い始める。
`--start` の hook は `--func` がなくても記録する。
条件がなければ入口からすべてを追い、hook にだけ条件があれば入口では待機する。
追い始めた後は開始条件を再評価せず、同じ ID と tag で選択した hook を繰り返し記録する。
通常の引数 filter は引き続き各 hook で判定する。
受付を拒否された実行は後の hook でやり直さない。

```sh
sudo bpf-ninja -p 42 --hook-pcapng --func before_tx \
  --start 'after_nat=eth/ipv4[src==192.0.2.9]' -w nat.pcapng
```

## 追跡方式を選ぶ

既定の `--run-tracking=auto` は kernel 6.3 未満で `ctx`、6.3 以降で `percpu` を選び、方式と理由を表示する。
kernel の版が不明なら `ctx` を選び、明示的な `ctx` 指定も受け付ける。
明示的な `percpu` 指定には版の判定が必要で、判定できなければ attach 前に拒否する。
対応する基準は Linux 6.1 以降とする。
`--run-tracking=percpu` または `--run-tracking=ctx` で上書きでき、取得中は方式を変えない。
`percpu` は CPU ごとに 8 段の stack を持ち、hook と出口で root ctx を必ず比較する。
不一致なら stack が空になるまで poison を維持し、その stack での記録を抑止して counter を増やし、異なる ctx を持つ同時実行間で ID を取り違えない。
結果を不完全として表示し、次回の `--run-tracking=ctx` を案内する。
`ctx` は root ctx だけを key にした事前割当て HASH を使い、容量は `max(1024, 64 × possible CPU 数)` とする。
stale key の衝突はその実行を拒否し、出口で削除して数える。
容量不足も数え、LRU や timeout で成功を推測しない。
採番器は両方式で共有し、`cpu << 48 | sequence` を返す。
48 bit の sequence が尽きたら採番を止め、ID を再利用しない。
ctx を主 identity とするため、packet data や head の変更では拒否しない。
kernel pointer は ID として出力しない。

## tag ごとの上限と確定を扱う

tag ごとの上限は書いた EPB の byte 数で判定し、新しい追跡を止めて、進行中の実行の記録を最後まで書く。
開始条件の set と `--split-by-tag` を使う場合、上限に達した tag も、`--finalize-on-del` と同じ受付停止、grace period、reader watermark、close と merge を経て確定する。
reader callback や writer 登録の mutex を持ったまま barrier を待たない。
reader が上限到達を認識する前に受け付けた実行もあるため、ring の backlog と進行中の実行の分だけ上限を超えることがある。
開始条件が参照する set だけを対象とし、tag 0 は対象にしない。
set entry の削除による確定は `--finalize-on-del` を指定した場合だけ行う。
指定がなければ上限未到達の tag は終了まで開いたままにし、entry の再追加で追跡を再開できる。
確定した tag を set に足し直しても再開しない。
capture 全体の `-c` と `--max-bytes` は即時出力の件数と batch の規則を保つ。

## shard を合算する

取得中の `.cpuN` shard と停止後の合算 pcapng の両方に、interface description と packet id が残る。
tag ごとの出力や、`bpf-ninja merge --base hooks.pcapng` による tag shard の復旧でも保持する。
merge は hook 形式を自動検出する。
packet id は capture 内だけで有効なため、同じ capture の shard だけを合算する。
旧形式と hook 形式の混在は入力順によらず拒否する。
別 capture の hook ファイルで interface table が異なる場合は、旧 merge 処理で packet id を捨てて結合する代わりにエラーになる。
interface table が同一の別 capture はこの形式では区別できないため、混ぜて合算してはいけない。
旧 writer は EPB option を出せないため、`BPF_NINJA_FAST_PCAPNG=0` でもこの形式では fast writer を使う。
`-c` が数えるのは hook record であり、実行の数ではないため、同じ ID の record 群の途中で停止する場合がある。
byte limit には EPB ごとの packet id option 領域 16 byte を含む。

## 対応範囲

XDP または SchedCLS program 一つ、entry mode、異なるサブ関数 1〜255 個に対応する。
すべての hook の引数 0 が root ctx と同じ型であることを attach 前に確認する。
static XDP の pointer 引数には、必要なら fault-handled context read を使う。
root 自体、複数 program、EXT、PREEMPT_RT、gated capture、`--arg-echo`、`--dump-asm`、`--raw-dump` は拒否する。
RT と判定するのは sysfs が `1`、`uname -v` に `PREEMPT_RT` がある、または config が `CONFIG_PREEMPT_RT=y` の場合だけだ。
file の不在だけでは RT と扱わない。
`--hook-pcapng` を指定しない場合、既存の単一 hook と複数ターゲットの出力形式は変わらない。

サブ関数内も含め、tail call を持つプログラムは observer を付ける前に拒否する。
tail call の飛び先では entry trampoline を迂回し得るため、tail call chain をまたぐ相関には対応しない。
この制約により、該当 kernel の複数 attach に関する tail call trampoline の不具合も避ける。
選択した親自体が tail call の飛び先として呼ばれる場合も、実行開始の observer を迂回して相関レコードを出せない場合がある。
親は通常の entry から実行する必要がある。
取得中に別の observer や freplace 対象を追加、削除、置換すると、trampoline の書き換えで境界の observer が実行されない場合があるため、この操作は対応範囲外とする。
これにより run stack の深さがずれた場合は、capture を停止して再開する必要がある。
stack の自動再同期は行わない。
6.3 未満の通常の並行 `BPF_PROG_TEST_RUN` は同じ CPU 上で交錯し得るため、`ctx` を既定にする。
通常 test-run の BH 禁止は [upstream v6.3](https://github.com/torvalds/linux/blob/v6.3/net/bpf/test_run.c#L406) から確認できる。
recursion miss だけでは交錯を検出できないため、ctx 不一致と key 衝突を別に数える。
observer miss は開始時、定期確認、tag barrier 後、終了時に読み、停止後の残存状態も検査する。
いずれも loss を検出する診断であり、出力済み記録の修復は約束しない。

`XDP_REDIRECT` は選択したプログラムの実行を通常どおり終了する。
その後の CPUMAP / DEVMAP、別 interface、別プログラム、再実行には同じ ID を引き継がない。
物理パケットをプログラム間やホスト間で追跡する ID ではない。
VM test は `BPF_PROG_TEST_RUN` の REDIRECT 戻り値を検査し、実際の redirect 配送は検査しない。

hook record がない理由には、分岐による迂回、フィルターの不一致、相関処理の上限、export の欠落がある。
最後に見えた hook を処理の到達点と解釈する前に、capture status と loss counter を確認する。

## 欠落を診断する

欠落があっても capture と tag の確定を続け、停止後に shard を merge してから summary を `capture status=incomplete` とし、終了 status を非 0 にする。
診断の読出し失敗も不完全として保持する。
方式は途中で切り替えず、percpu の不一致数と次回の ctx 指定の hint を表示する。
開始時には、例えば `run tracking: ctx (kernel before 6.3 allows normal test-run interleaving)` と表示する。
counter は event 数であり、一つの実行について複数の counter が増えるため、合計を欠落した実行数とは扱わない。
次の欠落 counter が非 0 なら不完全とし、`run_pre_tracking` だけは除く。

| counter | 意味 |
| --- | --- |
| `run_mismatch` | per-CPU の観測が別の ctx を見つけた回数を表す。 |
| `run_poisoned` | per-CPU stack に poison を新しく設定した回数を表す。 |
| `run_blocked_hook` | stale key または poison による拒否 frame が hook を抑止した回数を表す。 |
| `run_collision` | 入口で既存 ctx key と衝突した回数を表す。 |
| `run_insert_failed` | ctx 登録失敗を表し、容量不足、bucket lock、衝突後の参照失敗も含む。 |
| `run_untracked_hook` | 有効な frame のない hook の回数を表し、不一致を見つけた hook も含む。 |
| `run_exit_without_entry` | 有効な frame のない出口を表し、poison や上限超過の場合も含む。 |
| `run_stale_reclaimed` | stale な拒否 ctx entry を出口で回収した回数を表す。 |
| `run_overflow` | per-CPU の入口が 8 段を超えた回数を表す。 |
| `run_sequence_exhausted` | 開始時に ID を採番できなかった回数を表す。 |
| `run_lookup_failed` | 必要な frame の参照または ctx entry の削除に失敗した回数を表す。 |
| `run_read_failed` | 開始条件または static XDP prologue の読出し失敗を表す。 |
| `run_pre_tracking` | 追跡の有効化前に観測した実行数を表し、欠落とは扱わない。 |
| `run_residual` | Quiesce 後の残存を表し、追跡中、拒否、無効の内訳も表示する。 |
| `observer_misses` | 起動時の基準値以降の全 observer の recursion miss を表す。 |
| `root_entry_misses / root_exit_misses` | root 入口と出口の recursion miss を表し、observer_misses の内数である。 |

起動時は受付を止めたまま observer を attach し、新しい入口には拒否 frame を作る。
RCU grace period を待って observer miss の基準値を取得してから追跡を有効化する。
`run_pre_tracking` は、この間に拒否した入口と、追跡開始前に frame なしで観測した出口を数える。
入口も出口も observer が実行されなかった実行は個別には数えられない。
追跡開始後まで実行が続いても起動中の frame は拒否状態を保ち、その hook は記録しない。

ctx 比較で防ぐのは、異なる ctx を持つ同時実行間の取り違えである。
A の root 出口が欠落し、その ctx address を再利用した B の root 入口も欠落すると、どちらの方式でも B の hook が A の stale な ID と tag を使う場合がある。
root 入口と出口の recursion miss は別々に数え、summary には後続の ID と tag の対応が信頼できない旨を表示する。
hook だけの miss は記録を失わせ、root 境界の miss は対応づけにも影響する。
trampoline の同時書換えによる欠落は recursion miss に含まれないため、取得中に他の observer や freplace 対象を変更する操作は対応範囲外のままとする。
入口の observer だけが書く世代番号では、その入口自体が欠落した新しい呼出しを検出できない。

## 検証する

`go test ./internal/output ./internal/capture ./cmd/bpf-ninja` で、BPF をロードせずに interface の振り分け、description、ID、破損 shard、byte 計数、CLI 制約を検査する。
既存形式の byte 比較には、hook 対応前の writer で生成した entry、exit、gated の fixture を使う。
`TestBpfHookPcapngStaticPointer` は pointer filter の一致と不一致、global と static サブ関数間の run ID の共有、同一入力を再実行した場合の ID の区別を検査する。
`internal/program` の他の privileged test `TestBpfHookPcapng*` は、3 map の C fixture を `inject.TransformLookup` で変換し、`BPF_PROG_TEST_RUN` を実行して API と CLI の合算 pcapng を読む。
2 CPU、同一入力の反復、hook 間の packet 書き換え、3 番目の hook の迂回、REDIRECT 戻り値、未対応ターゲットの拒否を検査する。
`TestBpfRun*` は両方式、開始条件と tag 継承、XDP/tc の head 調整、stale entry、容量不足、marker 付きの交錯、進行中の停止を検査する。
権限不要のテストで生成命令を marshal し、byte 列を固定する。
実際の clone_redirect の入れ子と性能比較は延期する。
通常の privileged suite は fixture と CLI を build できる。
VM へ build 済みの成果物を渡す場合は、`BPF_NINJA_HOOK_TEST_OBJECT`、`BPF_NINJA_HOOK_TEST_BINARY`、`BPF_NINJA_HOOK_TEST_DIR` を指定し、一時 test directory の外へ成果物を保存できる。
network attach や link の変更は不要である。

run-tracking 用の object は `BPF_NINJA_RUN_TEST_OBJECT` に指定できる。
通常の交錯テストは誤対応 0 を検査し、6.1 の不一致数は 0 以上を許す。
`preempt=full` の再現 wrapper だけが `BPF_NINJA_REQUIRE_PERCPU_MISMATCH=1` を指定し、6.3 未満の percpu の不一致を必須にする。

命令 golden の更新は `UPDATE_RUN_GOLDEN=1 go test ./internal/program -run '^TestRunCaptureMarshal$' -count=1` で行い、`.hex` の byte 列と `.asm` の命令一覧の両方を確認する。
各 stage は単独でも実行できる。

診断値の読み取りに失敗した場合は、最初のエラーを終了時の要約に残す。
欠落を検出した後に tag を完了した場合は、完了行に `run tracking incomplete` を付ける。
ctx の挿入失敗は起動中でも欠落に数え、正常に拒否した起動中の frame だけを pre-tracking に数える。
