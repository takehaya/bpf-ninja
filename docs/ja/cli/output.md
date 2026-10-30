# 出力とキャプチャの完了

`-w` は pcap-ng の保存先です。
取得中に書き込む shard、終了後の合算ファイル、tag の finalize 完了通知を区別してください。
各実行には新しい出力ディレクトリを使い、以前のファイルを今回の完了通知と取り違えないようにします。

## 停止後に確認すること

Ctrl-C または SIGTERM で停止を要求し、プロセスの終了を待ちます。
終了コード、`capture status`、loss counters、最終 pcap の読み取りを確認してください。
`complete` は対象の drain と出力完了を表し、全 wire packet の捕捉や fsync による耐久性を保証しません。
損失指標がある場合は終了コードだけで成功と判断しないでください。
契約の詳細は [capture lifecycle](../../capture-lifecycle.md) が正本です。
[実行 recipe](../examples/capture-recipes.md)では停止と pcap 検査まで行います。

## 出力ファイルレイアウト (per-CPU sharded)

R22 以降、ringbuf は per-CPU shard (`BPF_MAP_TYPE_ARRAY_OF_MAPS` の inner は個別の `BPF_MAP_TYPE_RINGBUF`) で構成されます。user-space 側も shard ごとに 1 goroutine + 1 file で受けるので、`-w path.pcap` を指定したときの出力は次のようになります。

```
path.pcap         ← 全 shard を時刻順にマージした単一 pcap-ng (そのまま使える)
path.pcap.cpu0    ← CPU 0 が受けた packets (残置)
path.pcap.cpu1    ← CPU 1 が受けた packets (残置)
...
path.pcap.cpuN    ← (N = nproc - 1)
```

キャプチャ停止時 (Ctrl-C または `-c`) に、bpf-ninja は per-CPU shard を時刻順に k-way マージして base の `path.pcap` を単一 pcap-ng として書き出します。停止直後に `merging N shard(s) into path.pcap ...` と表示されるので、そこがマージ中です。`tcpdump -r path.pcap` でそのまま全パケットを時刻順に読めます。`.cpuN` は残るので、個別に読む・自分で mergecap することもできます。

```bash
# base をそのまま読む (全 CPU 分・時刻順)
tcpdump -r path.pcap

# CPU 12 が受けた分だけ読む
tcpdump -r path.pcap.cpu12

# 自分で mergecap したい場合 (base と同等)
mergecap -w merged.pcap path.pcap.cpu*
```

`-w` を付けない場合 (stdout ストリーミング) は、全 CPU を 1 本の pcap-ng ストリームに直列化してマージするので、`sudo bpf-ninja ... | tcpdump -r -` で全コア分が見えます。高レートでは `-w` を使ってください。stdout の直列化はインタラクティブ経路向けです。

`convert` は raw-dump の `.raw` 専用です。
`--raw-dump -w session` は `session.W<offset>.cpu<N>.raw` を生成し、自動合算しません。
停止後に `bpf-ninja convert -r 'session.W*.cpu*.raw' -o session.pcapng` を実行します。
`.cpuN` の pcap-ng shard は convert の入力ではありません。
変換と救出は [offline 出力処理](../examples/offline-output.md)を参照してください。

## tag ごとに pcap を出し分ける (`--split-by-tag`)

set の value すなわち tag を使って、マッチしたパケットを tag ごとに別々の pcap へ振り分けられます。`-w out.pcap` に `--split-by-tag` を足すと、tag=1 に当たったパケットは `out.1.pcap`、tag=2 は `out.2.pcap` へ流れます。拡張子の手前に tag を差し込む形なので、`out.pcap` が `out.1.pcap` になります。

GTP-U トンネルの TEID ごとに tag を分けて入れておく例を次に示します。

```bash
PIN=/sys/fs/bpf/tunnels
sudo bpf-ninja set create $PIN --key "teid:u32"
sudo bpf-ninja set add    $PIN teid=0x1000 tag=1
sudo bpf-ninja set add    $PIN teid=0x2000 tag=2

sudo bpf-ninja -i eth0 --mode xdp --set "tunnels=$PIN" \
  --split-by-tag -w out.pcap \
  'eth/ipv4/udp/gtp[teid in @tunnels]'
```

出し分けはロックフリーの per-CPU 書き込みをそのまま使うため、キャプチャ中はシャードごとに `out.cpu0.1.pcap` や `out.cpu1.2.pcap` のような live ファイルが生えます。これらは 1 秒ごとに flush するので、実行中でも `cp` や tcpdump や Wireshark で取り出せます。周期的な flush だけでは完了 ack になりません。確定した成果物が必要なら正常終了か finalize の合算ファイルを待ちます。

Ctrl-C などでクリーンに終了すると、per-CPU の tag ファイルを tag ごとに時刻順でまとめて `out.1.pcap` や `out.2.pcap` を作ります。per-CPU ファイルはそのまま残します。途中で kill されたときは合算が走らないので、残った per-CPU ファイルを後から `bpf-ninja merge` でまとめられます。

```bash
sudo bpf-ninja merge --base out.pcap        # out.cpuN.<tag> を out.<tag> にまとめる
sudo bpf-ninja merge --base out.pcap --fexit  # --mode exit で録った場合
```

注意点は次のとおりです。

- `-w` が必須です。stdout は 1 本のストリームなのでファイルに分割できません。`--raw-dump` や `--null-output` との併用もできません。
- set にマッチしなかったパケットは捕捉されずに落ちるので、どのファイルにも出ません。set を 1 つも使わないフィルタでは全パケットの tag が 0 になり、`out.0.pcap` に入ります。
- 複数の set を参照するフィルタでは、ソース順で最後にマッチした set の tag を採用します。
- tag の value 幅を `--value "tag:u64"` などで 8 バイトにした場合、出し分けに使うのは下位 32 ビットです。
- live ファイルは CPU ごと tag ごとに 1 本開くので、tag の種類が多いとファイルディスクリプタを消費します。種類が多い運用では `ulimit -n` を上げてください。上限に達すると起動途中でその旨のエラーを出します。

出力の write / flush / close に失敗した場合は非ゼロで終了し、不完全な shard を成功した合算結果として公開しません。`--finalize-on-del` の失敗した tag は再試行でも完了通知や `state=finalized` に変わりません。元の shard は調査・救出用に残ります。保存済み shard が正常で合算先の作成だけが失敗した場合は再試行できます。`merge` は欠けた shard は許容しますが、存在する shard の破損・切り詰めはエラーにします。完了はバッファの flush と close、合算ファイルの rename までを意味し、電源断への耐久性を保証する fsync は含みません。

### set del で tag の出力を完成させる (`--finalize-on-del`)

常駐プロセス 1 個で複数のキャプチャジョブを多重化する運用向けに、entry の削除を「この tag は終わり」の合図として使えます。`--finalize-on-del` を付けると、ある tag の entry が全 watch set から消え、かつ ringbuf の残りが掃けたと確認できた時点で、その tag の per-CPU ファイルを flush して閉じ、プロセスを止めずに `out.<tag>.pcap` へ合算します。合算は一時ファイルに書いてから rename するので、**`out.<tag>.pcap` の出現がそのまま完了の合図**です。呼び出し側の流れは `set del` → ファイルを待つ (inotify や stat) → 回収、だけになります。


完了判定には、無通信の時間ではなく、BPF 処理と出力処理の完了を使います。
削除を検出した tag を capture 専用 map で停止し、実行中の BPF 処理が完了するまで待ってから、各 ring の producer 位置を記録します。
全 shard がその位置まで読み、writer の登録と書き込みを終えたことを確認して合算します。
別 tag の保存が遅れている場合も、未処理レコードを残したまま完了通知を出しません。

停止処理を始めた tag は、同じ capture 中には再利用できません。
set entry を再追加しても再開しません。
停止した tag は最大 65,536 個保持し、上限への到達や同期処理の失敗はエラーとして報告します。

```bash
sudo bpf-ninja -i eth0 --mode xdp --set "tunnels=$PIN" \
  --split-by-tag --finalize-on-del -w out.pcap \
  'eth/ipv4/udp/gtp[teid in @tunnels]'

# 別シェルから: ジョブ終了 = entry を消してファイルを待つ
sudo bpf-ninja set del $PIN teid=0x1000
timeout 30s sh -c 'until [ -f out.1.pcap ]; do sleep 0.1; done'
# timeout は失敗。capture の stderr とプロセス状態を確認する
```

- 完了までの固定秒数は契約ではありません。kernel grace period、reader drain barrier、writer の終了、合算が完了してから ack を公開します。失敗時は正常な ack と扱わず、stderr と終了状態を確認してください。
- 完成した tag は使い切りです。同じ tag の entry を後から add し直しても record は捨てられ、stderr に 1 回警告が出ます。`out.<tag>.pcap` は変わりません。
- 1 パケットも来なかった tag も、entry の削除後に空の (ヘッダだけの) `out.<tag>.pcap` を作ります。合図としては同じに扱えます。ただし entry の存在をポーリングで観測する前 (追加から 1 秒未満) に消した場合は検知できません。
- `--split-by-tag` と `--set` が必須です。tag 0 (set 不一致) は対象になりません。per-CPU の shard ファイルは合算後もそのまま残ります。

### entry ごとの出力サイズ上限 (`set add ... max-bytes=N`)

出力バイト上限は entry (すなわち tag) 単位で set map に持たせます。`set add` に `max-bytes=N` を付けると、その tag の出力 (per-CPU shard の合計) が N に達した時点でその tag への書き込みだけが止まり、他の tag はそのまま録り続けます。上限は entry ごとに別々の値にでき、省略または 0 なら無制限です。ジョブごとに予算が違う多重化運用がフラグ 1 個では表現できなかったため、v0.22.0 の `--max-bytes-per-tag` フラグはこの方式に置き換えて廃止しました。

```bash
sudo bpf-ninja set add $PIN teid=0x1000 tag=1 max-bytes=104857600
sudo bpf-ninja set add $PIN teid=0x2000 tag=2 max-bytes=10485760
sudo bpf-ninja set add $PIN teid=0x3000 tag=3      # 上限なし

sudo bpf-ninja -i eth0 --mode xdp --set "tunnels=$PIN" \
  --split-by-tag --exit-when-capped -w out.pcap \
  'eth/ipv4/udp/gtp[teid in @tunnels]'
```

- 上限のカウント対象は pcap-ng の packet block バイトで、ファイルごとの固定ヘッダは含みません。判定は ringbuf バッチ単位なので、shard あたり最大 1 バッチぶんの超過があり得ます。
- record が運ぶのは tag だけなので、上限は実質 **tag 単位**です。同じ tag を共有する entry は 1 つの予算を共有します。entry ごとに違う上限が付いている場合は大きい方が有効で、上限なし (0) の entry が 1 つでもあればその tag は上限なしになります。
- 上限はキャプチャ中でも `set add` の上書きで変更でき、約 1 秒で反映されます。ただし一度上限に達した tag は、後から上限を引き上げても再開しません。
- `set add` で既存 entry を更新するとき、`max-bytes=` を**省略しても既存の上限は維持されます** (state と同じ扱い)。上限を外すには明示的に `max-bytes=0` を指定します。tag を変えた更新は新しいジョブへの割り当てとみなし、state も上限もこの `set add` の指定どおりに始まります。
- 上限に達した tag の live ファイルは閉じてファイルディスクリプタを解放します。到達を検知した CPU の分は即時に、他の CPU の分は次にその tag のパケットを見た時点で閉じます。
- `--exit-when-capped` を足すと、**上限を持つ全 entry** が到達した時点で自動的に exit 0 します。上限なしの entry と tag 0 (set 不一致) は判定に参加しません。通常のシャットダウンと同じく per-CPU ファイルの合算まで行うので、待っている呼び出し側はそのまま完成した `out.<tag>.pcap` を回収できます。前回実行の残りで最初から全 entry が capped/finalized の map に対して起動した場合は、録るものが無いので即座に exit 0 します。
- `--finalize-on-del` と併用すると、上限に達した tag は entry の `state` が `capped` に書き換わってカーネル側のマッチも止まり、そのまま静止 → 合算の経路に入って `out.<tag>.pcap` が生成され、最後に `state=finalized` になります。**`--exit-when-capped` の exit はこの finalize の完了を待つ**ので、プロセスが exit 0 した時点で上限付き全 tag の ack ファイルと `state=finalized` が揃っていることが保証されます (cap 到達から exit まで数秒かかります)。entry 自体は消えないので、`set list` で「どのキー (teid 等) のジョブがどこまで進んだか」を追えます。`--finalize-on-del` 無しの場合は state に触らず、従来通りユーザー空間で捨てるだけです。
- state は pinned map に**プロセスを跨いで残ります**。capped/finalized の entry は次のキャプチャでもマッチしないので、同じコマンドを再実行しても該当 tag は何も録れません。キーを新しいジョブとして使い直すには `set add ... tag=<新しい番号>` で tag を振り直します (同じ tag への復帰手段は意図的にありません)。
- キャプチャプロセスと `set add` は map の value を無同期で読み書きします (last-writer-wins)。state の書き込みが競合で失われても毎秒の巡回で自動修復されますが、`set add` の上限変更がまれに 1 回失われる可能性はあります (再実行すれば反映されます)。
- プロセス全体の上限は `--max-bytes` フラグです。こちらは `--split-by-tag` 無しでも使えて、到達すると `-c` と同じ経路でキャプチャ全体を止めて exit 0 します。逆に、entry に `max-bytes` を付けても `--split-by-tag` 無しのキャプチャでは強制されません (起動時に警告を出します)。
- 外部ツールで作った pinned map の value が struct の場合、認識できる layout (`tag[,state,max_bytes]`) 以外は open 時にエラーになります (0.22 までは value の BTF を見ていませんでした)。単一整数 value は従来どおり開けます。




## hook ごとの相関情報

[`--hook-pcapng`](hook-pcapng.md) は hook ごとの interface と実行ごとの共通 packet id を出力する。
この形式の `.cpuN` shard、通常終了時の合算、tag shard の合算は `if_description` と `epb_packetid` を保持する。
既存の entry/exit gated capture の合算では packet id を保持しない。

[DSL 利用ガイドに戻る](../dsl-usage.md)
