# 出力とキャプチャの完了

`-w` で pcap-ng の保存先を指定します。
取得中は CPU ごとの shard に書き込み、停止後に 1 つのファイルへ合算します。
`--split-by-tag` では tag ごとのファイルに分け、`--finalize-on-del` ではファイルの出現によって tag ごとの完了を知らせます。
前回のファイルと取り違えないよう、実行ごとに新しい出力ディレクトリを使ってください。

## 停止後に確認すること

1. Ctrl-C か SIGTERM で停止を要求し、プロセスの終了を待ちます。
2. 終了コード、`capture status`、loss counters を確認します。
3. 最終的な pcap が読めるか確認します。

`complete` は、対象の drain と出力が完了したことを表します。
すべての wire packet を取得できたことや、fsync による耐久性を保証するものではありません。
損失の指標が出ているときは、終了コードだけで成功と判断しないでください。
契約の詳細は [capture lifecycle](../../capture-lifecycle.md) にあります。
停止から pcap の検査までの手順は [実行 recipe](../examples/capture-recipes.md) で試せます。

## CPU ごとの shard と合算ファイル

ringbuf は CPU ごとの shard に分かれており、user space でも shard ごとに 1 つのファイルへ書き出します。
`-w path.pcap` の出力は次のようになります。

```
path.pcap         ← 全 shard を時刻順に合算した pcap-ng (そのまま使う)
path.pcap.cpu0    ← CPU 0 が受けた packet (残る)
path.pcap.cpu1    ← CPU 1 が受けた packet (残る)
...
path.pcap.cpuN    ← N は /sys/devices/system/cpu/possible の最大 CPU 番号
```

- 停止 (Ctrl-C か `-c`) すると、全 shard を時刻順に合算して `path.pcap` に書き出します。
- 合算中は `merging N shard(s) into path.pcap ...`、完了すると `merged into path.pcap (per-CPU .cpuN kept)` と表示します。
- `.cpuN` ファイルはそのまま残るため、個別に読んだり `mergecap` で手動合算したりできます。

```bash
# 全 CPU 分を時刻順に読む
tcpdump -r path.pcap

# CPU 12 が受けた分だけ読む
tcpdump -r path.pcap.cpu12

# 自分で合算する (path.pcap と同じ内容)
mergecap -w merged.pcap path.pcap.cpu*
```

`-w` を指定しない場合、全 CPU の出力を 1 本の pcap-ng ストリームにまとめて stdout へ流します。
`sudo bpf-ninja ... | tcpdump -r -` で全 CPU 分を確認できます。
stdout は対話的な確認向けです。高 rate の環境では `-w` を使ってください。

## raw-dump と `convert`

- `--raw-dump -w session` は `session.W<offset>.cpu<N>.raw` を出力します。自動では合算しません。
- 停止後に `bpf-ninja convert -r 'session.W*.cpu*.raw' -o session.pcapng` を実行して pcap-ng に変換します。
  `-o` を省略すると stdout に出力します。
- `convert` に渡せるのは `.raw` ファイルだけです。`.cpuN` の pcap-ng shard は入力にできません。

変換とデータ救出の手順は [offline 出力処理](../examples/offline-output.md) にあります。

## tag ごとに pcap を分ける (`--split-by-tag`)

set の value (tag) を使い、一致した packet を tag ごとのファイルに振り分けます。
`-w out.pcap` に `--split-by-tag` を追加すると、tag=1 の packet は `out.1.pcap` に、tag=2 は `out.2.pcap` に出力されます。
ファイル名の拡張子の手前に tag が入ります。

以下は、GTP-U の TEID ごとに tag を分ける例です。

```bash
PIN=/sys/fs/bpf/tunnels
sudo bpf-ninja set create $PIN --key "teid:u32"
sudo bpf-ninja set add    $PIN teid=0x1000 tag=1
sudo bpf-ninja set add    $PIN teid=0x2000 tag=2

sudo bpf-ninja -i eth0 --mode xdp --set "tunnels=$PIN" \
  --split-by-tag -w out.pcap \
  'eth/ipv4/udp/gtp[teid in @tunnels]'
```

### 取得中と停止後のファイル

- 取得中は、shard と tag の組み合わせごとに `out.cpu0.1.pcap` や `out.cpu1.2.pcap` のような live ファイルが作られます。
- live ファイルは 1 秒ごとに flush されるため、取得中でも `cp`、tcpdump、Wireshark で読み取れます。
  ただし、周期的な flush は完了の合図ではありません。確定した結果が必要なときは、正常終了または finalize による合算ファイルを待ってください。
- 正常に終了すると、tag ごとに時刻順で合算して `out.1.pcap` や `out.2.pcap` を作ります。live ファイルも残ります。
- 途中で kill された場合は合算されません。残ったファイルは後から `bpf-ninja merge` でまとめられます。

```bash
sudo bpf-ninja merge --base out.pcap          # out.cpuN.<tag> を out.<tag> にまとめる
sudo bpf-ninja merge --base out.pcap --fexit  # --mode exit で取った場合
```

### 制約

- `-w` が必要です。stdout は 1 本のストリームなのでファイルを分けられません。
- `--raw-dump`、`--null-output`、gated capture (`--mode` を 2 つ指定) とは併用できません。
- set に一致しなかった packet は取得されず、どのファイルにも入りません。
- set を使わない filter では、全 packet の tag が 0 になり、`out.0.pcap` に出力されます。
- 複数の set を参照する filter では、記述順で最後に一致した set の tag が使われます。
- `--value "tag:u64"` などで tag を 8 バイトにした場合、ファイルの振り分けには下位 32 ビットが使われます。
- live ファイルは CPU と tag の組み合わせごとに 1 つ開くため、tag の種類が多いとファイルディスクリプタを多く消費します。
  tag が多いときは `ulimit -n` を引き上げてください。
  ファイルは tag の packet が初めて来たときに開くので、上限に達するとその時点でエラーになり、`ulimit -n` を上げるか tag の種類を減らすよう示します。

### 書き込みに失敗したとき

- write、flush、close のいずれかに失敗すると、非ゼロの終了コードで終了します。不完全な shard から合算ファイルを出力して成功扱いにすることはありません。
- 元の shard は、原因調査やデータ救出のために残されます。
- shard が正常で合算ファイルの作成だけに失敗した場合は、合算を再試行できます。
- `merge` は存在しない shard があっても処理を続けますが、既存の shard に破損や切り詰めがある場合はエラーにします。
- `--finalize-on-del` で合算に失敗した tag は、再試行しても完了通知や `state=finalized` にはなりません。
- ここでいう完了とは、バッファの flush と close、および合算ファイルの rename までを指します。電源断に備える fsync は含みません。

## set del で tag の出力を完成させる (`--finalize-on-del`)

1 つの常駐プロセスで複数のキャプチャジョブを扱う場合、entry の削除をその tag の終了合図にできます。
`--finalize-on-del` を付けると、ある tag の entry がすべての set から削除され、ringbuf の残りを読み終えた時点で、その tag の live ファイルを flush して閉じます。
その後、プロセスを止めずに `out.<tag>.pcap` へ合算します。
合算時は一時ファイルへ書き出してから rename するため、`out.<tag>.pcap` が現れた時点で完了と分かります。
呼び出し側は、`set del` の実行、ファイル出現の待機 (inotify や stat)、ファイルの回収という手順で進められます。

```bash
sudo bpf-ninja -i eth0 --mode xdp --set "tunnels=$PIN" \
  --split-by-tag --finalize-on-del -w out.pcap \
  'eth/ipv4/udp/gtp[teid in @tunnels]'

# 別のシェルから: entry を消してファイルを待つ
sudo bpf-ninja set del $PIN teid=0x1000
timeout 30s sh -c 'until [ -f out.1.pcap ]; do sleep 0.1; done'
# timeout したら失敗。capture の stderr とプロセスの状態を確認する
```

### 完了の判定

完了の判定は、無通信の経過時間ではなく、BPF 処理と出力処理の完了に基づきます。

1. 削除を検出した tag を、capture 専用の map で停止させます。
2. kernel の grace period を待ち、実行中の BPF 処理を完了させます。
3. 各 ring の producer 位置を記録します。
4. 全 shard がその位置まで読み切り、writer の書き込み完了を確認してから合算します。

- ほかの tag の保存が遅れていても、未処理の record を残したまま完了と判定することはありません。
- 完了までにかかる秒数は一定ではありません。失敗したときは正常完了とみなさず、stderr と終了状態を確認してください。

### 注意

- `--split-by-tag` と `--set` が必要です。tag 0 (set に一致しない packet) は対象外です。
- 停止を始めた tag は使い切りで、同じ capture 内では再利用できません。
  同じ tag の entry を後から追加し直しても record は破棄され、stderr に 1 回だけ警告が出ます。`out.<tag>.pcap` は更新されません。
- 停止した tag は 65,536 個まで保持できます。上限に達したときや同期処理に失敗したときは、エラーを報告します。
- packet が 1 つも来なかった tag でも、entry の削除後に空 (ヘッダのみ) の `out.<tag>.pcap` を作ります。完了の合図として同じように扱えます。
  ただし、entry を追加してから約 1 秒以内に削除すると、capture がその entry を認識する前に消えるため検知できません。
- live ファイルは合算後も残ります。

## entry ごとの出力上限 (`set add ... max-bytes=N`)

出力バイト数の上限は、entry (tag) ごとに set map で管理します。
`set add` に `max-bytes=N` を指定すると、その tag の出力 (全 shard の合計) が N バイトに達した時点で、その tag への書き込みだけが止まります。
ほかの tag は取得を続けます。
`max-bytes` を省略するか 0 にすると、上限なしになります。

```bash
sudo bpf-ninja set add $PIN teid=0x1000 tag=1 max-bytes=104857600
sudo bpf-ninja set add $PIN teid=0x2000 tag=2 max-bytes=10485760
sudo bpf-ninja set add $PIN teid=0x3000 tag=3      # 上限なし

sudo bpf-ninja -i eth0 --mode xdp --set "tunnels=$PIN" \
  --split-by-tag --exit-when-capped -w out.pcap \
  'eth/ipv4/udp/gtp[teid in @tunnels]'
```

### 数え方

- 計算対象は pcap-ng の packet block のバイト数です。ファイルごとの固定ヘッダは含みません。
- 上限の判定は ringbuf のバッチ単位で行うため、shard ごとに最大 1 バッチ分超過することがあります。
- record が持つ情報は tag だけなので、上限は tag 単位で機能します。同じ tag を持つ複数の entry は、1 つの上限枠を共有します。
- 同じ tag の entry 間で上限値が異なるときは、最も大きい値が使われます。上限なし (0) の entry が 1 つでもあれば、その tag は上限なしになります。
- 上限は `--split-by-tag` を指定したときだけ有効です。指定せずに上限付きの entry が存在すると、起動時に警告を出します。

### 変更と状態

- 取得中でも `set add` で上書きすれば上限を変更でき、約 1 秒で反映されます。
  ただし、一度上限に達した tag は、後から上限を引き上げても再開しません。
- 既存の entry を `set add` で更新するとき、`max-bytes=` を省略すると現在の上限が維持されます。上限を解除するには `max-bytes=0` を指定します。
- tag を変更する更新は新しいジョブとして扱われ、state と上限はその `set add` の指定値で初期化されます。
- 上限に達した tag の live ファイルは閉じられ、ファイルディスクリプタが解放されます。
  到達を検知した CPU のファイルは即座に閉じられ、ほかの CPU のファイルは次にその tag の packet を処理したときに閉じられます。
- キャプチャプロセスと `set add` は、map の value を同期なしで読み書きします (後から書いた方が優先されます)。
  競合によって state の書き込みが失われても、約 1 秒ごとの巡回処理で修復されます。
  まれに `set add` による上限の変更が競合で失われることがあります。反映されない場合はもう一度実行してください。

### `--exit-when-capped`

- 上限付きの entry がすべて上限に達した時点で、プロセスが exit 0 します。
  上限なしの entry と tag 0 は判定から除外されます。
- 終了前に通常どおり合算を行うため、呼び出し側は完成した `out.<tag>.pcap` を回収できます。
- 起動時点で上限付きの entry がすべて capped または finalized の場合、取得対象がないためすぐに exit 0 します。
- 上限付きの entry がまだないときは、警告を出して追加されるまで待機します。
  map の value が単一の整数であり上限を保持できない形式のときは、自動終了しない旨を警告します。
- `--split-by-tag` と `--set` が必要です。

### `--finalize-on-del` と組み合わせる

- 上限に達した tag は、entry の `state` が `capped` に書き換わり、kernel 側での一致判定も止まります。
- 続けて完了処理に進み、`out.<tag>.pcap` を合算してから、最後に `state=finalized` へ更新します。
- `--exit-when-capped` による終了はこの完了処理を待ちます。そのため、exit 0 した時点ですべての上限付き tag の合算ファイルと `state=finalized` がそろっています。上限到達から exit までは数秒かかります。
- entry 自体は削除されないため、`set list` で各キーのジョブの進行状況を確認できます。
- `--finalize-on-del` を付けない場合は state を書き換えず、上限を超えた record を user space で破棄するだけです。

### pinned map に残る状態

- state は pinned map に保存され、プロセスをまたいで維持されます。
- capped や finalized になった entry は次回の capture でも一致しないため、同じコマンドを再実行してもその tag の packet は取得されません。
- 同じキーを新しいジョブで再利用するには、`set add ... tag=<新しい番号>` で別の tag を割り当てます。同じ tag を再び有効にする方法はありません。
- 外部ツールで作成した pinned map の value が struct の場合、先頭が `tag` で、ほかに `state` (u8) と `max_bytes` (u64) だけを持つ構造でなければ開くときにエラーになります。value が単一の整数の map はそのまま開けます。

## プロセス全体の上限 (`--max-bytes`)

- `--max-bytes N` は、出力の合計が N バイトに達した時点でキャプチャ全体を停止します。バイト数の数え方は entry ごとの上限と同じです。
- `--split-by-tag` がなくても使えます。
- 上限に達して停止すると、`-c` と同様に shard を合算して exit 0 します。
- 0 以上の値を指定してください。
- `--raw-dump` や `--null-output` とは併用できません。

[DSL 利用ガイドに戻る](../dsl-usage.md)
