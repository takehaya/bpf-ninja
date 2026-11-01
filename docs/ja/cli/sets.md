# Set map の作成と更新

set は bpffs に pin された BTF 付きの hash map です。
map のキーが照合する値そのもので、value は小さな tag です。
キャプチャ中に entry を追加や削除でき、re-attach は不要です。

- Linux で BPF map を操作する権限と、書き込み可能な bpffs が必要です。
- 新しい pin 名を使い、既存の map を上書きしないでください。例にある pin 名を使う場合も、共有ホストでは事前に存在しないか確認してください。
- 片付けるときは `set list` と `set schema` の結果を保存してから、自分で作成した pin だけを `rm -- "$PIN"` で削除します。
  `set del` は entry を削除するコマンドであり、map の unpin ではありません。
- 専用の namespace の利用や pin の片付けまでを含む手順は [実行中の更新 recipe](../examples/runtime-sets.md) にあります。

## なぜ set を使うか

`--arg-filter "imsi=X"` は値を命令列に埋め込むため、値を変えるたびに re-attach が必要です。
set を参照すると、IMSI の一覧などを packet ごとに O(1) の lookup で照合できます。
entry の追加と削除は、実行中の capture にすぐ反映されます。

- 複合キーの各フィールドは AND 条件として、1 回の lookup で照合します。
- OR 条件は entry を複数登録して表します。
- 部分キーでは照合できません。キーのフィールドはすべて指定します。

## 基本の流れ

```bash
# 1) set を作る (BTF 付きの hash map を pin する)
sudo bpf-ninja set create /sys/fs/bpf/flows --key "imsi:u64,teid:u32" --max-entries 1024

# 2) entry を入れる (フィールド名で指定する。幅とパディングはツールが合わせる)
sudo bpf-ninja set add /sys/fs/bpf/flows imsi=999990000000001 teid=0x3039 tag=1

# 3) capture する (--set で名前を付け、@NAME で参照する)
sudo bpf-ninja -p 1661 --func upf_capture_point_ul \
  --set "flows=/sys/fs/bpf/flows" --arg-filter "@flows" -w out.pcap

# 4) capture 中でも出し入れできる
sudo bpf-ninja set add /sys/fs/bpf/flows imsi=999990000000777 teid=100
sudo bpf-ninja set del /sys/fs/bpf/flows imsi=999990000000001 teid=0x3039
sudo bpf-ninja set list /sys/fs/bpf/flows
sudo bpf-ninja set schema /sys/fs/bpf/flows

# 5) 容量が足りなくなったら resize する (entry と BTF のスキーマは保つ)
sudo bpf-ninja set resize /sys/fs/bpf/flows --max-entries 4096
```

## サブコマンド

| コマンド | 働き |
|---|---|
| `set create PIN --key SCHEMA [--value SCHEMA] [--max-entries N]` | BTF 付きの hash map を作成して pin します。`--max-entries` の既定値は 1024 です (1 から 2^32-1) |
| `set add PIN field=value ... [tag=N] [max-bytes=N]` | entry を追加または更新します |
| `set del PIN field=value ...` | entry を削除します |
| `set list PIN` | すべての entry を `field=value ... tag=N` の形式で表示します |
| `set schema PIN` | map の BTF から読み取ったキーのレイアウトを表示します |
| `set resize PIN --max-entries N` | 容量を変更します |

## キー

- `--key` には `name:type` をカンマ区切りで指定します (例: `"imsi:u64,teid:u32"`)。
- 型は `u8`、`u16`、`u32`、`u64`、`ipv6` (16 バイトのアドレスや SRv6 SID) です。
- 数値のフィールドはそれぞれの幅に、`ipv6` は 8 バイト境界に揃えて配置されます。キー全体は最大 64 バイトです。
- 24 bit の VNI は `u32` のフィールドに、MAC は `u64` のフィールドに入れます。
- `tag`、`max-bytes`、`max_bytes`、`state` はキーのフィールド名に使えません。
- 値は 10 進数でも `0x` 付きの 16 進数でも指定できます。`set list` は 10 進数で表示します。
- `u64` のフィールドは MAC の表記 (`aa:bb:cc:dd:ee:ff`) も受け付けます。`0xaabbccddeeff` と指定しても同じキーになります。
- `ipv6` のフィールドは IPv6 の表記で指定し、`set list` も IPv6 の表記で表示します。
- フィールドの幅に収まらない値、不足しているフィールド、未定義のフィールドはエラーになります。

## value と tag

value の既定の型は `tag:u32,state:u8,max_bytes:u64` の struct です。

| フィールド | 意味 |
|---|---|
| `tag` | entry ごとの小さな番号です。`tag=N` を省略すると 1 (存在を示す値) が入ります |
| `state` | `active`、`capped`、`finalized` のいずれかです。上限への到達や finalize の完了時に capture プロセスが書き換えます |
| `max_bytes` | entry ごとの出力バイト数の上限です。`set add ... max-bytes=N` で指定します。省略または 0 で上限なしになります |

- 同じキーに `set add` を実行すると上書きされます。
- 同じ tag で更新する場合、`state` と、指定しなかった `max-bytes` の値は維持されます。
- `max-bytes` の使い方は [entry ごとの出力上限](output.md#entry-ごとの出力上限-set-add--max-bytesn) にあります。
- `--value "tag:u16"` のように、1、2、4、8 バイトの単一の整数も使えます。
  その map では上限と state を使えないため、`max-bytes=` を指定するとエラーになります。
- tag に指定できるのはフィールドの幅に収まる数値だけです。`ipv6` はキー専用の型です。
- tag 0 は set に一致しない traffic の番号です。そのため、tag 0 の entry に上限は設定できません。
- 既定の型の map では、`set list` は `tag=N state=S max-bytes=M` を表示し、上限なしの場合は `max-bytes=unlimited` と表示します。

## 関数の引数と照合する (`--set` と `--arg-filter @NAME`)

`--set "NAME=/sys/fs/bpf/path"` で set に名前を付け、`--arg-filter "@NAME"` で参照します。
キーは fentry の引数から作ります。

- 既定では、キーの BTF フィールド名と同じ名前の引数を対応させます。
- 名前が異なる場合は `--set "flows=/sys/fs/bpf/flows,key(imsi=arg:subscriber,teid=arg:teid)"` のように明示します。
  `()` は bash のメタ文字のため、引用符が必要です。
- `arg:` には `key->dport` のようなメンバー参照の式も書けます。
- `@NAME` は、ほかの `--arg-filter` と AND 条件で組み合わさります。`--set` は複数定義できます。
- 引数がキーのフィールドより広い場合、値が切り詰められるためエラーになります (u64 の引数を u32 のフィールドに入れる場合など)。
- `--arg-filter @NAME` は `--mode entry` と `--mode exit` でのみ使えます。`--arg-echo` とは併用できません。

## packet のフィールドと照合する (DSL の `layer[field in @NAME]`)

GTP TEID や SRv6 SID のように、照合したい値が引数ではなく packet の中にあるときは、DSL の bracket predicate を使います。
packet のフィールドがそのままキーになります。
`--mode entry`、`--mode exit`、`--mode xdp` のどれでも使えます。

```bash
# set は同じ (キー = 照合する値)
sudo bpf-ninja set create /sys/fs/bpf/teids --key "teid:u32"
sudo bpf-ninja set add    /sys/fs/bpf/teids teid=0x3039

# packet の gtp.teid を set と照合する
sudo bpf-ninja -p 1661 --set "teids=/sys/fs/bpf/teids" \
  'eth/ipv4/udp/gtp[teid in @teids]' -w out.pcap

# 複合キーは 1 つの角括弧にカンマで並べる (entry の中は AND)
sudo bpf-ninja set create /sys/fs/bpf/flows --key "teid:u32,msg_type:u8"
sudo bpf-ninja -i eth0 --mode xdp --set "flows=/sys/fs/bpf/flows" \
  'eth/ipv4/udp/gtp[teid in @flows, msg_type in @flows]'

# 128 bit の SRv6 SID (IPv6 の宛先) を照合する。キーの型は ipv6
sudo bpf-ninja set create /sys/fs/bpf/sids --key "dst:ipv6"
sudo bpf-ninja set add    /sys/fs/bpf/sids dst=fc00::1
sudo bpf-ninja -i eth0 --mode xdp --set "sids=/sys/fs/bpf/sids" \
  'eth/ipv6[dst in @sids]'

# SRH の segment list の N 番目の SID を照合する。segments[0] は最終の宛先
sudo bpf-ninja -i eth0 --mode xdp --set "sids=/sys/fs/bpf/sids" \
  'eth/ipv6/srv6[segments[0].addr in @sids]'

# 送信元 MAC を照合する。48 bit の MAC は u64 のキーで、値は MAC の表記で書ける
sudo bpf-ninja set create /sys/fs/bpf/macs --key "src:u64"
sudo bpf-ninja set add    /sys/fs/bpf/macs src=aa:bb:cc:dd:ee:ff
sudo bpf-ninja -i eth0 --mode xdp --set "macs=/sys/fs/bpf/macs" \
  'eth[src in @macs]/ipv4/tcp'
```

### 名前と型

- DSL のフィールド名が、そのまま set のキーのフィールド名になります。`gtp[teid in @teids]` はキーの `teid` を参照します。
- フィールドが 1 つだけのキーでは、名前はラベルにすぎません。`ipv6[dst in @sids]` は `sid:ipv6` のキーにも当てられます。
- 数値のフィールドは、packet では network order、`set add` では host order です。変換はツールが行うため、通常の数値で `set add` を実行してください。
- `ipv6` のフィールドはアドレスのバイト列そのものです。packet と `set add fc00::1` の値を同じ network order のまま照合します。
- キーの型は、packet のフィールドが収まる最小の読み出し幅に合わせます。
  24 bit の `vxlan.vni` と `geneve.vni` は `u32`、48 bit の `eth.src` と `eth.dst` は `u64` です。
  値はフィールドの数値そのものなので、VNI は `set add vni=100`、MAC は `set add src=aa:bb:cc:dd:ee:ff` と指定します。
- packet のフィールドと set のフィールドで幅が異なるとエラーになります。

### キーの幅

- packet から作るキーは、合計 16 バイトまでです。
  TEID (4)、IMSI (8)、TEID と IMSI (12)、SRv6 SID (16) はいずれも収まります。
- 数値のフィールドは 1 つにつき 8 バイトまで、`ipv6` のフィールドは 16 バイトです。16 バイトのキーはそれだけで上限を使い切ります。
- bit slice をキーにできるのは、64 bit 以下の slice と、`ipv6.dst[0:128]` のように 128 bit のフィールド全体を指す slice です。65 bit から 127 bit の slice は型エラーになります。
- byte 境界から始まらない slice では、ヘッダ上の bit 範囲が収まる読み出し幅がキーの幅になります。
  `ipv6[traffic_class[0:4] in @tc]` は `u8`、DSCP の `ipv6[traffic_class[0:6] in @dscp]` は `u16` のキーになります。

### 書ける場所

- 定数の添字を持つ aux フィールドを使えます。`srv6[segments[0].addr in @sids]` は segment list の 0 番目を参照します。
- `ipv6[exts[1].next_header in @nh]` のように entry の長さが変わる stack でも、定数の添字であれば手前の entry をたどって位置を求めます。該当する entry がない packet は一致しません。
- `tcp[mss.value in @NAME]` のように、parser が走査して位置を決める option のフィールドもキーにできます。該当する option がない packet は一致しません。
- bracket に指定できるのは定数の添字 `[N]` だけです。`segments[srv6.last_entry]` のような動的な添字や、添字なしの `any()` と `all()` には `where` 句を使います。
- `@NAME` は、ほかの bracket の条件やレイヤの条件と AND 条件で組み合わさります。
- `in @NAME` は bracket predicate の中でのみ使えます。`where` 句では使えません。
- `in @NAME` は、quantifier のない必須のレイヤにのみ指定できます。
  `vlan[...]?` のような optional や繰り返しのレイヤ、`(vlan[...]|qinq)` のような alternation の分岐はエラーになります。そのレイヤがなくても filter が成立し、キーの値が定まらない場合があるためです。
- 同じ set の同一キーフィールドを 2 回指定するとエラーになります。set は 1 つのキーで 1 回だけ lookup するためです。

### 複数の値と複数の set

OR 条件を表すには、同じ set に複数の entry を追加します。
各 entry は独立した 1 つのキーであり、どれかに該当すれば一致します。

```bash
# (imsi=999990000000001 かつ teid=0x1000) または
# (imsi=999990000000777 かつ teid=0x2000)
sudo bpf-ninja set add $PIN imsi=999990000000001 teid=0x1000 tag=1
sudo bpf-ninja set add $PIN imsi=999990000000777 teid=0x2000 tag=1
```

複数の set を 1 つの filter で組み合わせることもできます。
`--set` を複数定義し、DSL では `layer[a in @s1, b in @s2]` のようにカンマで並べます。
角括弧内のカンマは AND 条件のため、両方がそれぞれの set に一致したときだけ通過します。

```bash
sudo bpf-ninja set create /sys/fs/bpf/src --key "sport:u16"
sudo bpf-ninja set create /sys/fs/bpf/dst --key "dport:u16"
sudo bpf-ninja set add /sys/fs/bpf/src sport=1111
sudo bpf-ninja set add /sys/fs/bpf/dst dport=443
sudo bpf-ninja -i eth0 --mode xdp \
  --set "src=/sys/fs/bpf/src" --set "dst=/sys/fs/bpf/dst" \
  'eth/ipv4/tcp[sport in @src, dport in @dst]'
```

## 外部で作った map を使う

- hash 型で、キーに BTF があれば参照できます。
  キーは整数、整数のみの struct (各フィールドは 1、2、4、8 バイトまたは `__u8[16]`)、またはバイト配列です。キー全体は最大 64 バイトです。
  bitfield と、境界に揃っていないフィールドは使えません。
- BTF のない map は `set create` で作り直してください。
- value は単一の整数か、`tag` で始まる struct です。struct に追加できるのは `state` (u8) と `max_bytes` (u64) だけです。
- bpftool などで直接書き込むときは、パディングを 0 で埋めてください。hash はキーの全バイトから計算されるため、パディングが 0 でないと一致しません。
  `bpf-ninja set add` はこの処理を自動で行います。

## resize

BPF の map は作成後に容量を変更できません。
`set resize` は、同じスキーマの新しい map を作成し、entry をすべてコピーしてから pin を差し替えます。

1. map を更新する writer と capture を停止します。コピーから差し替えまでの間に古い map へ追加した entry は失われます。
2. `set resize PIN --max-entries N` を実行します。
3. capture を attach し直します。実行中の capture は attach 時の古い map を使い続けるため、新しい容量は次の attach から有効になります。

- 現在の entry 数より少ない容量には変更できません。
- 一時的な pin `PIN_resize_tmp` が残っているとエラーになります。前回の resize が異常終了したか、同時に実行していないかを確認してから削除してください。
- 同じ容量を指定した場合は、何もせずに終了します。

## 手元で動きを確かめる

`set` のサブコマンドは、capture の target がなくても動作します。
map を作成して entry を追加・削除し、`set list` と `set schema` で内容を確認すると、set の動作を手元で確かめられます。
root 権限と bpffs の mount が必要です。

```bash
PIN=/sys/fs/bpf/bpfninja_handtest

# 1) BTF 付きの hash map を作って pin する。この例では value を u32 の tag だけにする
sudo bpf-ninja set create $PIN --key "imsi:u64,teid:u32" --value "tag:u32" --max-entries 1024

# 2) フィールド名で entry を入れる。tag が value になる
sudo bpf-ninja set add $PIN imsi=999990000000001 teid=0x3039 tag=1
sudo bpf-ninja set add $PIN imsi=999990000000777 teid=100    tag=2

# 3) 読み戻す
sudo bpf-ninja set list   $PIN
sudo bpf-ninja set schema $PIN

# 4) 上書きする
sudo bpf-ninja set add  $PIN imsi=999990000000777 teid=100 tag=9
sudo bpf-ninja set list $PIN | grep 999990000000777              # tag=9 になる

# 5) 消す
sudo bpf-ninja set del  $PIN imsi=999990000000001 teid=0x3039
sudo bpf-ninja set list $PIN
```

手順 3 の出力は次のようになります。
並び順は hash map を走査した順になるため、実行や kernel によって変わります。

```text
$ sudo bpf-ninja set list $PIN
imsi=999990000000777 teid=100 tag=2
imsi=999990000000001 teid=12345 tag=1

$ sudo bpf-ninja set schema $PIN
hash map: key 16 B, value 4 B, max_entries 1024
  imsi                 u64   offset 0
  teid                 u32   offset 8
note: entries must zero all padding bytes (hash covers the full key)
```

- `teid=0x3039` のように 16 進数で追加しても、`set list` では 10 進数の 12345 と表示されます。
- `set list` は map 内の entry の一覧を表示します。どの entry に一致したかは示しません。

### bpftool で map を見る

set の map は BTF を持つため、`bpftool map dump` はフィールド名付きで表示します。
`set list` の結果と突き合わせて確認できます。

```bash
sudo bpftool map dump pinned $PIN
```

```text
[{
        "key": {
            "imsi": 999990000000777,
            "teid": 100
        },
        "value": 2
    }, ...
```

上の形式は libbpf を使う bpftool の既定の出力です。
古い bpftool では、フィールドを並べただけのテキストになることがあります。

### 16 バイトの SID キー

```bash
sudo bpf-ninja set create /sys/fs/bpf/sids --key "dst:ipv6"
sudo bpf-ninja set add    /sys/fs/bpf/sids dst=fc00::1
sudo bpf-ninja set list   /sys/fs/bpf/sids     # dst=fc00::1 tag=1 state=active max-bytes=unlimited
sudo bpf-ninja set schema /sys/fs/bpf/sids     # dst  ipv6  offset 0
```

[DSL 利用ガイドに戻る](../dsl-usage.md)
