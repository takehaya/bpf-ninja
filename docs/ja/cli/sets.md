# Set map の作成と更新

set は bpffs に pin した BTF 付き hash map です。
Linux の BPF map 操作権限と、書込み可能な bpffs が必要です。
新しい pin 名を用意し、既存 map を上書きしないでください。
下の説明用 pin 名は、共有ホストで使う前に存在確認が必要です。

`set add/del` は実行中の capture に反映されます。
`set resize` を実行する前に、map を更新する writer と capture を停止してください。
容量変更後に再 attach します。
既存 capture は古い map の参照を保持するため、新容量は pin の置換だけでは適用されません。

停止後に `set list` と `set schema` を保存してから、自分で作成した pin だけを `rm -- "$PIN"` で外します。
`set del` は entry の削除であり、map の unpin ではありません。
[実行中の更新 recipe](../examples/runtime-sets.md)は専用 namespace と pin の cleanup を含みます。

## 集合マッチ (`--set` / `--arg-filter @NAME`)

`--arg-filter "imsi=X"` は値を命令列に焼き込むため、値を変えるたびに re-attach が要ります。pinned BPF hash map を集合として参照すると、IMSI 群などの購読者リストをパケットごとの O(1) lookup で照合でき、エントリの追加・削除はキャプチャ中でも即時反映されます。この場合は re-attach が不要です。

map のキーが照合する値そのもので、スカラまたは struct 複合キーになります。value は小さな tag です。複合キーのフィールド間は AND で 1 lookup し、OR はエントリを複数入れて表現します。すなわち集合は直和です。部分キーは不可です。

```bash
# 1) 集合を作る (BTF 付き hash map を pin)。--max-entries は省略可で既定 1024、
#    1〜2^32-1 で指定できる
sudo bpf-ninja set create /sys/fs/bpf/flows --key "imsi:u64,teid:u32" --max-entries 1024

# 2) エントリ投入 (フィールド名で指定。幅・パディングはツールが保証)
sudo bpf-ninja set add /sys/fs/bpf/flows imsi=999990000000001 teid=0x3039 tag=1

# 3) キャプチャ (--set で名前を付け、@NAME で参照)
sudo bpf-ninja -p 1661 --func upf_capture_point_ul \
  --set "flows=/sys/fs/bpf/flows" --arg-filter "@flows" -w out.pcap

# 4) キャプチャ中でも出し入れできる
sudo bpf-ninja set add /sys/fs/bpf/flows imsi=999990000000777 teid=100
sudo bpf-ninja set del /sys/fs/bpf/flows imsi=999990000000001 teid=0x3039
sudo bpf-ninja set list /sys/fs/bpf/flows
sudo bpf-ninja set schema /sys/fs/bpf/flows

# 5) 容量が足りなくなったら resize (エントリと BTF スキーマは保たれる)
sudo bpf-ninja set resize /sys/fs/bpf/flows --max-entries 4096
```

`set resize` は BPF map の容量を後から変えられない制約を、同じスキーマの新 map を作ってエントリを全コピーし pin を差し替えることで回避します。実行中のキャプチャは attach 時の旧 map を掴んだままなので、新しい容量は次回 attach から有効です。コピーと差し替えの間に旧 map へ入れたエントリは失われるため、resize は `set add` を止めてから行ってください。

- キーの対応付けは、既定ではキーの BTF フィールド名と fentry 引数名を同名で一致させます。名前が違うときは `--set "flows=/sys/fs/bpf/flows,key(imsi=arg:subscriber,teid=arg:teid)"` と明示します。`()` は bash のメタ文字なのでクオートが必須です。
- `@NAME` は他の `--arg-filter` と AND で合成されます。`--set` は複数定義できます。
- 引数がキーのフィールドより広い場合、たとえば u64 引数を u32 フィールドに入れる場合は切り詰めになるためエラーです。
- 外部で作った pinned map も、hash 型で BTF キー (整数 or 整数のみの struct、各 1/2/4/8B、キー全体 64B 以下) を持っていれば参照できます。BTF 無しの map は `set create` で作り直してください。
- bpftool などで外部から直接書く場合は、パディングのゼロ埋めが必須です。hash はキー全バイトをハッシュするため、パディングが非ゼロだと永遠に一致しません。`bpf-ninja set add` はこれを自動で保証します。
- スキーマとしてキー幅やオフセットは `set schema` で確認できます。`bpftool map dump pinned <path>` も、合成 BTF のおかげでフィールド名付きで整形表示されます。

### DSL `layer[field in @NAME]` でパケットフィールドを照合する

`--arg-filter @NAME` はキーを fentry 引数から作ります。GTP TEID や SRv6 SID のように、照合したい値が引数ではなくパケット内にあり dispatcher が渡してくれない場合は、DSL の bracket predicate でパケットフィールドをそのままキーにできます。

```bash
# 集合は同じ (キー = 照合する値)
sudo bpf-ninja set create /sys/fs/bpf/teids --key "teid:u32"
sudo bpf-ninja set add    /sys/fs/bpf/teids teid=0x3039

# DSL でパケットの gtp.teid を集合照合 (fentry でも --mode xdp でも動く)
sudo bpf-ninja -p 1661 --set "teids=/sys/fs/bpf/teids" \
  'eth/ipv4/udp/gtp[teid in @teids]' -w out.pcap

# 複合キーは 1 つの角括弧にカンマ併記 (エントリ内は AND)
sudo bpf-ninja set create /sys/fs/bpf/flows --key "teid:u32,msg_type:u8"
sudo bpf-ninja -i eth0 --mode xdp --set "flows=/sys/fs/bpf/flows" \
  'eth/ipv4/udp/gtp[teid in @flows, msg_type in @flows]'

# 128bit の SRv6 SID (= IPv6 宛先) を照合する。キー型は ipv6、値は IPv6 リテラル
sudo bpf-ninja set create /sys/fs/bpf/sids --key "dst:ipv6"
sudo bpf-ninja set add    /sys/fs/bpf/sids dst=fc00::1
sudo bpf-ninja -i eth0 --mode xdp --set "sids=/sys/fs/bpf/sids" \
  'eth/ipv6[dst in @sids]'

# SRH の segment list の N 番目の SID を照合する。segments[0] は最終宛先
sudo bpf-ninja -i eth0 --mode xdp --set "sids=/sys/fs/bpf/sids" \
  'eth/ipv6/srv6[segments[0].addr in @sids]'

# 送信元 MAC を照合する。48 bit の MAC は u64 のキーで、値は MAC の表記で書ける
sudo bpf-ninja set create /sys/fs/bpf/macs --key "src:u64"
sudo bpf-ninja set add    /sys/fs/bpf/macs src=aa:bb:cc:dd:ee:ff
sudo bpf-ninja -i eth0 --mode xdp --set "macs=/sys/fs/bpf/macs" \
  'eth[src in @macs]/ipv4/tcp'
```

- 同名一致します。DSL のフィールド名がそのまま集合キーのフィールド名になり、`gtp[teid in @teids]` は集合キー `teid` を引きます。ただしスカラ集合、つまりフィールドが 1 個のキーは名前がラベルにすぎないので、`ipv6[dst in @sids]` を `sid:ipv6` のようにフィールド名が違うキーへ当てても照合できます。
- エンディアンはツールが吸収します。数値フィールドはパケットが network order、`set add` は host order で書きますが変換をツールが合わせるので、利用者は普段どおりの数値で `set add` するだけで済みます。`ipv6` フィールドは IPv6 アドレスのバイト列そのものが値なので、パケットも `set add fc00::1` も同じ network order のまま照合します。
- キー幅には上限があります。パケット由来キーはホストスタックの空き領域を使うため、合計 16 バイトまでです。TEID の 4 バイト、IMSI の 8 バイト、TEID と IMSI を合わせた 12 バイト、SRv6 SID の 16 バイトはいずれも収まります。数値フィールドは 1 個 8 バイトまで、`ipv6` フィールドは 16 バイトで、16 バイトのキーはそれ 1 個で予算を使い切ります。
- キーの型はパケットのフィールドを覆う最小の読み出し幅に合わせます。24 bit の `vxlan.vni` と `geneve.vni` は `u32`、48 bit の `eth.src` と `eth.dst` は `u64` です。値はフィールドの数値そのものなので、VNI は `set add vni=100`、MAC は `set add src=aa:bb:cc:dd:ee:ff` と書きます。`u64` のフィールドは MAC の表記も受け付け、`0xaabbccddeeff` と書いても同じキーになります。`set list` は 10 進の数値で表示します。bit slice をキーにできるのは 64 bit 以下の slice と、`ipv6.dst[0:128]` のように 128 bit のフィールド全体を指す slice だけで、65 bit から 127 bit の slice は型エラーです。byte の境界から始まらないフィールドの slice は、ヘッダ上の bit 範囲を覆う読み出し幅がキーの幅になります。`ipv6[traffic_class[0:4] in @tc]` は `u8`、DSCP の `ipv6[traffic_class[0:6] in @dscp]` は `u16` のキーです。
- 定数インデックスの aux フィールドを bracket で参照できます。`srv6[segments[0].addr in @sids]` は SRH の segment list の 0 番目を引きます。`ipv6[exts[1].next_header in @nh]` のように entry の長さが可変な stack でも、定数インデックスなら手前の entry を辿って該当 entry の位置を求めます。該当する entry が無いパケットは不一致になります。bracket に書けるのは `[N]` の定数インデックスだけで、`segments[srv6.last_entry]` のような動的インデックスや添字なしの `any()/all()` は `where` 句を使います。`tcp[mss.value in @NAME]` のように、parser が走査して位置を決める option のフィールドも集合キーにでき、option が無いパケットは不一致になります。
- `@NAME` は他の bracket 条件やレイヤ条件と AND で合成します。`in @NAME` は bracket predicate 専用で、`where` 句の中では使えません。
- `in @NAME` は必ず通るレイヤ、すなわち quantifier のない `QuantOne` のレイヤにのみ書けます。`vlan[...]?` のような optional や繰り返しのレイヤ、`(vlan[...]|qinq)` のような alternation の枝は、そのレイヤが不在でもフィルタが成立しうるため、抽出が走らずキーが未書き込みになる可能性があり、reject されます。
- 引数由来の `--arg-filter @NAME` は entry/exit 専用のままです。パケット由来の DSL `@NAME` は entry/exit と `--mode xdp` の両方で動きます。

## Hand-test として `set` map を手元で叩く

`set` サブコマンドはキャプチャのターゲットが無くても単体で動きます。map を作ってエントリを出し入れし、`set list` / `set schema` で読み戻すだけで、集合まわりの配線を手元で確認できます。root と bpffs のマウントが要ります。

### ライフサイクルをひととおり流す

```bash
PIN=/sys/fs/bpf/bpfninja_handtest

# 1) BTF 付き hash map を作って pin する。この例では value を u32 の tag に限定
sudo bpf-ninja set create $PIN --key "imsi:u64,teid:u32" --value "tag:u32" --max-entries 1024

# 2) フィールド名でエントリを入れる。tag が value
sudo bpf-ninja set add $PIN imsi=999990000000001 teid=0x3039 tag=1
sudo bpf-ninja set add $PIN imsi=999990000000777 teid=100    tag=2

# 3) 読み戻す
sudo bpf-ninja set list   $PIN
sudo bpf-ninja set schema $PIN

# 4) 消す
sudo bpf-ninja set del  $PIN imsi=999990000000001 teid=0x3039
sudo bpf-ninja set list $PIN
```

`set list` は各エントリを `field=value ... tag=N` の形で印字します。`set schema` はキーのレイアウトを出します。並び順は hash map の iterate 順なので、実行ごとやカーネルごとに例と違って見えることがあります。

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

`teid=0x3039` は 16 進で入れても `set list` では 10 進の 12345 で出ます。入力は 10 進でも `0x` 付き 16 進でも構いません。

### value すなわち tag を出し入れする

value はエントリごとの小さな tag です。`tag=N` を省くと存在マーカーの 1 が入ります。`set add` で同じキーに別の tag を入れると上書きになります。読み戻しは `set list` の `tag=N` 列です。

```bash
sudo bpf-ninja set add  $PIN imsi=999990000000777 teid=100 tag=9  # 上書き
sudo bpf-ninja set list $PIN | grep 999990000000777              # tag=9 になる
```

value 型は既定で `tag:u32,state:u8,max_bytes:u64` の struct です。`tag` に加えて、entry の状態 (`state`: active / capped / finalized、キャプチャプロセスが cap 到達や finalize 完了で書き換えます) と、entry ごとの出力バイト上限 (`max_bytes`: `set add ... max-bytes=N` で指定、省略または 0 = 無制限) を持ちます。`--value "tag:u16"` のような 1/2/4/8 バイトの単一整数も従来通り使えますが、その map では cap と state は使えません。tag は数値専用で、`ipv6` はキー側だけの型です。

### 複数の値を照合する

複合キーはフィールド間が AND で 1 lookup です。OR は同じ集合にエントリを複数入れて表現します。各エントリは独立した 1 つのキーで、マッチはそのいずれかに当たるかどうかです。

```bash
# (imsi=999990000000001 かつ teid=0x1000) または
# (imsi=999990000000777 かつ teid=0x2000) を照合したい
sudo bpf-ninja set add $PIN imsi=999990000000001 teid=0x1000 tag=1
sudo bpf-ninja set add $PIN imsi=999990000000777 teid=0x2000 tag=1
```

複数の集合を 1 つのフィルタで組み合わせることもできます。`--set` は複数定義でき、DSL では `layer[a in @s1, b in @s2]` のようにカンマ併記します。ブラケット内のカンマは AND なので、両方がそれぞれの集合に当たったときだけ通ります。

```bash
sudo bpf-ninja set create /sys/fs/bpf/src --key "sport:u16"
sudo bpf-ninja set create /sys/fs/bpf/dst --key "dport:u16"
sudo bpf-ninja set add /sys/fs/bpf/src sport=1111
sudo bpf-ninja set add /sys/fs/bpf/dst dport=443
sudo bpf-ninja -i eth0 --mode xdp \
  --set "src=/sys/fs/bpf/src" --set "dst=/sys/fs/bpf/dst" \
  'eth/ipv4/tcp[sport in @src, dport in @dst]'
```

いま集合に何が入っているかは、フィルタを流しながら別ターミナルで `set list` を叩けば確認できます。`set list` は map のエントリ一覧で、マッチしたエントリを名指しするものではありません。エントリの追加・削除はキャプチャ中でも即時反映され、re-attach は要りません。

### bpftool で map を直接覗く

合成した BTF のおかげで、`bpftool map dump` はフィールド名付きで整形表示されます。`set list` と突き合わせて配線を確認できます。

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

出力の見え方は bpftool のバージョンに依存します。上の JSON 風表示は libbpf ベースの新しい bpftool の既定です。古い bpftool ではフィールドを並べた素のテキストになることがあります。

bpftool で直接書き込む場合は、パディングのゼロ埋めが必須です。hash はキー全バイトをハッシュするので、パディングが非ゼロだと永遠に一致しません。`bpf-ninja set add` はこのゼロ埋めを自動で保証するため、手で書くより安全です。外部で作った pinned map も、hash 型で BTF キーを持てば `set list` / `set schema` で読めます。

### 16 バイトの SID キーを確認する

`ipv6` 型のキーは IPv6 リテラルで出し入れし、`set list` でも IPv6 表記で戻ります。

```bash
sudo bpf-ninja set create /sys/fs/bpf/sids --key "dst:ipv6"
sudo bpf-ninja set add    /sys/fs/bpf/sids dst=fc00::1
sudo bpf-ninja set list   /sys/fs/bpf/sids     # dst=fc00::1 tag=1
sudo bpf-ninja set schema /sys/fs/bpf/sids     # dst  ipv6  offset 0
```


[DSL 利用ガイドに戻る](../dsl-usage.md)
