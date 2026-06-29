# T-Rex 運用ガイド (E810 hardware mode)

`benchmark/trex/` 配下の T-Rex profile + 関連 ops の手引き。 DUT (paper bench host) ↔ trex host (`ocxma-trex` = `lab-kiba-ocxma-trex-01`) の 2 台構成を前提。

## クイックリファレンス

| やりたいこと | 使うもの | 達成可能 offered rate (64B) |
|---|---|---|
| **既定** 高 PPS bench | `/opt/trex/v3.08` (hardware mode) | **~23 Mpps** |
| TRex 既存資産を再現 (legacy) | `/opt/trex/v3.06` (software mode) | ~22 Mpps |
| DPDK 不要、 kernel-only fallback | `pktgen` module | ~23 Mpps |

## 1. NIC + host 構成

| 役割 | host | NIC | iface name | MAC |
|---|---|---|---|---|
| DUT (xdp-ninja 側) | `dut1` (本機) | E810-C QSFP `8a:00.0` | `enp138s0f0np0` | `40:a6:b7:95:a2:d0` |
| trex (generator) | `ocxma-trex` | E810-C QSFP `8a:00.0` | (vfio-pci 時は隠れる、 ice 時 `enp138s0f0`) | `40:a6:b7:82:cd:d8` |

物理接続: `dut1:8a:00.0 (port 0) ←→ ocxma-trex:8a:00.0 (port 0)`、 1 link 100 GbE。 trex host の `8a:00.1` (port 1) は cable 無し (link down 想定)。

ssh エイリアス: `ssh ocxma-trex` で trex host に届く想定。

## 2. T-Rex hardware mode (DPDK, 推奨)

### 2.1 NIC を vfio-pci に bind

```bash
# trex host で:
for d in 0000:8a:00.0 0000:8a:00.1; do
  echo "$d" | sudo tee /sys/bus/pci/drivers/ice/unbind          # ice から外す
  echo "vfio-pci" | sudo tee /sys/bus/pci/devices/$d/driver_override
  echo "$d" | sudo tee /sys/bus/pci/drivers/vfio-pci/bind
done
lspci -s 8a:00 -k | grep "driver in use"      # vfio-pci × 2 を確認
```

逆操作 (ice に戻す、 ping 等で疎通確認したいとき):

```bash
for d in 0000:8a:00.0 0000:8a:00.1; do
  echo "$d" | sudo tee /sys/bus/pci/drivers/vfio-pci/unbind
  echo "" | sudo tee /sys/bus/pci/devices/$d/driver_override
  echo "$d" | sudo tee /sys/bus/pci/drivers_probe
done
```

### 2.2 hugepages 確認

```bash
cat /proc/meminfo | grep -i hugepages_total    # >= 2048 (2 MiB × 2048 = 4 GiB) 想定
# 足りなければ:
echo 2048 | sudo tee /proc/sys/vm/nr_hugepages
```

### 2.3 設定 YAML

`/opt/trex/v3.08/scripts/trex_e810_hw.yaml` (この repo の `benchmark/trex/trex_e810_hw.yaml` と同内容)。 ポイント:

- `port_limit: 2` (TRex は dual_if 前提で偶数 port を要求、 単 port 構成は受け付けない)
- `port_bandwidth_gb: 100`
- `port_speed` は **書かない** (`100` と書くと **100 Mbps** に解釈されて link drop する、 hardware default で auto = 100 GbE になる)
- `interfaces` は `["8a:00.0", "8a:00.1"]` (PCI BDF。 trailing `,scalar=1` 等の DPDK devargs は TRex YAML がそのまま PCI lookup に渡すので **失敗する**)

### 2.4 TRex v3.08 起動

```bash
# trex host で background 起動 + ログ取得:
cd /opt/trex/v3.08/scripts && sudo nohup ./t-rex-64 -i \
    --cfg /opt/trex/v3.08/scripts/trex_e810_hw.yaml --no-key --stl \
    > /tmp/trex_hw.log 2>&1 &

# 起動成功確認:
pgrep -l _t-rex-64
grep -E "Link Up|max cores|tx queues" /tmp/trex_hw.log
# 期待出力:
#   link : Link Up - speed 100000 Mbps - full-duplex
#   link : Link Down
#   max cores for 2 ports   : 1
#   tx queues per port      : 3
```

### 2.5 TX 動作確認 probe

```bash
ssh ocxma-trex python3 /opt/trex/v3.08/scripts/trex_minimal_probe.py
# 期待: {"requested_pps": 1000000.0, "tx_pps": 約 19-23M, "opackets": 数千万, "oerrors": 0}
# 重要: oerrors が 0 でない (= 65M+ など) 場合は hardware mode が壊れてる。 §6 参照
```

DUT 側で wire 到達確認:

```bash
# DUT で:
before=$(ip -s link show enp138s0f0np0 | awk '/RX:/{getline; print $2}')
ssh ocxma-trex python3 /opt/trex/v3.08/scripts/trex_max_v2.py
after=$(ip -s link show enp138s0f0np0 | awk '/RX:/{getline; print $2}')
echo "DUT RX delta = $((after - before))"
```

### 2.6 停止 / cleanup

```bash
ssh ocxma-trex 'sudo pkill -9 _t-rex-64; sleep 2'
```

## 3. T-Rex software mode (legacy, 22 Mpps cap)

R5-R8 で使ってた path。 `/opt/trex/v3.06`。 NIC は **ice driver の状態** (vfio-pci じゃない)。 hardware DPDK 不要、 ice driver で済む。

```bash
# trex host で:
cd /opt/trex/v3.06 && sudo nohup ./t-rex-64 -i \
    --cfg /opt/trex/v3.06/cfg/trex_cfg.yaml --no-key --stl \
    > /tmp/trex_sw.log 2>&1 &
```

特徴:
- offered rate **20.7 Mpps が CPU 上限** (TRex software emulation 自体の cap、 100G NIC 側じゃない)
- DPDK / vfio-pci 不要、 setup 軽い
- **xdp-ninja R10 までの evaluation はこちらで実施済み**

## 4. Kernel pktgen (DPDK 不要 fallback、 23 Mpps)

NIC が **ice driver** に bound してる状態で動く。 vfio-pci にしてしまうと使えないので注意。

```bash
# trex host で:
sudo modprobe pktgen
sudo ethtool -G enp138s0f0 tx 8160         # TX ring 最大化
sudo /opt/trex/v3.08/scripts/pktgen_run.sh 64 5
#   引数: <threads> <duration_s>
# 期待出力: pktgen TX 約 23 Mpps、 oerrors=0
```

Script は per-thread に独立 TX queue 割当て + UDP port randomize で RSS 分散させる。 source は `benchmark/trex/pktgen_run.sh` (この repo に commit、 trex host にも copy 済み)。

特徴:
- kernel in-tree、 DPDK build 不要
- 64 thread / 64 CPU で **23 Mpps offered**
- TRex hardware mode と同じ rate (E810 PCIe 側 か single-flow rate の cap が支配的)

## 5. xdp-ninja bench でやる定型手順

DUT 側で xdp-ninja を T-Rex 流量に対して走らせる:

```bash
# DUT で:
# 1. target XDP program を attach (例: prod_pass.o)
sudo ip link set dev enp138s0f0np0 xdp off
sudo ip link set dev enp138s0f0np0 xdp obj scripts/test/prod_pass.o sec xdp

# 2. trex を準備 (上 §2.4 で起動済み)

# 3. xdp-ninja を fast-reader + no-wakeup + raw-dump で起動
sudo timeout 65 ./xdp-ninja --mode xdp -i enp138s0f0np0 \
    --raw-dump --fast-reader --no-wakeup \
    --in-memory-buffer 512 \
    -w /dev/shm/cap.raw &

# 4. 5 秒 warmup 後に trex でロードかける
sleep 5
ssh ocxma-trex python3 /opt/trex/v3.08/scripts/trex_max_v2.py    # 5 sec デフォルト

# 5. xdp-ninja 終了待ち
wait
# 6. 結果集計
ls -la /dev/shm/cap.raw     # bytes
sudo ./xdp-ninja convert /dev/shm/cap.raw /tmp/cap.pcap   # raw→pcap-ng
tcpdump -nnr /tmp/cap.pcap 2>/dev/null | wc -l            # packet count
```

## 6. トラブルシューティング

### `oerrors: 65M+`、 `opackets: 0` で TX 出ない

**原因**: TRex v3.04 / v3.05 / v3.06 + E810 + recent ice firmware の **既知 regression** ([Issue #1136](https://github.com/cisco-system-traffic-generator/trex-core/issues/1136))。 TRex 開発元 (syaakov 2024-07-09) 公式に 「E810 は fully supported じゃない、 Intel に問い合わせろ」 と回答。

**対処**: **TRex master branch を source build** (= 内部 v3.08、 DPDK 25.07)。 `/opt/trex/v3.08` がそれ。 v3.06 を使うのはやめる。

Build 手順 (再構築が必要なとき):

```bash
# DUT で internet 経由 clone:
cd /tmp && git clone --depth 1 https://github.com/cisco-system-traffic-generator/trex-core.git

# deps を jammy 用に .deb 直 wget (apt が DNS 切れな環境向け):
cd /tmp/trex_deps && for url in \
  http://archive.ubuntu.com/ubuntu/pool/main/n/numactl/libnuma-dev_2.0.14-3ubuntu2_amd64.deb \
  http://archive.ubuntu.com/ubuntu/pool/main/e/elfutils/libelf-dev_0.186-1build1_amd64.deb \
  http://archive.ubuntu.com/ubuntu/pool/main/p/python-pyelftools/python3-pyelftools_0.27-1_all.deb \
  http://archive.ubuntu.com/ubuntu/pool/main/z/zlib/zlib1g-dev_1.2.11.dfsg-2ubuntu9.2_amd64.deb; do
  wget -q "$url"
done

# trex host へ転送 + install (libelf-dev の dep error は --force-depends で OK):
scp /tmp/trex_deps/*.deb ocxma-trex:/tmp/
ssh ocxma-trex 'sudo dpkg -i --force-depends /tmp/*_amd64.deb'
rsync -az --exclude=".git" /tmp/trex-core/ ocxma-trex:/opt/trex/v3.08/

# trex host で build (3-5 分):
ssh ocxma-trex 'cd /opt/trex/v3.08/linux_dpdk && ./b configure && ./b build -j 16'
```

### `0000:8a:00.0,scalar=1 does not exist`

YAML の `interfaces:` に DPDK devargs を埋めるとこれが出る。 TRex は PCI ID を literal で lookup する。 devargs (`scalar=1`、 `prefer-split-drv=1` 等) は **TRex YAML 経由で渡せない** — TRex source patch 必要。

### `Configuration file should include even number of interfaces, got: 1`

`port_limit: 1` + `interfaces: ["..."]` 単 port 構成は **受け付けない**。 必ず 2 port (片方 link down 可)。

### `Link Up - speed 100 Mbps` (期待は 100 Gbps)

YAML に `port_speed: 100` 書いてる。 これは Mbps 単位なので **100 Mbps** に AN drop してる。 `port_speed` 行を **削除** (auto = 100 G が default)。

### `ice_program_hw_rx_queue(): currently package doesn't support RXDID (22)`

DDP package が NIC firmware と version mismatch。 COMMS DDP package を Intel から落として `/lib/firmware/intel/ice/ddp/ice.pkg` に symlink。 \
我々の環境は `/lib/firmware/updates/intel/ice/ddp/ice_comms-1.3.53.0.pkg` を `ice.pkg` に link し直し済み。

### `WARNING: there is no link on one of the ports`

port 1 (`8a:00.1`) に cable が無い時の警告。 **無視して OK**。 `max cores: 1` も同じ理由 (TRex は link up port の数 × dual_if 設定で core 数決める)。

## 7. 既知の上限

- **23 Mpps offered ceiling**: TRex v3.08 hardware mode も pktgen も同じ ~23 Mpps で頭打ち。 原因は port 0 単一 link / single-core DPDK PMD TX path。 cable で port 1 も DUT 側別 NIC に繋いで dual_if 活かせば理論上 ~46 Mpps、 ただし要 cable 追加 + DUT 側 NIC 増設。
- **AF_XDP path**: 採用しない (CLAUDE.md memory: feedback_perf_features_optin.md と user 直言 「AF_XDP は絶対にやらない」)。
- **TRex software mode**: 20.7 Mpps が hard ceiling、 これは TRex 自身の CPU emulator の cap。 100G NIC では無く software 側で詰まる。

## 8. ファイル配置メモ

| 場所 | 内容 |
|---|---|
| `/opt/trex/v3.06` | legacy software mode、 R5-R10 paper data の generator |
| `/opt/trex/v3.08` | master build (DPDK 25.07)、 hardware mode 動作確認済み |
| `/opt/trex/v3.08/scripts/trex_e810_hw.yaml` | hardware mode config |
| `/opt/trex/v3.08/scripts/trex_minimal_probe.py` | 1 Mpps × 3 sec の最小 TX probe |
| `/opt/trex/v3.08/scripts/trex_max_v2.py` | 200 Mpps 要求 × 5 sec の max-rate probe (port randomize 込み) |
| `/opt/trex/v3.08/scripts/pktgen_run.sh` | kernel pktgen runner (DPDK 無し fallback) |
| `/tmp/trex_hw.log` | trex hardware mode 起動ログ |

## 9. 関連 Issue / 参照

- [v3.05 release kills E810 support · trex-core#1136](https://github.com/cisco-system-traffic-generator/trex-core/issues/1136) — v3.05+ regression の primary 報告、 公式 "not fully supported" 発言
- [E810-CQDA2 initalisation in v3.04 is incorrect · trex-core#1110](https://github.com/cisco-system-traffic-generator/trex-core/issues/1110) — v3.04 の v3.03 二段起動 workaround (master fix で不要)
- [TRex Release Notes (Cisco)](https://trex-tgn.cisco.com/trex/doc/release_notes.html)
- [DPDK 25.07 ICE PMD documentation](https://doc.dpdk.org/guides-25.07/nics/ice.html)
