# 0001 fast-reader のゼロコピー flush

- 状態：却下
- 日付：2026-07-07

## 背景

高レート（およそ 1.6〜1.8 Mpps、64 論理 CPU、Intel E810）で捕捉スループットの上限を切り分けたところ、律速はストレージでもシリアライズでも `write(2)` でもなかった。
出力を `--null-output` にしてもスループットは変わらず、`-w` で pcap-ng をディスクへ書く場合とほぼ同じだった。
律速はユーザ空間 reader の per-record 処理にあると分かった。

その per-record 処理の中に、削れそうに見えるコピーがあった。
`internal/capture/capture.go` の `batchBuilder.add` は、各パケットのペイロードを per-shard の arena へコピーしている（`b.arena = append(b.arena, pkt.Data...)`）。
このコピーを消して、mmap した ring から直接 pcap へ書けば per-record コストが下がるのではないか、という仮説を立てた。

## コピーが存在する理由

このコピーは意図的で、コミット #43「copy packet payload into a per-shard arena to stop batch aliasing」で入っている。
fast-reader の `fastrb.Reader.ReadBatch` は、レコードを走査するループの末尾で consumer position を一括で進める。
呼び出し側 `RunShardsFast` は `ReadBatch` が返ってから `flush`（pcap 書き込み）する。
つまり consumer position は flush より前に進むので、position が進んだ時点でカーネルからはそのスロットが空きに見え、producer（BPF）が上書きできる。
`add` がコピーせず `Packet.Data` を ring 参照のまま持つと、flush の時点で既に上書きされている。
だから arena へ退避している。

## 試した実装

consumer position の遅延コミットでゼロコピー化した。

- `fastrb.Reader` に、position を進めずに最大 N 件を走査する `ReadBatchPeek` と、position を publish する `Commit` を足した。
- `RunShardsFast` を「`ReadBatchPeek`（コピーせず ring 参照のまま batch へ）→ `flush` → `Commit`」のループに変えた。
- N を既存のバッチ幅（256）に固定した。これで producer から見て未消費のスロットは常に 1 バッチぶんに収まり、flush 中に producer を枯渇させない。
- 遅い sink ではバースト耐性が下がるトレードオフがあるため、`--zero-copy`（`--fast-reader` 前提）のオプトインにした。

健全性は確認できた。
`--zero-copy` で撮った pcap は正しく読め、破損は 0、既存の aliasing 回帰テストは緑のままだった。

## 測定結果

同一負荷で `--fast-reader`（arena コピー）と `--fast-reader --zero-copy` を交互に測った。実効 12 秒窓。

| パケット長 | fast-reader（arena copy） | fast-reader --zero-copy |
|---|---|---|
| 128B | 1.21〜1.25 Mpps | 1.26 Mpps |
| 64B | 1.22〜1.24 Mpps | 1.16 Mpps |

差は測定ノイズと同程度で、有意な向上はなかった。
64B ではむしろわずかに下がった。

## 判断と理由

ゼロコピー化は採用しない。

律速は per-record のペイロードコピーではなかった。
128B のコピーは L1 キャッシュ内で数 ns に収まり、per-record の他の固定処理（`ParseRawSample` の各フィールド読み出し、`time.Unix` の呼び出し、`Packet` 値の append、バッチと flush のループ回し）に埋もれる。
「per-record 処理が律速」という切り分けは正しかったが、その内訳でコピーが占める割合は小さかった。
パケットが小さいほどコピーする量も減るので、64B で 128B より効くこともなかった。

得られる数%に対して、`--zero-copy` は複雑さ（peek/commit の 2 段 API、ring 解放を sink 速度に結合する副作用）が見合わない。

## 今後

per-record スループットをさらに上げるなら、コピーではなく次を測る。

- per-record 固定処理そのものの軽量化。`ParseRawSample` のフィールド読みと `time.Unix` 変換をバッチ単位に寄せる、`Packet` 値のコピーを減らす、など。
- drain と parse/write のパイプライン分離。mmap drain を producer コア、パースと書き込みを別コアに置き、SPSC で受け渡す。reader を別コアへ逃がす議論はここで生きる。

## 参考

- 律速の切り分けと map-in-map 構成：[../capture-datapath.md](../capture-datapath.md)
- コピーを入れたコミット：#43「copy packet payload into a per-shard arena to stop batch aliasing」
