# Figures — 生成方法

このディレクトリの図は **2 系統** で管理している。

- **TikZ 系**（概念図 / 構成図）— `.tex` ソースから `pdflatex` で `.pdf` を生成。本文は `\includegraphics` でその `.pdf` を取り込む。
- **matplotlib 系**（実測データのグラフ）— `benchmark/analysis/` の Python スクリプトが `benchmark/results/` の CSV を読んで `.pdf` を出力する。

`.tex` が隣にある PDF は TikZ 系、無い PDF は matplotlib 系。判別は `pdfinfo <file>.pdf` の `Creator` でも可能（`TeX` か `Matplotlib`）。

## 一覧

| 図 (PDF) | 種別 | 本文 | ソース | 入力データ |
|----------|------|------|--------|-----------|
| `fig_arch.pdf` | TikZ | §3 | `fig_arch.tex` | — |
| `fig_insns.pdf` | TikZ | §4 | `fig_insns.tex` | — |
| `fig_layerstart.pdf` | TikZ | §4 | `fig_layerstart.tex` | — |
| `fig_topology.pdf` | TikZ | §5 | `fig_topology.tex` | — |
| `fig_datapath.pdf` | matplotlib | §5 | `benchmark/analysis/b4_boxplot.py` | `benchmark/results/b4_xdp_drop_rep*.csv` |
| `fig_visibility_matrix.pdf` | matplotlib | attic | `benchmark/analysis/plot_visibility.py` | `benchmark/results/visibility_matrix.csv` |

「本文」列が `attic` の図は現行の本文 (`main.tex`) では未使用で、`sections/attic/`
からのみ参照される。本文に取り込まれている matplotlib 図は `fig_datapath.pdf` のみ。

補足: `fig_visibility_matrix.pdf` を出すと同時に `plot_visibility.py` は §6.6 で
`\input{}` される `sections/attic/_visibility_matrix_table.tex` も書き出す。

## 退避済み: throughput (B3 / fig7)

end-to-end throughput (B3) のベンチは廃止し、図・スクリプト・データを一式 attic に
退避した（削除はしていない）。英語投稿版 (`main.tex`) の本文から throughput の節と
図は除いてある。

| 退避物 | 退避先 |
|--------|--------|
| 図 | `figures/attic/fig7_throughput.pdf` |
| スクリプト | `benchmark/analysis/attic/plot_b3.py` |
| データ (`bpf_ringbuf`) | `benchmark/results/attic/b3_throughput_ringbuf_v1.csv` |
| データ (`perf event array`, 旧バックエンド) | `benchmark/results/attic/b3_throughput_perf.csv` |

再生成する場合は `benchmark/analysis/attic/plot_b3.py` を repo ルートから実行する
（入力・出力とも attic 内のパスを指すよう更新済み）。

## TikZ 図の再生成

各 `.tex` は `\documentclass[tikz]{standalone}` の単独ドキュメント。図ディレクトリで:

```bash
pdflatex fig_arch.tex        # -> fig_arch.pdf
pdflatex fig_insns.tex       # -> fig_insns.pdf
pdflatex fig_layerstart.tex  # -> fig_layerstart.pdf
pdflatex fig_topology.tex    # -> fig_topology.pdf
```

各ファイル冒頭の `% Build:` コメントにも同じ手順がある。

本文 (`main.tex`) に TikZ を直接インラインしていないのは意図的: 本文ビルドを軽く保ち、
acmart と TikZ ライブラリの衝突を切り離すため。直埋めにしたい場合は `standalone` の
ガワを外して `main.tex` 側で `\usepackage{tikz}` + `\input{}` すれば可能。

## matplotlib 図の再生成

`benchmark/results/` の CSV が前提（ベンチ実行で生成）。3 スクリプトとも
**リポジトリルートから**実行する。入力 (`benchmark/results/...`) も出力
(`docs/paper/.../figures/...`) もスクリプト内で repo ルート相対に解決されるので、
追加のパス指定は不要:

```bash
# repo ルートで
python3 benchmark/analysis/b4_boxplot.py benchmark/results/b4_xdp_drop_rep*.csv
python3 benchmark/analysis/plot_visibility.py  # 図 + attic の table .tex を書き出す
```

`b4_boxplot.py` の出力先は `-o` で上書きできる。
（退避した throughput 図 `fig7` の再生成は上記「退避済み」セクションを参照。）
