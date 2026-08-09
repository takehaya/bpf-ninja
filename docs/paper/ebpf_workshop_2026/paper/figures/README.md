# Figures

Two kinds of figures live here.

- TikZ (concept and architecture diagrams): built from the `.tex`
  source next to the PDF with `pdflatex`, and included by the body
  via `\includegraphics`.
- matplotlib (measured data): built by scripts under
  `benchmark/analysis/` from the CSVs under `benchmark/results/`.

| PDF | Kind | Body | Source | Input data |
|-----|------|------|--------|-----------|
| `fig_arch.pdf` | TikZ | Sec 3 | `fig_arch.tex` | none |
| `fig_layerstart.pdf` | TikZ | Sec 4 | `fig_layerstart.tex` | none |
| `fig_datapath.pdf` | matplotlib | Sec 5 | `benchmark/analysis/b4_boxplot.py` | `benchmark/results/b4_xdp_drop_rep*.csv` |

## Rebuilding the TikZ figures

Each `.tex` is a standalone document. In this directory:

```bash
pdflatex fig_arch.tex        # -> fig_arch.pdf
pdflatex fig_layerstart.tex  # -> fig_layerstart.pdf
```

The body does not inline TikZ on purpose: it keeps the main build
light and isolates acmart from the TikZ libraries.

## Rebuilding the matplotlib figure

Run from the repository root. The output path can be overridden with
`-o`:

```bash
python3 benchmark/analysis/b4_boxplot.py benchmark/results/b4_xdp_drop_rep*.csv \
    -o docs/paper/ebpf_workshop_2026/paper/figures/fig_datapath.pdf
```
