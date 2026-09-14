# Figures

| PDF | Source | Input |
|---|---|---|
| `fig_arch.pdf` | `fig_arch.tex` (TikZ) | Architecture diagram |
| `fig_layerstart.pdf` | `fig_layerstart.tex` (TikZ) | Packet layout diagram |
| `fig_datapath.pdf` | [`../../analysis/b4_boxplot.py`](../../analysis/b4_boxplot.py) | [`../../data/`](../../data/README.md): `b4_xdp_drop_rep1.csv` through `rep10.csv` |

Run `make figures` from the publication directory to regenerate all three.
To rebuild just the datapath chart:

```sh
python3 analysis/b4_boxplot.py data/b4_xdp_drop_rep*.csv
```

The plot reports each filter's percentage throughput reduction relative to
the accept-all measurement for the same packet stream, then computes the mean
and population standard deviation over the ten repetitions. The supplied
camera-ready chart uses that convention. See the [data guide](../../data/README.md)
for the complete formulas and runtime-summary convention.
