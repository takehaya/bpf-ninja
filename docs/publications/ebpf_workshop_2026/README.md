# eBPF Workshop 2026: Kunai

Source and measurement artifacts for **Kunai: Toward a Verifier-Safe Layered
DSL for Nested Encapsulation Packet Filtering on eBPF**.

- `paper/`: camera-ready LaTeX source, bibliography, and figure PDFs.
- `data/`: measurements used by the evaluation; see the [data guide](data/README.md).
- `analysis/`: figure generation and numerical summaries.

## Build the paper

From the repository root:

```sh
make -C docs/publications/ebpf_workshop_2026
```

The output is `docs/publications/ebpf_workshop_2026/paper/main.pdf`.
The build needs GNU Make, pdfLaTeX, BibTeX, latexmk, and TeX Live packages
including `ACM-Reference-Format.bst`, `algorithm`, and `algpseudocode`.
The camera-ready `acmart.cls` version 2.19 is included.
On Debian/Ubuntu, the package set is:

```sh
sudo apt install make latexmk texlive-latex-extra texlive-publishers \
    texlive-science texlive-fonts-recommended
```

All figures are supplied as PDFs, so Python is optional for building the paper.
The directory can also be copied out of the repository and built with `make`.

## Regenerate figures and summaries

From this directory, set up Python 3.11 or newer:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
make figures PYTHON=.venv/bin/python
make
```

`make figures` rebuilds both TikZ diagrams with pdfLaTeX and the datapath chart
from the ten supplied repetitions. The [figure guide](paper/figures/README.md)
maps each PDF to its source. PDF metadata and font rendering may vary with
the toolchain.

Recompute the numerical summaries with Python's standard library:

```sh
make data
```

The [data guide](data/README.md) explains the units, baseline normalization,
standard deviations, and the mapping to the compiler's filter IDs.
These commands process the saved measurements; they do not run traffic or
load BPF programs. The compiler and verifier tests are available in this
repository at the paper's pinned `v0.23.1` tag.

## Source archive

```sh
make source-archive
```

This creates `paper/kunai-ebpf26-camera-ready-src.tar.gz`, including the
generated bibliography and everything needed for the LaTeX build. The CSVs
and Python analysis are distributed alongside it in this repository.
`make clean` removes paper build products and retains the source, data, and
supplied figure PDFs.
