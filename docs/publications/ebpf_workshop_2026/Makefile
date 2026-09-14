PYTHON ?= python3

.PHONY: all figures data source-archive clean

all:
	$(MAKE) -C paper

# Explicit regeneration; the ordinary paper build uses the supplied PDFs.
figures:
	$(MAKE) -C paper tikz
	$(PYTHON) analysis/b4_boxplot.py data/b4_xdp_drop_rep*.csv

data:
	$(PYTHON) analysis/summarize.py

source-archive:
	$(MAKE) -C paper source-archive

clean:
	$(MAKE) -C paper clean
