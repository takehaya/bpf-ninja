MAIN := main
SECTIONS := $(wildcard sections/0*.tex)
FIGURES := figures/fig_arch.pdf figures/fig_layerstart.pdf figures/fig_datapath.pdf
LATEXMK ?= latexmk
PDFLATEX ?= pdflatex
LATEXFLAGS := -interaction=nonstopmode -file-line-error -halt-on-error
ARCHIVE := kunai-ebpf26-camera-ready-src.tar.gz
SRC_FILES := main.tex acmart.cls refs.bib main.bbl Makefile $(SECTIONS) \
	figures/fig_arch.tex figures/fig_layerstart.tex $(FIGURES)

.PHONY: all tikz pages source-archive clean

all: $(MAIN).pdf

$(MAIN).pdf: $(MAIN).tex $(SECTIONS) refs.bib acmart.cls $(FIGURES) Makefile
	$(LATEXMK) -pdf $(LATEXFLAGS) $(MAIN).tex

tikz:
	cd figures && $(PDFLATEX) $(LATEXFLAGS) fig_arch.tex
	cd figures && $(PDFLATEX) $(LATEXFLAGS) fig_layerstart.tex

pages: $(MAIN).pdf
	pdfinfo $(MAIN).pdf

source-archive: $(MAIN).pdf
	tar czf $(ARCHIVE) --transform 's,^,kunai-ebpf26/,' $(SRC_FILES)

clean:
	$(LATEXMK) -C $(MAIN).tex
	rm -f $(MAIN).bbl $(ARCHIVE) figures/*.aux figures/*.log figures/*.out
