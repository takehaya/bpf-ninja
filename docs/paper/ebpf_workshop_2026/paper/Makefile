# Build for the eBPF Workshop'26 submission.
# Requires: latexmk + acmart class (texlive-publishers on Debian/Ubuntu).

MAIN := main
SECTIONS := $(wildcard sections/*.tex)
BIB := refs.bib
LATEXMK := latexmk -pdf -interaction=nonstopmode -file-line-error -halt-on-error

.PHONY: all clean check pages

all: $(MAIN).pdf

$(MAIN).pdf: $(MAIN).tex $(SECTIONS) $(BIB)
	$(LATEXMK) $(MAIN).tex

# Show body page count (excluding references and appendices).
# 6.0 is the hard limit; this is a quick sanity check during writing.
pages: $(MAIN).pdf
	@pdfinfo $(MAIN).pdf | grep -E "^Pages" || echo "(install poppler-utils for pdfinfo)"

# Quick anonymization sanity check before submission.
check:
	@echo "== Anonymization grep (should be empty for review submission) =="
	@grep -rn -E 'takehaya|takeru|sacrament' . || echo "  (clean)"
	@echo "== TODO count =="
	@grep -rn '\\TODO' sections/*.tex | wc -l
	@echo "== Page count =="
	@$(MAKE) -s pages

clean:
	$(LATEXMK) -C
	rm -f *.aux *.bbl *.blg *.fdb_latexmk *.fls *.log *.out *.synctex.gz
