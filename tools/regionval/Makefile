.PHONY: ci build vet test lint check-trust dafny-verify dafny-gen dafny-check-gen corpus verify-sim

DAFNY ?= dafny
# Z3's default case_split=3 loops on bv64 function unfoldings; 0 only changes
# the search strategy, not what counts as a proof.  normalizeDeclarationOrder:0
# keeps Boogie's declaration order, so Z3 gets the same input on every run
# (otherwise the order is shuffled per run and a goal's cost varies widely).
DFLAGS := --boogie -proverOpt:O:smt.case_split=0 --boogie /normalizeDeclarationOrder:0 --verification-time-limit 120
# All files are listed: dafny verify does not verify included files otherwise.
DFY := dafny/src/Bits.dfy dafny/src/Semantics.dfy dafny/src/Terms.dfy dafny/src/Obligations.dfy \
	dafny/src/Checker.dfy dafny/src/Soundness.dfy dafny/src/Api.dfy
# Whole-program simulation proof (dafny/sim); not part of the generated Go.
SIM := dafny/sim/Model.dfy dafny/sim/Rewrite.dfy dafny/sim/Premises.dfy dafny/sim/Theorem.dfy \
	dafny/sim/Facts.dfy dafny/sim/Region.dfy dafny/sim/Bridge.dfy dafny/sim/LayoutFacts.dfy dafny/sim/Frames.dfy \
	dafny/sim/Sites.dfy dafny/sim/Classes.dfy dafny/sim/Calls.dfy dafny/sim/Wrap.dfy dafny/sim/Step.dfy dafny/sim/Witness.dfy dafny/sim/Witness2.dfy dafny/sim/Witness3.dfy dafny/sim/Witness4.dfy \
	dafny/sim/Main.dfy
# Scan source text conservatively, including comments; only these attributes are allowed.
TRUST_RE := \{:(?!(?:isolate_assertions|nowarn)\})|(?m:^[ \t]*@)|\bassume\b|\b(?:replaceable|abstract)\s+module\b
export TRUST_RE
# Every include must resolve to a listed file, so its body is verified separately.
define TRUST_CHECK
from pathlib import Path
import os, re, sys
files = {Path(f).resolve() for f in sys.argv[1:]}
failed = False
for directory in ("src", "sim"):
    for path in Path("dafny", directory).glob("*.dfy"):
        if path.resolve() not in files:
            print(f"{path}: not listed in DFY or SIM")
            failed = True
for name in sys.argv[1:]:
    path = Path(name)
    text = path.read_text()
    for match in re.finditer(os.environ["TRUST_RE"], text):
        line = text.count("\n", 0, match.start()) + 1
        print(f"{path}:{line}: trust escape: {match.group()!r}")
        failed = True
    for match in re.finditer(r"\binclude\b", text):
        target = re.match(r'\s+"([^"\r\n]+)"', text[match.end():])
        line = text.count("\n", 0, match.start()) + 1
        if target is None:
            print(f"{path}:{line}: unsupported include syntax")
            failed = True
        elif (path.parent / target[1]).resolve() not in files:
            print(f"{path}:{line}: include {target[1]} is not listed in DFY or SIM")
            failed = True
sys.exit(1 if failed else 0)
endef
export TRUST_CHECK
GEN_MODULE := github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go
export CGO_ENABLED := 0

ci: ## What CI runs (needs dafny, goimports and golangci-lint on PATH)
	$(MAKE) check-trust dafny-verify dafny-check-gen vet test lint

build: ## Build the regionval CLI
	go build -o regionval ./cmd/regionval

vet:
	go vet ./...

test: ## Go tests (no Dafny needed)
	go test -count=1 ./...

lint: ## golangci-lint (the root linters, generated Go excluded)
	golangci-lint run ./...

check-trust: ## Check allowed attributes, trust escapes, file lists and include targets in DFY and SIM
	@python3 -c "$$TRUST_CHECK" $(DFY) $(SIM)
	@echo "check-trust: ok"

dafny-verify: ## Verify the Dafny core and its soundness proof
	$(DAFNY) verify $(DFLAGS) $(DFY)

verify-sim: check-trust ## Verify the simulation proof with warnings as errors (SIMLOG=dir: a CSV log per file)
	@if [ -n "$(SIMLOG)" ]; then mkdir -p "$(SIMLOG)" || exit $$?; fi
	@# One invocation per file: an included file is not verified again (Dafny
	@# verifies included files only with --verify-included-files), and every
	@# file of SIM is passed once, so each file is verified exactly once.
	@rc=0; for f in $(SIM); do s=$$(date +%s); \
	  csv=; [ -n "$(SIMLOG)" ] && csv="--log-format=csv;LogFileName=$(SIMLOG)/$$(basename $$f .dfy).csv"; \
	  out=$$($(DAFNY) verify $(DFLAGS) $$csv $$f 2>&1); r=$$?; \
	  if [ $$r -ne 0 ]; then printf '%s\n' "$$out"; \
	  else printf '%s\n' "$$out" | grep -vE '^Dafny program verifier' | grep -E 'Error|Warning|error|warning'; fi; \
	  echo "$$f: $$(echo "$$out" | grep -E 'verifier finished' | sed 's/Dafny program verifier finished with //') ($$(( $$(date +%s) - s )) s)"; \
	  [ $$r -eq 0 ] || rc=1; done; exit $$rc

dafny-gen: ## Regenerate dafny/gen-go from the Dafny sources
	@t=$$(mktemp -d); \
	$(DAFNY) translate go --no-verify --go-module-name $(GEN_MODULE) -o $$t/gen dafny/src/Api.dfy && \
	rm -rf dafny/gen-go && mv $$t/gen-go dafny/gen-go; \
	rc=$$?; rm -rf $$t; exit $$rc

dafny-check-gen: ## Fail if dafny/gen-go differs from a fresh translation
	@t=$$(mktemp -d); \
	$(DAFNY) translate go --no-verify --go-module-name $(GEN_MODULE) -o $$t/gen dafny/src/Api.dfy >/dev/null && \
	diff -r $$t/gen-go dafny/gen-go && echo "dafny-check-gen: generated Go is up to date"; \
	rc=$$?; rm -rf $$t; exit $$rc

CAPTURES ?=
corpus: ## Check every capture under CAPTURES=<dir>
	./scripts/corpus.sh "$(CAPTURES)"
