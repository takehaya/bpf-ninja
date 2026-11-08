.PHONY: ci build vet test lint check-trust dafny-verify dafny-gen dafny-check-gen corpus

DAFNY ?= dafny
# Z3's default case_split=3 loops on bv64 function unfoldings; 0 only changes
# the search strategy, not what counts as a proof.
DFLAGS := --boogie -proverOpt:O:smt.case_split=0 --verification-time-limit 120
# All files are listed: dafny verify does not verify included files otherwise.
DFY := dafny/src/Bits.dfy dafny/src/Semantics.dfy dafny/src/Terms.dfy dafny/src/Obligations.dfy \
	dafny/src/Checker.dfy dafny/src/Soundness.dfy dafny/src/Api.dfy
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

check-trust: ## Fail on assume, axioms, unverified or extern declarations, or a .dfy file missing from DFY
	@for f in dafny/src/*.dfy; do case " $(DFY) " in *" $$f "*) ;; *) echo "$$f is not listed in DFY"; exit 1;; esac; done
	@rc=0; grep -nE '\bassume\b|\{: *axiom\b|@Axiom\b|\{: *verify +false|@Verify\b|\{: *extern\b|@Extern\b' $(DFY) || rc=$$?; \
	case $$rc in 0) echo "trust escape found"; exit 1;; 1) ;; *) exit $$rc;; esac
	@echo "check-trust: ok"

dafny-verify: ## Verify the Dafny core and its soundness proof
	$(DAFNY) verify $(DFLAGS) $(DFY)

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
