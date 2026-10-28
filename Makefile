.PHONY: build build-libpcap clean test test-unit test-bpf test-integration test-all vet goreleaser
.PHONY: install-lint-tools lint lint-ci p4c-check lean-build lean-gen lean-vocab golden-update golden-diff

BINARY = bpf-ninja
DIFF_FROM_BRANCH_NAME ?= main
CGO_ENABLED ?= 0
export CGO_ENABLED
GO_TAGS ?=
GO_TAG_FLAGS = $(if $(strip $(GO_TAGS)),-tags '$(GO_TAGS)')

build:
	go build $(GO_TAG_FLAGS) -o $(BINARY) ./cmd/bpf-ninja/

build-libpcap: ## Build the legacy tcpdump/cBPF configuration (needs libpcap-dev)
	$(MAKE) build CGO_ENABLED=1 GO_TAGS=enable_libpcap

vet:
	go vet $(GO_TAG_FLAGS) ./...

## Lint:

install-lint-tools: ## install lint tools
	./scripts/install_lint_tools.sh

lint: ## Run lefthook pre-commit on all files
	lefthook run pre-commit --all-files

lint-ci: ## Run lefthook pre-commit on changed files (for CI)
	@if ! git diff --quiet $(DIFF_FROM_BRANCH_NAME) HEAD; then \
		git diff --name-only -z $(DIFF_FROM_BRANCH_NAME) HEAD | xargs -0 lefthook run pre-commit --file; \
	fi

test: test-unit

test-unit:
	go test $(GO_TAG_FLAGS) ./...

test-bpf:
	sudo env "PATH=$(PATH)" "HOME=$(HOME)" "GOPATH=$$(go env GOPATH)" "GOMODCACHE=$$(go env GOMODCACHE)" \
		CGO_ENABLED=1 python3 scripts/test/privileged.py

test-bench-run:
	sudo env "PATH=$(PATH)" "HOME=$(HOME)" "GOPATH=$$(go env GOPATH)" "GOMODCACHE=$$(go env GOMODCACHE)" \
		bash benchmark/microbench/run_runtime.sh

test-integration: build-libpcap
	sudo scripts/test/run_tests.sh

test-all: test-unit test-bpf test-integration

lean-build: ## Build the Lean 4 spec (needs elan; not part of test-unit)
	cd spec/lean && lake build

lean-vocab: ## Regenerate spec/lean/Kunai/VocabData.lean from the bundled .p4 vocabulary
	go run ./spec/lean/gen/vocab2lean > spec/lean/Kunai/VocabData.lean.tmp \
		&& mv spec/lean/Kunai/VocabData.lean.tmp spec/lean/Kunai/VocabData.lean

lean-gen: ## Regenerate the vocabulary and pkg/kunai/dsltest/testdata/spec_vectors*.json from the Lean spec
	$(MAKE) lean-vocab
	$(MAKE) lean-build
	mkdir -p pkg/kunai/dsltest/testdata
	spec/lean/.lake/build/bin/gen > pkg/kunai/dsltest/testdata/spec_vectors.json.tmp \
		&& mv pkg/kunai/dsltest/testdata/spec_vectors.json.tmp pkg/kunai/dsltest/testdata/spec_vectors.json
	spec/lean/.lake/build/bin/gen --generated > pkg/kunai/dsltest/testdata/spec_vectors_gen.json.tmp \
		&& mv pkg/kunai/dsltest/testdata/spec_vectors_gen.json.tmp pkg/kunai/dsltest/testdata/spec_vectors_gen.json

p4c-check: ## Validate bundled .p4 vocab with the official p4c parser (docker required)
	./scripts/p4c-check.sh

goreleaser: ## build with goreleaser
	goreleaser release --snapshot --clean

clean:
	rm -f $(BINARY)

golden-update: ## Rewrite the bytecode golden (pkg/kunai/dsltest/testdata/golden) and list the filters that moved
	cd pkg/kunai/dsltest && go test -run '^TestGolden$$' -update

GOLDEN_BASE ?= main
golden-diff: ## Diff every golden filter's text between GOLDEN_BASE (default main) and the working tree, without instruction indexes (GOLDEN_DIFF_INDEX=1 keeps them); scripts/golden-diff.sh exits 0 same, 1 moved, 2 error
	./scripts/golden-diff.sh "$(GOLDEN_BASE)"

.PHONY: docs-update docs-check

docs-update: ## Regenerate CLI and protocol references without loading BPF
	go test $(GO_TAG_FLAGS) ./cmd/bpf-ninja -run '^TestDocumentation$$' -count=1 -update-docs

docs-check: ## Fail if generated references drift from this checkout
	go test $(GO_TAG_FLAGS) ./cmd/bpf-ninja -run '^TestDocumentation$$' -count=1
