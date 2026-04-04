.PHONY: build clean test test-unit test-bpf test-integration test-all vet goreleaser
.PHONY: install-lint-tools lint lint-ci

BINARY = xdp-ninja
DIFF_FROM_BRANCH_NAME ?= main

build:
	go build -o $(BINARY) ./cmd/xdp-ninja/

vet:
	go vet ./...

## Lint:

install-lint-tools: ## install lint tools
	./scripts/install_lint_tools.sh

lint: ## Run lefthook pre-commit on all files
	lefthook run pre-commit --all-files

lint-ci: ## Run lefthook pre-commit on changed files (for CI)
	FILES="$$(git diff --name-only $(DIFF_FROM_BRANCH_NAME) HEAD | tr '\n' ' ')"; \
	if [ -n "$$FILES" ]; then \
		lefthook run pre-commit --file $$FILES; \
	fi

test: test-unit

test-unit:
	go test ./...

test-bpf:
	sudo env "PATH=$(PATH)" "HOME=$(HOME)" "GOPATH=$$(go env GOPATH)" "GOMODCACHE=$$(go env GOMODCACHE)" \
		go test -v -count 1 -timeout 5m ./internal/program/ -run TestBpf

test-integration: build
	sudo scripts/test/run_tests.sh

test-all: test-unit test-bpf test-integration

goreleaser: ## build with goreleaser
	goreleaser release --snapshot --clean

clean:
	rm -f $(BINARY)
