# Keep GOLANGCI_VERSION in sync with .github/workflows/ci.yml
GOLANGCI_VERSION ?= v2.12.0
GOSEC_VERSION ?= v2.22.9
GOVULNCHECK_VERSION ?= v1.1.4

TOOLS_BIN := $(CURDIR)/.tools
GOLANGCI_LINT := $(TOOLS_BIN)/golangci-lint
GOLANGCI_LINT_CACHE := $(TOOLS_BIN)/golangci-cache
GOSEC := $(TOOLS_BIN)/gosec
GOVULNCHECK := $(TOOLS_BIN)/govulncheck

# Standalone gosec excludes mirror the gosec block in .golangci.yml — that file
# holds the canonical rationale; keep the two in sync (#165). G306 is excluded
# here (golangci configures it to allow 0644); all writes use explicit perms.
# G407 false positives (random nonce flagged as hardcoded) are suppressed inline
# via #nosec in internal/keystore.
GOSEC_EXCLUDES := G104,G115,G124,G710,G306

.PHONY: all build test vet lint gosec govulncheck ci tools clean tidy bench-up bench-down bench-clean

all: lint test build

build:
	go build -o bin/nebula-mgmt ./cmd/nebula-mgmt
	go build -o bin/nebula-agent ./cmd/nebula-agent

vet:
	go vet ./...

test:
	go test -v -race ./...

lint: tools
	GOLANGCI_LINT_CACHE="$(GOLANGCI_LINT_CACHE)" $(GOLANGCI_LINT) run --timeout=5m ./...

ci: vet build test lint gosec govulncheck

# Standalone gosec audit, independent of golangci-lint's bundled subset (#165).
gosec: $(GOSEC)
	$(GOSEC) -exclude=$(GOSEC_EXCLUDES) -quiet ./...

$(GOSEC):
	@mkdir -p $(TOOLS_BIN)
	GOBIN="$(TOOLS_BIN)" go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)

# Reachable-vulnerability scan of the dependency graph (#209).
govulncheck: $(GOVULNCHECK)
	$(GOVULNCHECK) ./...

$(GOVULNCHECK):
	@mkdir -p $(TOOLS_BIN)
	GOBIN="$(TOOLS_BIN)" go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

tools:
	@mkdir -p $(TOOLS_BIN)
	@if [ ! -x "$(GOLANGCI_LINT)" ] || ! "$(GOLANGCI_LINT)" version 2>/dev/null | grep -q "$(patsubst v%,%,$(GOLANGCI_VERSION))"; then \
		echo "Installing golangci-lint $(GOLANGCI_VERSION) into $(TOOLS_BIN)..."; \
		GOBIN="$(TOOLS_BIN)" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION); \
	fi

clean:
	rm -rf bin/ .tools/

tidy:
	go mod tidy

# Local multi-operator offensive test bench (#208). See hack/offensive-bench/README.md.
bench-up:
	hack/offensive-bench/bench.sh up

bench-down:
	hack/offensive-bench/bench.sh down

bench-clean:
	hack/offensive-bench/bench.sh clean
