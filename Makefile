# Keep GOLANGCI_VERSION in sync with .github/workflows/ci.yml
GOLANGCI_VERSION ?= v2.12.0

TOOLS_BIN := $(CURDIR)/.tools
GOLANGCI_LINT := $(TOOLS_BIN)/golangci-lint

.PHONY: all build test vet lint ci tools clean tidy

all: lint test build

build:
	go build -o bin/nebula-mgmt ./cmd/nebula-mgmt
	go build -o bin/nebula-agent ./cmd/nebula-agent

vet:
	go vet ./...

test:
	go test -v -race ./...

lint: tools
	$(GOLANGCI_LINT) run --timeout=5m ./...

ci: vet build test lint

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
