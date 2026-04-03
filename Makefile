.PHONY: all build test lint clean

all: lint test build

build:
	go build -o bin/nebula-mgmt ./cmd/nebula-mgmt
	go build -o bin/nebula-agent ./cmd/nebula-agent

test:
	go test -v -race ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/

tidy:
	go mod tidy
