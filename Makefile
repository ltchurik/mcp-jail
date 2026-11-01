BIN=bin/mcp-jail
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test lint clean install

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/mcp-jail

test:
	go test ./...

lint:
	go vet ./...

install: build
	install -m 0755 $(BIN) $(HOME)/.local/bin/mcp-jail

clean:
	rm -rf bin dist
