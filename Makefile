PROJECT   := nhi-watch
MODULE    := github.com/Zyrakk/nhi-watch
BINARY    := bin/$(PROJECT)
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -s -w -X '$(MODULE)/internal/cli.Version=$(VERSION)'
GO        := go
GOFLAGS   := -trimpath
LINT      := golangci-lint

.PHONY: all build test lint run clean fmt vet help

## all: build + test (default target)
all: build test

## build: compile the nhi-watch binary
build:
	@echo "==> Building $(PROJECT) $(VERSION)..."
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/nhi-watch/
	@echo "==> Binary: $(BINARY)"

## test: run all unit tests with race detection
test:
	@echo "==> Running tests..."
	$(GO) test -race -count=1 -v ./...

## lint: run golangci-lint (install: https://golangci-lint.run/usage/install/)
lint:
	@echo "==> Running linter..."
	$(LINT) run ./...

## fmt: format all Go source files
fmt:
	@echo "==> Formatting..."
	$(GO) fmt ./...

## vet: run go vet
vet:
	@echo "==> Vetting..."
	$(GO) vet ./...

## run: build and execute discover against the current kubeconfig
run: build
	@echo "==> Running $(PROJECT) discover..."
	./$(BINARY) discover --verbose

## run-json: same as run but with JSON output
run-json: build
	./$(BINARY) discover --verbose -o json

## clean: remove build artifacts
clean:
	@echo "==> Cleaning..."
	rm -rf bin/
	$(GO) clean -cache -testcache

## help: show this help
help:
	@echo "Available targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
