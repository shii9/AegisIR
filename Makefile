.PHONY: build test test-go test-python lint smoke clean package fmt help

BINARY     := dist/aegisir
GOOS       ?= linux
GOARCH     ?= amd64
CGO_ENABLED := 0
LDFLAGS    := -trimpath

help:
	@echo "AegisIR — Build Targets"
	@echo ""
	@echo "  make build    Build Linux amd64 binary → dist/aegisir"
	@echo "  make test     Run all Go + Python unit tests"
	@echo "  make lint     Run go vet static analysis"
	@echo "  make fmt      Format all Go source files"
	@echo "  make smoke    Build + run CLI smoke tests"
	@echo "  make package  Build + test + create release tarballs"
	@echo "  make clean    Remove all build artifacts"

build:
	@mkdir -p dist/python
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) \
		go build $(LDFLAGS) -o $(BINARY) ./cmd/aegisir
	@cp python/engine.py dist/python/engine.py
	@echo "Built: $(BINARY)"

test: test-go test-python

test-go:
	go test ./... -race -count=1 -timeout 60s

test-python:
	PYTHONPATH=python python3 -m unittest discover -s python -p 'test_*.py' -v

lint:
	go vet ./...

fmt:
	gofmt -w cmd internal

smoke: build
	bash scripts/smoke.sh

package: test build
	bash scripts/package.sh

clean:
	rm -rf dist/
	rm -rf python/__pycache__/
	rm -f python/*.pyc
	rm -f .pytest_cache/
	rm -f aegisir
	@echo "Cleaned all build artifacts."
