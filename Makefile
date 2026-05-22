.PHONY: build test lint clean

BINARY := oteldoctor
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")
LDFLAGS := -ldflags "-s -w -X github.com/firfircelik/oteldoctor/internal/cli.version=$(VERSION) -X github.com/firfircelik/oteldoctor/internal/cli.commit=$(COMMIT) -X github.com/firfircelik/oteldoctor/internal/cli.date=$(DATE)"

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/oteldoctor

test:
	go test -race -count=1 ./...

lint:
	@echo "lint: not implemented"

clean:
	rm -rf bin/
