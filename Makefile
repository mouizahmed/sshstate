GO ?= go
GOFMT ?= gofmt
PKGS := ./...

.PHONY: all build test vet fmt-check race vuln check clean

all: check

build:
	$(GO) build $(PKGS)

test:
	$(GO) test $(PKGS)

race:
	$(GO) test -race -timeout 30m $(PKGS)

vet:
	$(GO) vet $(PKGS)

fmt-check:
	@out="$$($(GOFMT) -l .)" || exit $$?; \
	if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest $(PKGS)

check: fmt-check vet build test race

clean:
	rm -rf dist bin
