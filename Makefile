GO ?= go
PKGS := ./...

.PHONY: all build test vet fmt-check race vuln check clean

all: check

build:
	$(GO) build $(PKGS)

test:
	$(GO) test $(PKGS)

race:
	$(GO) test -race $(PKGS)

vet:
	$(GO) vet $(PKGS)

fmt-check:
	@out="$$($(GO) fmt $(PKGS))"; \
	if [ -n "$$out" ]; then echo "gofmt made changes in:"; echo "$$out"; exit 1; fi

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest $(PKGS)

check: fmt-check vet build test race

clean:
	rm -rf dist bin
