GOLANGCI_LINT := github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.1.4

.PHONY: build test fuzz lint vuln fmt-check check

build:
	go build ./...

test:
	go test -race ./...

fuzz:
	go test ./internal/profile -run '^$$' -fuzz '^FuzzDecode$$' -fuzztime 20s

lint:
	go run $(GOLANGCI_LINT) run

vuln:
	go run $(GOVULNCHECK) ./...

fmt-check:
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }
	go run $(GOLANGCI_LINT) fmt --diff

# Keep prerequisites serial even when the caller enables make's job pool.
check:
	$(MAKE) fmt-check
	$(MAKE) lint
	$(MAKE) test
