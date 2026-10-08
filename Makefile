GOLANGCI_LINT := github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.1.4

.PHONY: build test fuzz lint vuln fmt-check check cross-build native-tray

# Native macOS tray code requires cgo; every other target uses pure Go.
CROSS_PACKAGES = $$(go list ./... | grep -vE '/cmd/fortix-tray$$')

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

# Build one target at a time, omitting only the native macOS tray command.
cross-build:
	@set -e; for os in darwin linux; do \
		for arch in amd64 arm64; do \
			echo "Cross-build $$os/$$arch"; \
			if [ "$$os" = darwin ]; then \
				GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(CROSS_PACKAGES); \
			else \
				GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build ./...; \
			fi; \
		done; \
	done

# Link the macOS tray using the runner's native SDK without leaving a binary behind.
native-tray:
	CGO_ENABLED=1 go build -o /dev/null ./cmd/fortix-tray

# Keep prerequisites serial even when the caller enables make's job pool.
check:
	$(MAKE) fmt-check
	$(MAKE) lint
	$(MAKE) test
