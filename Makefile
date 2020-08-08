GO=go

.PHONY: lint
lint:
	golangci-lint run

.PHONY: install
install:
	$(GO) install ./...
