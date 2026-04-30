NAME    := wazuh-cli
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
OSES    := linux darwin

.PHONY: build clean install lint test

build:
	@mkdir -p build
	@for os in $(OSES); do \
		out=build/$$os-amd64/$(NAME); \
		echo "Building $$out..."; \
		GOOS=$$os GOARCH=amd64 go build $(LDFLAGS) -o $$out .; \
	done

install:
	go install $(LDFLAGS) .

clean:
	rm -rf build/

lint:
	golangci-lint run ./...

test:
	go test ./...
