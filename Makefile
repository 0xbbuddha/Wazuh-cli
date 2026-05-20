NAME      := wazuh-cli
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -ldflags "-X main.version=$(VERSION)"
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.PHONY: build clean install lint test

build:
	@mkdir -p build
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d/ -f1); \
		arch=$$(echo $$platform | cut -d/ -f2); \
		out=build/$(NAME)-$$os-$$arch; \
		echo "Building $$out ..."; \
		GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o $$out .; \
	done

install:
	go install $(LDFLAGS) .

clean:
	rm -rf build/

lint:
	golangci-lint run ./...

test:
	go test ./...
