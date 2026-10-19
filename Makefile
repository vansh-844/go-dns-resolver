BINARY_NAME := dns-resolver
CMD_PKG     := ./cmd/resolverd
BUILD_DIR   := build
PI_DIR      := build-pi

# Raspberry Pi target. Override on the command line, e.g. `make deploy PI_GOARCH=arm GOARM=7`.
PI_GOARCH ?= arm64
PI_HOST   ?= vansh844@vansh-pi.local
PI_PATH   ?= /home/vansh844/

.PHONY: all build build-pi deploy run test vet fmt fmt-check check capture clean

all: check build

build:
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PKG)

build-pi:
	mkdir -p $(PI_DIR)
	GOOS=linux GOARCH=$(PI_GOARCH) go build -o $(PI_DIR)/$(BINARY_NAME) $(CMD_PKG)

deploy: build-pi
	scp $(PI_DIR)/$(BINARY_NAME) $(PI_HOST):$(PI_PATH)

run:
	go run $(CMD_PKG)

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# Fails if any file is not gofmt-clean (useful in CI).
fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "needs gofmt:"; echo "$$out"; exit 1; fi

check: fmt-check vet test

# Save real responses from a public resolver as test fixtures.
capture:
	go run ./cmd/capture -name example.com -type A
	go run ./cmd/capture -name google.com -type AAAA
	go run ./cmd/capture -name www.github.com -type A
	go run ./cmd/capture -name gmail.com -type MX
	go run ./cmd/capture -name google.com -type TXT
	go run ./cmd/capture -name example.com -type NS
	go run ./cmd/capture -name nonexistent-xyz-12345.com -type A
	go run ./cmd/capture -name example.com -type A -edns -file example.com_A_edns.hex

clean:
	rm -rf $(BUILD_DIR) $(PI_DIR)
