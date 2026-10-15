BINARY := pwnflow
BUILD_DIR := bin
PREFIX ?= /usr/local
VERSION ?= 0.1.0
GO ?= go

GOFLAGS ?=
LDFLAGS := -s -w -X main.version=$(VERSION)
TARGET := $(BUILD_DIR)/$(BINARY)

.PHONY: all build run test vet check clean install uninstall deps help

all: build

build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(TARGET) ./cmd/pwnflow
	@echo "Built $(TARGET) ($(VERSION))"

run:
	$(GO) run ./cmd/pwnflow $(ARGS)

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

check: test vet

clean:
	rm -rf $(BUILD_DIR)

install: build
	install -d $(PREFIX)/bin
	install -m 0755 $(TARGET) $(PREFIX)/bin/$(BINARY)
	install -d $(PREFIX)/share/pwnflow/scripts
	install -m 0755 scripts/install.sh $(PREFIX)/share/pwnflow/scripts/install.sh
	@echo "Installed $(PREFIX)/bin/$(BINARY)"

uninstall:
	rm -f $(PREFIX)/bin/$(BINARY)
	rm -f $(PREFIX)/share/pwnflow/scripts/install.sh
	@echo "Removed $(PREFIX)/bin/$(BINARY)"

deps:
	$(GO) mod download

help:
	@printf '%s\n' \
		"Usage: make [target]" \
		"" \
		"build       Compile PwnFlow into bin/pwnflow" \
		"run         Run PwnFlow; pass arguments with ARGS=\"...\"" \
		"test        Run unit tests" \
		"vet         Run go vet" \
		"check       Run tests and vet" \
		"clean       Remove generated build artifacts" \
		"install     Install the binary under PREFIX/bin" \
		"uninstall   Remove the locally installed binary" \
		"deps        Download Go module dependencies" \
		"help        Show this help"
