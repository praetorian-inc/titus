# Titus Makefile
# Build automation for secrets scanner

.PHONY: all build build-pure build-static build-wasm build-extension test vet lint clean integration-test static-test build-burp install-burp clean-burp clean-extension check-vectorscan

VERSION ?= dev
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

# Vectorscan/Hyperscan acceleration (default: enabled)
# Override with CGO_ENABLED=0 or make build-pure for pure-Go fallback
CGO_ENABLED ?= 1
GO_TAGS ?= vectorscan

# Build -tags flag (empty when GO_TAGS is empty to avoid bare "-tags" argument)
ifneq ($(GO_TAGS),)
  TAGS_FLAG := -tags $(GO_TAGS)
else
  TAGS_FLAG :=
endif

# Auto-detect vectorscan pkg-config path on macOS (Homebrew)
VECTORSCAN_PREFIX := $(shell brew --prefix vectorscan 2>/dev/null)
ifneq ($(VECTORSCAN_PREFIX),)
  export PKG_CONFIG_PATH := $(VECTORSCAN_PREFIX)/lib/pkgconfig:$(PKG_CONFIG_PATH)
endif

# Detect whether vectorscan is available for the build
VECTORSCAN_AVAILABLE := $(shell pkg-config --exists libhs 2>/dev/null && echo 1 || echo 0)

# Determine if the vectorscan check is needed for this build
ifeq ($(CGO_ENABLED),1)
  ifneq ($(findstring vectorscan,$(GO_TAGS)),)
    BUILD_NEEDS_VECTORSCAN := 1
  endif
endif

# Default target
all: build test vet

# Build the project (with Vectorscan/Hyperscan acceleration by default)
ifdef BUILD_NEEDS_VECTORSCAN
BUILD_DEPS := check-vectorscan
else
BUILD_DEPS :=
endif

build: $(BUILD_DEPS)
	@mkdir -p dist
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) $(LDFLAGS) -o dist/titus ./cmd/titus

# Check vectorscan/hyperscan availability and attempt auto-install if missing
check-vectorscan:
ifeq ($(VECTORSCAN_AVAILABLE),0)
	@echo ""
	@echo "=== Vectorscan/Hyperscan not found ==="
	@echo ""
	@echo "Attempting to install automatically..."
	@if [ "$$(uname)" = "Darwin" ]; then \
		brew install vectorscan && \
		export PKG_CONFIG_PATH="$$(brew --prefix vectorscan)/lib/pkgconfig:$$PKG_CONFIG_PATH" && \
		echo "[vectorscan] Installed successfully via Homebrew" || \
		(echo "" && \
		echo "Vectorscan is required for the default build (10-100x faster scanning)." && \
		echo "Install it manually:" && \
		echo "" && \
		echo "  macOS (Homebrew):  brew install vectorscan" && \
		echo "  Ubuntu/Debian:     sudo apt-get install libhyperscan-dev" && \
		echo "  Fedora/RHEL:       sudo dnf install hyperscan-devel" && \
		echo "" && \
		echo "Or build without vectorscan (slower, but no dependencies):" && \
		echo "  make build-pure" && \
		echo "" && \
		exit 1); \
	else \
		sudo apt-get install -y libhyperscan-dev && \
		echo "[vectorscan] Installed successfully via apt-get" || \
		(echo "" && \
		echo "Vectorscan is required for the default build (10-100x faster scanning)." && \
		echo "Install it manually:" && \
		echo "" && \
		echo "  macOS (Homebrew):  brew install vectorscan" && \
		echo "  Ubuntu/Debian:     sudo apt-get install libhyperscan-dev" && \
		echo "  Fedora/RHEL:       sudo dnf install hyperscan-devel" && \
		echo "" && \
		echo "Or build without vectorscan (slower, but no dependencies):" && \
		echo "  make build-pure" && \
		echo "" && \
		exit 1); \
	fi
else
	@echo "[vectorscan] Found hyperscan via pkg-config"
endif

# Build pure-Go binary (no CGO, no Vectorscan — portable fallback)
build-pure:
	@mkdir -p dist
	GOWORK=off CGO_ENABLED=0 go build $(LDFLAGS) -o dist/titus ./cmd/titus

# Build statically linked binary (pure Go, no CGO required)
build-static:
	@mkdir -p dist
	GOWORK=off CGO_ENABLED=0 go build \
		$(LDFLAGS) \
		-o dist/titus-static ./cmd/titus

# Build WASM binary for browser extension
build-wasm:
	GOWORK=off GOOS=js GOARCH=wasm go build -o extension/lib/titus.wasm ./wasm
	@echo "Built extension/lib/titus.wasm"

# Build browser extension (builds WASM first)
build-extension: build-wasm
	@echo ""
	@echo "=== Browser Extension Build Complete ==="
	@echo "Extension directory: extension/"
	@echo ""
	@echo "To install in Chrome:"
	@echo "  1. Go to chrome://extensions/"
	@echo "  2. Enable Developer mode"
	@echo "  3. Click 'Load unpacked'"
	@echo "  4. Select the 'extension' directory"
	@echo ""

# Run unit tests
test:
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) go test $(TAGS_FLAG) -v ./...

# Run integration tests
integration-test: build
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) go test -tags "integration $(GO_TAGS)" -v ./tests/integration/...

# Run go vet
vet:
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) go vet $(TAGS_FLAG) ./...

# Run staticcheck (optional)
lint:
	@which staticcheck > /dev/null || (echo "staticcheck not installed" && exit 0)
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) staticcheck $(TAGS_FLAG) ./...

# Install titus binary to ~/.titus/ for Burp extension
install:
	@mkdir -p ~/.titus
	cp dist/titus ~/.titus/titus
	chmod +x ~/.titus/titus
	@echo "Installed titus to ~/.titus/titus"

# Build Burp extension JAR (builds titus binary first)
build-burp: build
	cd burp && ./gradlew shadowJar
	@mkdir -p dist
	cp burp/build/libs/titus-burp-*-all.jar dist/
	@echo ""
	@echo "=== Burp Extension Build Complete ==="
	@echo "Extension JAR: dist/titus-burp-1.0.0-all.jar"
	@echo ""
	@echo "To install:"
	@echo "  1. Run 'make install' to copy titus binary to ~/.titus/"
	@echo "  2. Load the JAR in Burp Suite (Extensions → Add)"
	@echo ""

# Build and install Burp extension (one command to rule them all)
install-burp: build-burp install
	@echo ""
	@echo "=== Installation Complete ==="
	@echo "Binary:    ~/.titus/titus"
	@echo "Extension: dist/titus-burp-1.0.0-all.jar"
	@echo ""
	@echo "Load the JAR in Burp Suite (Extensions → Add)"

# Clean build artifacts
clean:
	rm -f titus titus-static
	rm -f titus.db
	rm -rf dist/

# Clean Burp artifacts
clean-burp:
	rm -rf burp/build
	rm -f burp/src/main/resources/titus

# Clean browser extension artifacts
clean-extension:
	rm -f extension/lib/titus.wasm

# Clean everything
clean-all: clean clean-burp clean-extension

# Run static binary test in container (requires build-static and docker)
static-test: build-static
	./scripts/static-binary-test.sh
