# Titus Makefile
# Build automation for secrets scanner

.PHONY: all build build-static build-wasm build-extension test vet lint clean integration-test static-test build-burp install-burp clean-burp clean-extension

# Default target
all: build test vet

# Build the project (pure Go, no CGO)
build:
	@mkdir -p dist
	GOWORK=off CGO_ENABLED=0 go build -o dist/titus ./cmd/titus

# Build statically linked binary (pure Go, no CGO required)
build-static:
	@mkdir -p dist
	GOWORK=off CGO_ENABLED=0 go build \
		-ldflags '-s -w' \
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
	GOWORK=off go test -v ./...

# Run integration tests
integration-test: build
	GOWORK=off go test -tags=integration -v ./tests/integration/...

# Run go vet
vet:
	GOWORK=off go vet ./...

# Run staticcheck (optional)
lint:
	@which staticcheck > /dev/null || (echo "staticcheck not installed" && exit 0)
	GOWORK=off staticcheck ./...

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
