# Titus Makefile
# Build automation for secrets scanner

.PHONY: all build build-static test vet lint clean integration-test static-test build-wasm test-wasm serve-wasm clean-wasm build-wasi test-wasi build-burp clean-burp

# Default target
all: build test vet

# Build the project (dynamic linking)
build:
	CGO_ENABLED=1 go build -o titus ./cmd/titus

# Build statically linked binary (for container deployment)
# Requires musl-gcc: apt-get install musl-dev musl-tools
build-static:
	CGO_ENABLED=1 CC=musl-gcc go build \
		-ldflags '-linkmode external -extldflags "-static"' \
		-tags 'osusergo netgo sqlite_omit_load_extension' \
		-o titus-static ./cmd/titus

# Run unit tests
test:
	go test -v ./...

# Run go vet
vet:
	go vet ./...

# Run staticcheck (optional)
lint:
	@which staticcheck > /dev/null || (echo "staticcheck not installed" && exit 0)
	staticcheck ./...

# Build WASM binary and copy JS files to dist/
build-wasm:
	@mkdir -p dist
	GOWORK=off GOOS=js GOARCH=wasm go build -o dist/titus.wasm ./wasm
	cp wasm/titus.js dist/
	@if [ -f "$$(go env GOROOT)/lib/wasm/wasm_exec.js" ]; then \
		cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" dist/; \
	elif [ -f "$$(go env GOROOT)/misc/wasm/wasm_exec.js" ]; then \
		cp "$$(go env GOROOT)/misc/wasm/wasm_exec.js" dist/; \
	else \
		echo "Error: wasm_exec.js not found"; exit 1; \
	fi
	@echo "WASM build complete. Files in dist/"

# Run tests in WASM mode
test-wasm:
	GOWORK=off GOOS=js GOARCH=wasm go test -v ./pkg/matcher ./pkg/store

# Serve WASM files for browser testing
serve-wasm: build-wasm
	@echo "Serving WASM at http://localhost:8080"
	@echo "Test page: dist/test.html"
	cd dist && python3 -m http.server 8080

# Clean build artifacts
clean:
	rm -f titus titus-static
	rm -f titus.db
	rm -rf dist/

# Clean WASM artifacts only
clean-wasm:
	rm -rf dist/

# Run integration tests (requires build)
integration-test: build
	./scripts/integration-test.sh

# Run static binary test in container (requires build-static and docker)
static-test: build-static
	./scripts/static-binary-test.sh

# Build WASI target for Chicory/Java runtime
build-wasi:
	@mkdir -p dist
	GOWORK=off GOOS=wasip1 GOARCH=wasm go build -o dist/titus-wasi.wasm ./wasi
	@echo "WASI build complete: dist/titus-wasi.wasm"

# Test WASI target compilation (actual runtime test requires wasmtime or similar)
test-wasi:
	GOWORK=off GOOS=wasip1 GOARCH=wasm go build -o /dev/null ./wasi
	@echo "WASI build test passed"

# Build Burp extension JAR (includes WASM binary)
build-burp: build-wasi
	@mkdir -p burp/src/main/resources
	cp dist/titus-wasi.wasm burp/src/main/resources/titus.wasm
	cd burp && ./gradlew shadowJar
	@mkdir -p dist
	cp burp/build/libs/titus-burp-*-all.jar dist/
	@echo "Burp extension built: dist/titus-burp-*-all.jar"

# Clean Burp artifacts
clean-burp:
	rm -rf burp/build
	rm -f burp/src/main/resources/titus.wasm
