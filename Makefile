# Titus Makefile
# Build automation for secrets scanner

.PHONY: all build build-static test vet lint clean integration-test static-test

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

# Clean build artifacts
clean:
	rm -f titus titus-static
	rm -f titus.db

# Run integration tests (requires build)
integration-test: build
	./scripts/integration-test.sh

# Run static binary test in container (requires build-static and docker)
static-test: build-static
	./scripts/static-binary-test.sh
