# Contributing to Titus

Thank you for your interest in contributing to Titus, a high-performance secrets detection tool by Praetorian. Titus is a Go port of NoseyParker and includes a Burp Suite extension (Java/Gradle) and a Chrome browser extension (WASM/JS).

We welcome contributions of all kinds -- bug reports, feature requests, documentation improvements, and code changes.

## Reporting Bugs

If you find a bug, please open a [GitHub Issue](https://github.com/praetorian-inc/titus/issues) with the following information:

- A clear, descriptive title
- Steps to reproduce the problem
- Expected behavior vs. actual behavior
- Your environment (OS, Go version, etc.)
- Any relevant log output or error messages

## Suggesting Features

Feature requests are tracked as [GitHub Issues](https://github.com/praetorian-inc/titus/issues). When suggesting a feature, please include:

- A clear description of the problem the feature would solve
- Your proposed solution or approach
- Any alternatives you have considered

## Development Setup

### Prerequisites

- **Go 1.24+**
- **make**
- For the Burp extension: JDK and Gradle
- For the Chrome extension: Node.js and npm

### Building

```bash
# Build the CLI (output to dist/titus)
make build

# Build a static binary
make build-static
```

### Testing

```bash
make test
```

### Burp Suite Extension

```bash
cd burp
./gradlew build
```

### Chrome Extension

```bash
cd chrome-extension
npm install
npm run build
```

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. **Make your changes** in the feature branch.
3. **Add or update tests** to cover your changes.
4. **Ensure all tests pass** by running `make test`.
5. **Push** your branch to your fork.
6. **Open a Pull Request** against `main` with a clear description of your changes.

A maintainer will review your PR and may request changes. Once approved, a maintainer will merge it.

### PR Guidelines

- Keep pull requests focused on a single change.
- Write clear commit messages that explain the "why" behind the change.
- Reference any related issues in the PR description (e.g., "Fixes #42").

## Code Style

- Run `go fmt` on all Go code before committing.
- Run `go vet` to catch common issues.
- Follow standard Go conventions and idioms.
- Keep functions short and well-named.
- Add comments for exported types and functions.

## Testing Expectations

- All new features should include tests.
- Bug fixes should include a test that reproduces the issue.
- Aim to maintain or improve overall test coverage.
- Tests should be deterministic and not depend on external services.

## License

Titus is licensed under the [Apache License 2.0](LICENSE). By contributing to this project, you agree that your contributions will be licensed under the same license.
