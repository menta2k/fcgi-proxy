# Contributing to fcgi-proxy

Thank you for considering contributing to fcgi-proxy.

## How to Contribute

1. **Fork** the repository
2. **Create a branch** from `main` for your change
3. **Write tests** for any new functionality
4. **Run the test suite** before submitting:
   ```bash
   go build ./...
   go vet ./...
   go test -race -cover ./...
   ```
5. **Open a Pull Request** against `main`

## Pull Request Requirements

- All CI checks must pass (tests, CodeQL)
- At least one approving review is required
- Code coverage should not decrease
- Follow existing code style and patterns

## Reporting Bugs

Open a [GitHub issue](https://github.com/menta2k/fcgi-proxy/issues) with:
- Steps to reproduce
- Expected vs actual behavior
- Go version and OS

## Security Vulnerabilities

Do **not** open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Code Style

- Run `go vet` and `go build` with no warnings
- Follow idiomatic Go patterns
- Keep functions small and focused
- Add tests for new functionality

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
