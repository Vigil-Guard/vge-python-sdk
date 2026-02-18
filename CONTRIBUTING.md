# Contributing to Vigil Guard Python SDK

Thank you for your interest in contributing to the Vigil Guard Python SDK.

## Getting Started

### Development Setup

```bash
git clone https://github.com/Vigil-Guard/python-SDK-vge.git
cd python-SDK-vge
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest -m "not integration and not performance" -v
```

### Linting and Type Checking

```bash
ruff check src/vigil/ tests/
mypy --strict src/vigil/
```

## How to Contribute

### Reporting Bugs

Open a [GitHub issue](https://github.com/Vigil-Guard/python-SDK-vge/issues) with:

- Python version and OS
- SDK version (`pip show vigil-guard`)
- Minimal reproduction steps
- Expected vs actual behavior

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

### Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Write tests for your changes
4. Ensure all tests pass and linters are clean
5. Submit a pull request against `main`

### Pull Request Guidelines

- Keep changes focused — one feature or fix per PR
- Add or update tests (target 80%+ coverage for new code)
- Follow existing code style (enforced by ruff and mypy)
- Update CHANGELOG.md under `[Unreleased]`

## Code Style

- Python 3.9+ compatible syntax
- Type hints on all public APIs (mypy strict mode)
- ruff for linting and formatting
- 100 character line length

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
