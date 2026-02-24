# Contributing to pakery

Thank you for considering contributing to pakery!

## Getting started

1. Fork the repository and clone it locally
2. Install Rust 1.79+ via [rustup](https://rustup.rs/)
3. Run the test suite to make sure everything works:

```bash
cargo test --workspace --all-features
```

## Development workflow

### Running checks locally

Before submitting a PR, run the full CI suite locally:

```bash
# Build
cargo check --workspace --all-features

# Tests
cargo test --workspace --all-features

# Linting
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Formatting
cargo fmt --all -- --check

# Documentation
RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --all-features --no-deps
```

### Project structure

| Crate | Description |
|-------|-------------|
| `pakery-core` | Shared cryptographic traits (`Hash`, `Kdf`, `Mac`, `CpaceGroup`, `DhGroup`, `Oprf`, `Ksf`) |
| `pakery-cpace` | CPace balanced PAKE (draft-irtf-cfrg-cpace) |
| `pakery-opaque` | OPAQUE augmented PAKE (RFC 9807) |
| `pakery-spake2` | SPAKE2 balanced PAKE (RFC 9382) |
| `pakery-spake2plus` | SPAKE2+ augmented PAKE (RFC 9383) |
| `pakery-crypto` | Concrete crypto implementations (Ristretto255, P-256) |
| `pakery-tests` | Integration tests with RFC test vectors |

### Key conventions

- Protocol crates depend only on `pakery-core` traits, never on concrete crypto
- All crates use `#![forbid(unsafe_code)]`
- All public API changes must maintain `no_std` compatibility
- Test against RFC test vectors where available
- Commit messages: `feat(crate): description`, `fix(crate): description`

## Submitting changes

1. Create a branch from `main`
2. Make your changes with clear, focused commits
3. Ensure all CI checks pass locally (see above)
4. Open a pull request against `main`

## Reporting security issues

If you discover a security vulnerability, please **do not** open a public issue. Instead, report it privately via GitHub's [security advisory](https://github.com/djx-y-z/pakery/security/advisories/new) feature.

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project: MIT OR Apache-2.0.
