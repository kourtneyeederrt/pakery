feat: prepare workspace for crates.io publication

Rename all crates from pake-* to pakery-* to avoid name conflicts
on crates.io (pake-cpace was already taken).

Crate rename:
- pake-core → pakery-core
- pake-cpace → pakery-cpace
- pake-opaque → pakery-opaque
- pake-spake2 → pakery-spake2
- pake-spake2plus → pakery-spake2plus
- pake-crypto → pakery-crypto
- pake-tests → pakery-tests

Publication metadata:
- Add authors, readme, documentation, keywords, categories to all crates
- Add version field to all inter-crate path dependencies
- Mark pakery-tests as publish = false
- Update repository URL to github.com/djx-y-z/pakery
- Remove Cargo.lock from .gitignore and commit it

Documentation:
- Add workspace README.md with architecture diagram and examples
- Add per-crate README.md files (6 crates)
- Add CHANGELOG.md (Keep a Changelog format)
- Add CONTRIBUTING.md

CI/CD:
- Add ci.yml (check, test, clippy, fmt, doc, msrv, no-std, wasm,
  feature-combinations, minimal-versions)
- Add audit.yml (RustSec security audit, weekly schedule)
- Add publish.yml (tag-triggered publish with environment approval)
- Add dependabot.yml (automated dependency update PRs)

Code fixes:
- Fix cargo fmt across workspace
- Fix clippy identity_op warning in pakery-spake2
- Fix clippy too_many_arguments in pakery-tests
- Fix broken intra-doc link in pakery-cpace
