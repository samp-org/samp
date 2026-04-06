# Contributing to SAMP

## Contribution types

### Spec changes

Spec changes go to `specs/`. A spec change PR must not include code. Code follows in a separate PR once the spec change is merged.

### Implementation changes

Implementation PRs must reference a specific section of the spec they implement or fix. If the spec does not cover the behavior in question, file a spec change first.

### New implementations

A new language implementation must:
1. Pass all test vectors in `e2e/test-vectors.json`.
2. Live in a top-level directory named after the language (e.g., `go/`).
3. Include a README with build and test instructions.

### New transport bindings

Transport bindings (beyond `system.remark`) go in `specs/transports/` as separate spec files. A reference implementation in at least one language must accompany the spec.

## Process

1. Open an issue describing the change.
2. Fork, branch, implement.
3. Ensure all tests pass (see below).
4. Submit a PR. One approval required.

## Running tests

| Language | Command |
|----------|---------|
| Rust | `cd rust && cargo test` |
| Python | `cd python/samp-crypto && maturin develop && cd .. && pytest` |
| Go | `cd go && go test ./...` |
| TypeScript | `cd typescript && npm test` |

## Code style

- Rust: `rustfmt` defaults. `clippy` clean with no allowed warnings.
- Python: `ruff` for linting, `ruff format` for formatting. Type hints on all public functions.
- Go: `gofmt` defaults. `go vet` clean.
- TypeScript: `prettier` for formatting. Strict TypeScript (`strict: true`).
- All: follow the [writing guide](docs/writing-guide.md) for documentation and comments.

## Test vectors

If your change affects encoding, signing, or encryption, update `e2e/test-vectors.json` using the generator (`cd e2e/generator && cargo run > ../test-vectors.json`) and ensure all implementations pass.
