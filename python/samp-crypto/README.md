# samp-crypto

Native crypto backend for [`samp-core`](https://pypi.org/project/samp-core/), the Python SDK for the Substrate Account Messaging Protocol (SAMP).

This package exposes the SAMP cryptographic primitives — sr25519 key agreement, HKDF-SHA256 key derivation, and ChaCha20-Poly1305 sealing — as a compiled extension module built with [PyO3](https://pyo3.rs) and [maturin](https://www.maturin.rs). It is not meant to be used directly; install `samp-core` instead.

## Install

```
pip install samp-core
```

`samp-crypto` is pulled in automatically as a dependency.

## What it provides

A single extension module, `samp_crypto`, with stateless functions covering:

- sr25519 key derivation from a 32-byte seed
- Sealed message encryption to a recipient public key (per the SAMP capsule format)
- Group capsule wrapping and unwrapping
- View-tag derivation for inbox scanning

The protocol details are specified in the [SAMP specification](https://github.com/samp-org/samp/blob/main/specs/samp.md).

## Supported platforms

Wheels are published for:

- CPython 3.9+ on Linux (x86_64, aarch64), macOS (x86_64, arm64), and Windows (x86_64)

A source distribution is also published; building from source requires a stable Rust toolchain.

## License

MIT. See the repository [LICENSE](https://github.com/samp-org/samp/blob/main/LICENSE).
