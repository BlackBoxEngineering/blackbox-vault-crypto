# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-10

### Added
- `SecureCipher` — high-level encrypt/decrypt with multi-round PBKDF2 + AES-GCM + HMAC-SHA256
- `KDF` — multi-round PBKDF2-HMAC-SHA256 key derivation (120k initial + 3×80k chained rounds)
- `AEAD` — low-level AES-256-GCM encrypt/decrypt
- `CSPRNG` — `crypto.getRandomValues` wrapper
- Full TypeScript declarations
- Test suite (vitest)
- GitHub Actions CI
