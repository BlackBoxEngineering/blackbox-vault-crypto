# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report privately to: **security@blackboxengineering.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix

You will receive an acknowledgement within 48 hours. We aim to release a fix within 14 days of a confirmed report.

## Scope

This package implements:
- Multi-round PBKDF2-HMAC-SHA256 key derivation
- AES-256-GCM authenticated encryption
- HMAC-SHA256 payload authentication
- CSPRNG via `crypto.getRandomValues`

All cryptographic operations use the browser/Node.js **Web Crypto API** (`crypto.subtle`). No third-party crypto dependencies.

## Security Model

- Passphrases are never stored or transmitted
- Each encryption call generates a fresh random 32-byte salt and 12-byte IV
- The HMAC covers the full payload including KDF parameters — tampering with any byte fails authentication
- Constant-time comparison is used for HMAC verification to prevent timing attacks
- Wrong passphrase causes AES-GCM authentication tag failure — nothing leaks about the plaintext

## Out of Scope

- Side-channel attacks against the underlying Web Crypto API implementation
- Physical access to the device
- Passphrase strength — callers are responsible for enforcing strong passphrases
