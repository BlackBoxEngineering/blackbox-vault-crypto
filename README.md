# blackbox-vault-crypto

Standalone vault crypto primitives extracted from [BlackBox Wallet](https://github.com/BlackBoxEngineering/blackboxwallet).

Pure Web Crypto API. Zero dependencies. MIT licensed.

[![CI](https://github.com/BlackBoxEngineering/blackbox-vault-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/BlackBoxEngineering/blackbox-vault-crypto/actions/workflows/ci.yml)

## Install

```bash
npm install blackbox-vault-crypto
```

**Requires Node.js 18 or later.**

In browsers, `crypto.subtle` is only available in [secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts) (HTTPS or `localhost`). This package will throw if `crypto.subtle` is unavailable.

## Quick start

```js
import { SecureCipher } from 'blackbox-vault-crypto';

// Encrypt — passphrase never leaves the device
const ciphertext = await SecureCipher.encrypt('my secret', 'my-passphrase-123');

// Decrypt — wrong passphrase throws, nothing leaks
const plaintext = await SecureCipher.decrypt(ciphertext, 'my-passphrase-123');
```

Each `encrypt` call generates a fresh random 32-byte salt and 12-byte IV. The same plaintext + passphrase produces a different ciphertext every time.

## API

### `SecureCipher`

High-level vault encrypt/decrypt. This is the main export most callers need.

```js
import { SecureCipher } from 'blackbox-vault-crypto';

// Encrypt a string
const ciphertext = await SecureCipher.encrypt(message, passphrase);

// Decrypt
const plaintext = await SecureCipher.decrypt(ciphertext, passphrase);

// Inspect the envelope without decrypting
const decoded = SecureCipher.decodeCiphertext(ciphertext);
// { version, salt, kdfParams, iv, ciphertextPart, tag, hmac, ... }

// Check version byte without decrypting
const version = SecureCipher.getCipherVersion(ciphertext); // 3 | null

// Constant-time comparison (use for HMAC verification)
SecureCipher.constantTimeEqual(a, b); // boolean
```

Passphrase must be 8–128 characters. Wrong passphrase → `Authentication failed`. Tampered ciphertext → `Authentication failed`.

### `KDF`

Multi-round PBKDF2-HMAC-SHA256 key derivation. 120,000 initial iterations + 3 chained rounds of 80,000.

```js
import { KDF } from 'blackbox-vault-crypto';

// Standard multi-round derivation (recommended)
const masterKey = await KDF.multiRoundPBKDF2(passphrase, salt);

// Explicit params
const masterKey = await KDF.multiRoundPBKDF2WithParams(passphrase, salt, 120000, 80000);

// Single-round (lower level)
const key = await KDF.pbkdf2(passphrase, salt, iterations);

// Default params used by SecureCipher
console.log(KDF.KDF_PARAMS_V3);
// { algorithmId: 1, iterations: 120000, memoryCost: 0, cpuCost: 80000, parallelism: 1 }
```

Salt must be at least 16 bytes. Use `CSPRNG.getRandomBytes(32)` to generate one.

### `AEAD`

Low-level AES-256-GCM encrypt/decrypt. Key must be a 32-byte `Uint8Array`.

```js
import { AEAD } from 'blackbox-vault-crypto';

const key = new Uint8Array(32); // use a derived key, not zeros
const ciphertext = await AEAD.encryptAESGCM('plaintext', key); // base64
const plaintext = await AEAD.decryptAESGCM(ciphertext, key);
```

### `CSPRNG`

`crypto.getRandomValues` wrapper with input validation.

```js
import { CSPRNG } from 'blackbox-vault-crypto';

const salt = CSPRNG.getRandomBytes(32);  // Uint8Array
const n = CSPRNG.getRandomInt(256);      // integer in [0, 256)
```

## Security model

- Passphrase → multi-round PBKDF2 (120k + 3×80k rounds) → master key
- HKDF split → `encKey` + `hmacKey`
- AES-256-GCM encrypt with fresh random IV
- HMAC-SHA256 over the full payload including KDF parameters
- Constant-time HMAC comparison prevents timing attacks
- Wrong passphrase → AES-GCM auth tag failure → nothing leaks

This is the same pattern used by BlackBox Wallet to protect vault roots locally. The passphrase never leaves the device. There is no server, no reset vector, and no credential to steal.

## Compatibility

| Environment | Support |
|---|---|
| Node.js 18+ | ✅ |
| Node.js 20+ | ✅ |
| Node.js 22+ | ✅ |
| Modern browsers (HTTPS / localhost) | ✅ |
| HTTP (non-secure context) | ❌ `crypto.subtle` unavailable |
| Node.js < 18 | ❌ |

## License

[MIT](LICENSE) — extracted from [BlackBox Wallet](https://github.com/BlackBoxEngineering/blackboxwallet).
