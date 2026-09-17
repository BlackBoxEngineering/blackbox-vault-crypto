import { SecureCipher } from '../src/secureCipher.js';
import { AEAD } from '../src/aead.js';
import { KDF } from '../src/kdf.js';
import { CSPRNG } from '../src/csprng.js';

let originalMinIterations = null;

beforeAll(() => {
  originalMinIterations = KDF._testMinIterations;
  KDF._testMinIterations = 50000;
});

afterAll(() => {
  KDF._testMinIterations = originalMinIterations;
});

describe('SecureCipher', () => {
  const message = 'sovereign identity root — treat as private key material';
  const passphrase = 'correct-horse-battery-staple-99!';

  it('encrypts and decrypts correctly', async () => {
    const ciphertext = await SecureCipher.encrypt(message, passphrase);
    const plaintext = await SecureCipher.decrypt(ciphertext, passphrase);
    expect(plaintext).toBe(message);
  });

  it('decodeCiphertext returns correct structure', async () => {
    const ciphertext = await SecureCipher.encrypt(message, passphrase);
    const decoded = SecureCipher.decodeCiphertext(ciphertext);
    expect(decoded.version).toBe(SecureCipher.VERSION);
    expect(decoded.salt.length).toBe(32);
    expect(decoded.kdfParams.algorithmId).toBe(KDF.KDF_ALGO_PBKDF2_MULTIROUND_SHA256);
    expect(decoded.kdfParams.iterations).toBeGreaterThan(0);
    expect(decoded.kdfParams.cpuCost).toBeGreaterThan(0);
    expect(decoded.kdfParams.parallelism).toBeGreaterThan(0);
  });

  it('produces different ciphertext each time', async () => {
    const c1 = await SecureCipher.encrypt(message, passphrase);
    const c2 = await SecureCipher.encrypt(message, passphrase);
    expect(c1).not.toBe(c2);
  });

  it('fails with wrong passphrase', async () => {
    const ciphertext = await SecureCipher.encrypt(message, passphrase);
    await expect(SecureCipher.decrypt(ciphertext, 'wrong-passphrase-99!')).rejects.toThrow('Authentication failed');
  });

  it('rejects passphrase shorter than 8 characters', async () => {
    await expect(SecureCipher.encrypt(message, 'short')).rejects.toThrow(/at least 8/);
  });

  it('rejects passphrase longer than 128 characters', async () => {
    await expect(SecureCipher.encrypt(message, 'a'.repeat(129))).rejects.toThrow(/exceed 128/);
  });

  it('rejects null passphrase', async () => {
    await expect(SecureCipher.encrypt(message, null)).rejects.toThrow();
  });

  it('handles empty message', async () => {
    const ciphertext = await SecureCipher.encrypt('', passphrase);
    const plaintext = await SecureCipher.decrypt(ciphertext, passphrase);
    expect(plaintext).toBe('');
  });

  it('decrypts correctly after clock changes', async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-01-01T10:00:00.000Z'));
      const ciphertext = await SecureCipher.encrypt(message, passphrase);
      vi.setSystemTime(new Date('2026-06-01T18:00:00.000Z'));
      const plaintext = await SecureCipher.decrypt(ciphertext, passphrase);
      expect(plaintext).toBe(message);
    } finally {
      vi.useRealTimers();
    }
  });

  it('fails authentication when payload bytes are tampered', async () => {
    const ciphertext = await SecureCipher.encrypt(message, passphrase);
    const bytes = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
    const ivOffset = 18 + 32 + 1;
    bytes[ivOffset] ^= 0x01;
    const tampered = btoa(String.fromCharCode(...bytes));
    await expect(SecureCipher.decrypt(tampered, passphrase)).rejects.toThrow('Authentication failed');
  });

  it('fails when v3 header KDF params are tampered', async () => {
    const ciphertext = await SecureCipher.encrypt(message, passphrase);
    const bytes = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
    bytes[2] ^= 0x01;
    const tampered = btoa(String.fromCharCode(...bytes));
    await expect(SecureCipher.decrypt(tampered, passphrase)).rejects.toThrow(/Authentication failed|Key derivation failed/);
  });

  it('fails on corrupted v3 salt length', async () => {
    const ciphertext = await SecureCipher.encrypt(message, passphrase);
    const bytes = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
    bytes[16] = 0x00;
    bytes[17] = 0x01;
    const tampered = btoa(String.fromCharCode(...bytes));
    await expect(SecureCipher.decrypt(tampered, passphrase)).rejects.toThrow(/Invalid v3 salt length|Malformed v3 payload/);
  });

  it('encodes multi-byte header integers in big-endian form', async () => {
    const ciphertext = await SecureCipher.encrypt(message, passphrase);
    const bytes = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
    const readU32BE = (off) => (((bytes[off] << 24) >>> 0) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3]) >>> 0;
    const readU16BE = (off) => (((bytes[off] << 8) | bytes[off + 1]) >>> 0);
    const p = KDF.KDF_PARAMS_V3;
    expect(readU32BE(2)).toBe(p.iterations);
    expect(readU32BE(6)).toBe(p.memoryCost);
    expect(readU32BE(10)).toBe(p.cpuCost);
    expect(readU16BE(14)).toBe(p.parallelism);
    expect(readU16BE(16)).toBe(32);
  });

  it('getCipherVersion returns current version', async () => {
    const ciphertext = await SecureCipher.encrypt(message, passphrase);
    expect(SecureCipher.getCipherVersion(ciphertext)).toBe(SecureCipher.VERSION);
  });

  it('getCipherVersion returns null for garbage input', () => {
    expect(SecureCipher.getCipherVersion('not-valid!!!')).toBeNull();
    expect(SecureCipher.getCipherVersion('')).toBeNull();
    expect(SecureCipher.getCipherVersion(null)).toBeNull();
  });

  it('constantTimeEqual returns true for equal arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(SecureCipher.constantTimeEqual(a, b)).toBe(true);
  });

  it('constantTimeEqual returns false for different arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const c = new Uint8Array([1, 2, 3, 5]);
    expect(SecureCipher.constantTimeEqual(a, c)).toBe(false);
  });

  it('constantTimeEqual returns false for different lengths', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(SecureCipher.constantTimeEqual(a, b)).toBe(false);
  });
});

describe('AEAD', () => {
  const key = new Uint8Array(32).fill(42);
  const plaintext = 'secret message';

  it('encrypts and decrypts correctly', async () => {
    const ciphertext = await AEAD.encryptAESGCM(plaintext, key);
    const decrypted = await AEAD.decryptAESGCM(ciphertext, key);
    expect(decrypted).toBe(plaintext);
  });

  it('produces different ciphertext each time', async () => {
    const c1 = await AEAD.encryptAESGCM(plaintext, key);
    const c2 = await AEAD.encryptAESGCM(plaintext, key);
    expect(c1).not.toBe(c2);
  });

  it('fails with wrong key', async () => {
    const ciphertext = await AEAD.encryptAESGCM(plaintext, key);
    const wrongKey = new Uint8Array(32).fill(99);
    await expect(AEAD.decryptAESGCM(ciphertext, wrongKey)).rejects.toThrow();
  });

  it('rejects non-32-byte key', async () => {
    await expect(AEAD.encryptAESGCM(plaintext, new Uint8Array(16))).rejects.toThrow(/32-byte/);
  });

  it('handles empty plaintext', async () => {
    const ciphertext = await AEAD.encryptAESGCM('', key);
    const decrypted = await AEAD.decryptAESGCM(ciphertext, key);
    expect(decrypted).toBe('');
  });

  it('rejects null plaintext', async () => {
    await expect(AEAD.encryptAESGCM(null, key)).rejects.toThrow();
  });
});

describe('KDF', () => {
  const passphrase = 'TestPassphrase123!';
  const salt = new Uint8Array(32).fill(1);

  it('derives consistent keys with same inputs', async () => {
    const iterations = KDF.generateIterations(100000);
    const k1 = await KDF.pbkdf2(passphrase, salt, iterations);
    const k2 = await KDF.pbkdf2(passphrase, salt, iterations);
    expect(k1).toEqual(k2);
  });

  it('derives different keys with different passphrases', async () => {
    const iterations = KDF.generateIterations(100000);
    const k1 = await KDF.pbkdf2('passphrase-one', salt, iterations);
    const k2 = await KDF.pbkdf2('passphrase-two', salt, iterations);
    expect(k1).not.toEqual(k2);
  });

  it('derives different keys with different salts', async () => {
    const iterations = KDF.generateIterations(100000);
    const salt2 = new Uint8Array(32).fill(2);
    const k1 = await KDF.pbkdf2(passphrase, salt, iterations);
    const k2 = await KDF.pbkdf2(passphrase, salt2, iterations);
    expect(k1).not.toEqual(k2);
  });

  it('always derives 32-byte keys', async () => {
    const iterations = KDF.generateIterations(100000);
    const key = await KDF.pbkdf2(passphrase, salt, iterations);
    expect(key.length).toBe(32);
  });

  it('rejects salt shorter than 16 bytes', async () => {
    await expect(KDF.multiRoundPBKDF2(passphrase, new Uint8Array(8))).rejects.toThrow(/at least 16/);
  });

  it('multiRoundPBKDF2WithParams is deterministic', async () => {
    const p = KDF.KDF_PARAMS_V3;
    const k1 = await KDF.multiRoundPBKDF2WithParams(passphrase, salt, p.iterations, p.cpuCost);
    const k2 = await KDF.multiRoundPBKDF2WithParams(passphrase, salt, p.iterations, p.cpuCost);
    expect(k1).toEqual(k2);
  });

  it('multiRoundPBKDF2 is stable across clock changes', async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-01-01T10:00:00.000Z'));
      const k1 = await KDF.multiRoundPBKDF2(passphrase, salt);
      vi.setSystemTime(new Date('2026-06-01T18:00:00.000Z'));
      const k2 = await KDF.multiRoundPBKDF2(passphrase, salt);
      expect(k1).toEqual(k2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('KDF_PARAMS_V3 has expected shape', () => {
    const p = KDF.KDF_PARAMS_V3;
    expect(p.algorithmId).toBe(KDF.KDF_ALGO_PBKDF2_MULTIROUND_SHA256);
    expect(p.iterations).toBeGreaterThanOrEqual(100000);
    expect(p.cpuCost).toBeGreaterThanOrEqual(50000);
    expect(p.parallelism).toBe(1);
  });
});

describe('CSPRNG', () => {
  it('generates the requested number of bytes', () => {
    expect(CSPRNG.getRandomBytes(32).length).toBe(32);
    expect(CSPRNG.getRandomBytes(16).length).toBe(16);
  });

  it('generates different bytes each call', () => {
    const b1 = CSPRNG.getRandomBytes(32);
    const b2 = CSPRNG.getRandomBytes(32);
    expect(b1).not.toEqual(b2);
  });

  it('returns a Uint8Array', () => {
    expect(CSPRNG.getRandomBytes(32)).toBeInstanceOf(Uint8Array);
  });

  it('rejects invalid lengths', () => {
    expect(() => CSPRNG.getRandomBytes(0)).toThrow();
    expect(() => CSPRNG.getRandomBytes(-1)).toThrow();
    expect(() => CSPRNG.getRandomBytes(65537)).toThrow();
  });

  it('getRandomInt returns values within range', () => {
    for (let i = 0; i < 100; i++) {
      const n = CSPRNG.getRandomInt(10);
      expect(n).toBeGreaterThanOrEqual(0);
      expect(n).toBeLessThan(10);
    }
  });
});
