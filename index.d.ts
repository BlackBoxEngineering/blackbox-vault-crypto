// blackbox-vault-crypto — type declarations

export interface KdfParams {
  algorithmId: number;
  iterations: number;
  memoryCost: number;
  cpuCost: number;
  parallelism: number;
}

export interface DerivedKeys {
  encKey: Uint8Array;
  hmacKey: Uint8Array;
}

export interface DecodedCiphertext {
  version: number;
  salt: Uint8Array;
  payload: Uint8Array;
  hmac: Uint8Array;
  encryptedData: Uint8Array;
  iv: Uint8Array | null;
  ciphertextPart: Uint8Array | null;
  tag: Uint8Array | null;
  kdfParams: KdfParams | null;
}

export declare const SecureCipher: {
  /** Encrypt a string with a passphrase. Returns base64 ciphertext. */
  encrypt(message: string, passphrase: string): Promise<string>;
  /** Decrypt base64 ciphertext with a passphrase. Throws on wrong passphrase or tampered data. */
  decrypt(ciphertext: string, passphrase: string): Promise<string>;
  /** Derive encKey + hmacKey from a passphrase and salt. */
  deriveKeys(passphrase: string, salt: Uint8Array, version?: number, kdfParams?: KdfParams | null): Promise<DerivedKeys>;
  /** Compute HMAC-SHA256 over data with key. */
  computeHMAC(data: Uint8Array, key: Uint8Array): Promise<Uint8Array>;
  /** HKDF-expand key with info to length bytes. */
  hkdfExpand(key: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>;
  /** Constant-time byte array comparison. */
  constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean;
  /** Decode a ciphertext envelope without decrypting. */
  decodeCiphertext(ciphertext: string): DecodedCiphertext;
  /** Return the cipher version byte, or null if invalid. */
  getCipherVersion(ciphertext: string): number | null;
  readonly VERSION: number;
  readonly LEGACY_VERSION: number;
};

export declare const KDF: {
  pbkdf2(passphrase: string, salt: Uint8Array, iterations?: number): Promise<Uint8Array>;
  multiRoundPBKDF2(passphrase: string, saltBytes: Uint8Array): Promise<Uint8Array>;
  multiRoundPBKDF2WithParams(passphrase: string, saltBytes: Uint8Array, initialIterations: number, roundIterations: number): Promise<Uint8Array>;
  multiRoundPBKDF2Legacy(passphrase: string, saltBytes: Uint8Array, initialIterations?: number, roundIterations?: number): Promise<Uint8Array>;
  generateIterations(base?: number): number;
  getLegacyIterationsForTimestamp(timestampMs: number): { initialIterations: number; roundIterations: number };
  getLegacyIterationCandidates(lookbackHours?: number): Array<{ initialIterations: number; roundIterations: number }>;
  readonly KDF_PARAMS_V3: Readonly<KdfParams>;
  readonly KDF_ALGORITHM_REGISTRY: Readonly<Record<number, string>>;
  readonly KDF_ALGO_PBKDF2_MULTIROUND_SHA256: number;
  readonly KDF_ALGO_SCRYPT: number;
  readonly KDF_ALGO_ARGON2ID: number;
  _testMinIterations: number | null;
};

export declare const AEAD: {
  /** AES-GCM encrypt plaintext string with a 32-byte key. Returns base64. */
  encryptAESGCM(plaintext: string, key: Uint8Array): Promise<string>;
  /** AES-GCM decrypt base64 ciphertext with a 32-byte key. */
  decryptAESGCM(ciphertext: string, key: Uint8Array): Promise<string>;
};

export declare const CSPRNG: {
  /** Generate cryptographically random bytes. */
  getRandomBytes(length: number): Uint8Array;
  /** Generate a cryptographically random integer in [0, max). */
  getRandomInt(max: number): number;
};
