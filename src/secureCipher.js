import { AEAD } from './aead.js';
import { CSPRNG } from './csprng.js';
import { KDF } from './kdf.js';

const LEGACY_VERSION = 2;
const CURRENT_VERSION = 3;
const LEGACY_KDF_LOOKBACK_HOURS = 24;
const HEADER_SALT_LEN = 32;
const HMAC_LEN = 32;
const AES_GCM_TAG_LEN = 16;
const AES_GCM_IV_LEN = 12;
const V3_FIXED_PREFIX_LEN = 1 + 1 + 4 + 4 + 4 + 2 + 2;
const MAX_PARALLELISM = 64;
const MAX_SALT_LEN = 64;
const MAX_IV_LEN = 32;
const MAX_CIPHERTEXT_LEN = 4 * 1024 * 1024;

function validatePassphrase(passphrase) {
	if (!passphrase || typeof passphrase !== 'string') throw new Error('Passphrase must be a non-empty string');
	if (passphrase.length < 8) throw new Error('Passphrase must be at least 8 characters');
	if (passphrase.length > 128) throw new Error('Passphrase must not exceed 128 characters');
}

async function encrypt(message, passphrase) {
	validatePassphrase(passphrase);
	if (message === null || message === undefined) throw new Error('Message cannot be null or undefined');
	if (typeof message !== 'string') throw new Error('Message must be a string');

	try {
		let cryptographicSalt;
		try {
			cryptographicSalt = CSPRNG.getRandomBytes(32);
		} catch (saltError) {
			throw new Error(`Salt generation failed: ${saltError.message || 'Unknown error'}`);
		}

		if (!cryptographicSalt || !(cryptographicSalt instanceof Uint8Array) || cryptographicSalt.length !== 32) {
			throw new Error('Failed to generate valid salt');
		}

		const kdfParams = { ...KDF.KDF_PARAMS_V3 };
		let derivedKeys;
		try {
			derivedKeys = await deriveKeys(passphrase, cryptographicSalt, CURRENT_VERSION, kdfParams);
		} catch (keyError) {
			throw new Error(`Key derivation failed: ${keyError.message || 'Unknown error'}`);
		}
		if (!derivedKeys?.encKey || !derivedKeys.hmacKey) throw new Error('Failed to derive encryption keys');

		const encrypted = await encryptAesGcmRaw(message, derivedKeys.encKey);
		const saltLength = cryptographicSalt.length;
		const ivLength = encrypted.iv.length;
		const ciphertextLength = encrypted.ciphertext.length;
		const tagLength = encrypted.tag.length;
		const payloadLength = V3_FIXED_PREFIX_LEN + saltLength + 1 + ivLength + 4 + ciphertextLength + 1 + tagLength;
		const payload = new Uint8Array(payloadLength);

		let offset = 0;
		payload[offset++] = CURRENT_VERSION;
		payload[offset++] = kdfParams.algorithmId;
		writeUint32BE(payload, offset, kdfParams.iterations); offset += 4;
		writeUint32BE(payload, offset, kdfParams.memoryCost); offset += 4;
		writeUint32BE(payload, offset, kdfParams.cpuCost); offset += 4;
		writeUint16BE(payload, offset, kdfParams.parallelism); offset += 2;
		writeUint16BE(payload, offset, saltLength); offset += 2;
		payload.set(cryptographicSalt, offset); offset += saltLength;
		payload[offset++] = ivLength;
		payload.set(encrypted.iv, offset); offset += ivLength;
		writeUint32BE(payload, offset, ciphertextLength); offset += 4;
		payload.set(encrypted.ciphertext, offset); offset += ciphertextLength;
		payload[offset++] = tagLength;
		payload.set(encrypted.tag, offset);

		const hmac = await computeHMAC(payload, derivedKeys.hmacKey);
		if (!hmac || hmac.length !== 32) throw new Error('Failed to compute HMAC');

		const result = new Uint8Array(payload.length + hmac.length);
		result.set(payload);
		result.set(hmac, payload.length);

		return btoa(String.fromCharCode(...result));
	} catch (error) {
		throw new Error(`Encryption failed: ${error.message || 'Unknown error'}`);
	}
}

async function decrypt(ciphertext, passphrase) {
	if (!ciphertext || typeof ciphertext !== 'string') throw new Error('Ciphertext must be a non-empty string');
	validatePassphrase(passphrase);

	try {
		const envelope = decodeEnvelope(ciphertext);
		const kdfContext = extractKdfContext(envelope.payload, envelope.version);

		let keys = await deriveKeys(passphrase, kdfContext.salt, envelope.version, kdfContext.kdfParams);
		if (!keys?.encKey || !keys.hmacKey) throw new Error('Failed to derive decryption keys');

		let expectedHmac = await computeHMAC(envelope.payload, keys.hmacKey);
		if (!expectedHmac || expectedHmac.length !== 32) throw new Error('Failed to compute expected HMAC');

		if (!constantTimeEqual(envelope.hmac, expectedHmac)) {
			if (envelope.version !== LEGACY_VERSION) throw new Error('Authentication failed');

			const legacyCandidates = KDF.getLegacyIterationCandidates(LEGACY_KDF_LOOKBACK_HOURS);
			let matched = false;
			for (let i = 1; i < legacyCandidates.length; i++) {
				const candidate = legacyCandidates[i];
				const legacyMasterKey = await KDF.multiRoundPBKDF2Legacy(
					passphrase,
					kdfContext.salt,
					candidate.initialIterations,
					candidate.roundIterations
				);
				keys = await deriveKeysFromMasterKey(legacyMasterKey);
				expectedHmac = await computeHMAC(envelope.payload, keys.hmacKey);
				if (constantTimeEqual(envelope.hmac, expectedHmac)) {
					matched = true;
					break;
				}
			}
			if (!matched) throw new Error('Authentication failed');
		}

		const parsedPayload = parseAuthenticatedPayload(envelope.payload, envelope.version, kdfContext);

		let result;
		if (envelope.version === CURRENT_VERSION) {
			result = await decryptAesGcmRaw(parsedPayload.iv, parsedPayload.ciphertextPart, parsedPayload.tag, keys.encKey);
		} else {
			if (parsedPayload.encryptedData.length === 0) throw new Error('No encrypted data found');
			const encrypted = btoa(String.fromCharCode(...parsedPayload.encryptedData));
			result = await AEAD.decryptAESGCM(encrypted, keys.encKey);
		}

		if (typeof result !== 'string') throw new Error('Decryption produced invalid result');
		return result;
	} catch (error) {
		throw new Error(`Decryption failed: ${error.message || 'Unknown error'}`);
	}
}

function decodeEnvelope(ciphertext) {
	let data;
	try {
		data = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
	} catch (base64Error) {
		throw new Error(`Invalid base64 ciphertext: ${base64Error.message || 'Unknown error'}`);
	}

	const minLengthV2 = 1 + HEADER_SALT_LEN + HMAC_LEN;
	if (data.length < minLengthV2) throw new Error('Ciphertext too short');

	const hmac = data.slice(-HMAC_LEN);
	const payload = data.slice(0, -HMAC_LEN);
	const version = payload[0];
	if (version !== LEGACY_VERSION && version !== CURRENT_VERSION) throw new Error(`Unsupported cipher version: ${version}`);
	return { version, payload, hmac };
}

function extractKdfContext(payload, version) {
	if (!(payload instanceof Uint8Array) || payload.length < 1) throw new Error('Invalid ciphertext payload');
	if (version === LEGACY_VERSION) {
		const salt = payload.slice(1, 1 + HEADER_SALT_LEN);
		if (salt.length !== HEADER_SALT_LEN) throw new Error('Invalid salt length');
		return { salt, kdfParams: null, offsetAfterSalt: 1 + HEADER_SALT_LEN };
	}
	if (version !== CURRENT_VERSION) throw new Error(`Unsupported cipher version: ${version}`);
	if (payload.length < V3_FIXED_PREFIX_LEN) throw new Error('Ciphertext too short for v3 header');

	let offset = 0;
	offset += 1;
	const algorithmId = payload[offset++];
	const iterations = readUint32BE(payload, offset); offset += 4;
	const memoryCost = readUint32BE(payload, offset); offset += 4;
	const cpuCost = readUint32BE(payload, offset); offset += 4;
	const parallelism = readUint16BE(payload, offset); offset += 2;
	const saltLength = readUint16BE(payload, offset); offset += 2;

	if (parallelism < 1 || parallelism > MAX_PARALLELISM) throw new Error('Invalid v3 parallelism value');
	if (saltLength < 16 || saltLength > MAX_SALT_LEN) throw new Error('Invalid v3 salt length');
	if (offset + saltLength > payload.length) throw new Error('Malformed v3 payload: salt out of bounds');

	const salt = payload.slice(offset, offset + saltLength);
	return { salt, kdfParams: { algorithmId, iterations, memoryCost, cpuCost, parallelism }, offsetAfterSalt: offset + saltLength };
}

function parseAuthenticatedPayload(payload, version, kdfContext) {
	if (version === LEGACY_VERSION) {
		return { encryptedData: payload.slice(1 + HEADER_SALT_LEN), iv: null, ciphertextPart: null, tag: null };
	}
	if (version !== CURRENT_VERSION) throw new Error(`Unsupported cipher version: ${version}`);

	let offset = Number.isInteger(kdfContext?.offsetAfterSalt) ? kdfContext.offsetAfterSalt : V3_FIXED_PREFIX_LEN + HEADER_SALT_LEN;
	if (offset >= payload.length) throw new Error('Malformed v3 payload: missing IV length');

	const ivLength = payload[offset++];
	if (ivLength < 8 || ivLength > MAX_IV_LEN) throw new Error('Invalid v3 IV length');
	if (offset + ivLength > payload.length) throw new Error('Malformed v3 payload: IV out of bounds');
	const iv = payload.slice(offset, offset + ivLength); offset += ivLength;

	if (offset + 4 > payload.length) throw new Error('Malformed v3 payload: missing ciphertext length');
	const ciphertextLength = readUint32BE(payload, offset); offset += 4;
	if (ciphertextLength > MAX_CIPHERTEXT_LEN) throw new Error('Ciphertext too large');
	if (offset + ciphertextLength > payload.length) throw new Error('Malformed v3 payload: ciphertext out of bounds');
	const ciphertextPart = payload.slice(offset, offset + ciphertextLength); offset += ciphertextLength;

	if (offset >= payload.length) throw new Error('Malformed v3 payload: missing tag length');
	const tagLength = payload[offset++];
	if (tagLength < 12 || tagLength > 32) throw new Error('Invalid v3 tag length');
	if (offset + tagLength !== payload.length) throw new Error('Malformed v3 payload: tag out of bounds');
	const tag = payload.slice(offset, offset + tagLength);

	return { encryptedData: new Uint8Array(0), iv, ciphertextPart, tag };
}

async function deriveKeys(passphrase, salt, version = CURRENT_VERSION, kdfParams = null) {
	try {
		let masterKey;
		if (version === LEGACY_VERSION) {
			masterKey = await KDF.multiRoundPBKDF2Legacy(passphrase, salt);
		} else {
			const algorithmId = Number(kdfParams?.algorithmId);
			const iterations = Number(kdfParams?.iterations);
			const memoryCost = Number(kdfParams?.memoryCost);
			const cpuCost = Number(kdfParams?.cpuCost);
			const parallelism = Number(kdfParams?.parallelism);

			if (!Number.isFinite(algorithmId) || !Number.isFinite(iterations) || !Number.isFinite(memoryCost) || !Number.isFinite(cpuCost) || !Number.isFinite(parallelism)) {
				throw new Error('Missing v3 KDF parameters in ciphertext header');
			}
			if (!KDF.KDF_ALGORITHM_REGISTRY?.[algorithmId]) throw new Error(`Unknown v3 KDF algorithm id: ${algorithmId}`);
			if (algorithmId !== KDF.KDF_ALGO_PBKDF2_MULTIROUND_SHA256) throw new Error(`Unsupported v3 KDF algorithm: ${algorithmId}`);
			if (iterations < 10000 || iterations > 2000000 || cpuCost < 10000 || cpuCost > 2000000 || parallelism < 1 || parallelism > MAX_PARALLELISM || memoryCost < 0 || memoryCost > 0xFFFFFFFF) {
				throw new Error('Invalid v3 KDF parameter values');
			}
			masterKey = await KDF.multiRoundPBKDF2WithParams(passphrase, salt, iterations, cpuCost);
		}
		return await deriveKeysFromMasterKey(masterKey);
	} catch (error) {
		throw new Error(`Key derivation failed: ${error.message || 'Unknown error'}`);
	}
}

async function deriveKeysFromMasterKey(masterKey) {
	if (!masterKey || !(masterKey instanceof Uint8Array) || masterKey.length < 32) throw new Error('Invalid master key derived');
	const encKey = masterKey.slice(0, 32);
	const info = new Uint8Array([0x48, 0x4D, 0x41, 0x43]); // 'HMAC'
	const hmacKey = await hkdfExpand(masterKey, info, 32);
	if (!hmacKey || !(hmacKey instanceof Uint8Array) || hmacKey.length !== 32) throw new Error('Invalid HMAC key derived');
	return { encKey, hmacKey };
}

async function computeHMAC(data, key) {
	if (!data || !key) throw new Error('Invalid HMAC parameters: data and key required');
	const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
	return new Uint8Array(signature);
}

async function hkdfExpand(key, info, length) {
	if (!key || !info || typeof length !== 'number') throw new Error('Invalid HKDF parameters');
	const cryptoKey = await crypto.subtle.importKey('raw', key, 'HKDF', false, ['deriveBits']);
	const salt = new Uint8Array(32);
	const derived = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, cryptoKey, length * 8);
	return new Uint8Array(derived);
}

function constantTimeEqual(a, b) {
	if (!a || !b || typeof a.length !== 'number' || typeof b.length !== 'number') throw new Error('Invalid inputs for constant time comparison');
	if (a.length !== b.length) return false;
	let result = 0;
	for (let i = 0; i < a.length; i++) result |= a[i] ^ b[i];
	return result === 0;
}

async function encryptAesGcmRaw(plaintext, key) {
	if (typeof plaintext !== 'string') throw new Error('Plaintext must be a string');
	if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error('Encryption key must be 32 bytes');
	const iv = CSPRNG.getRandomBytes(AES_GCM_IV_LEN);
	if (!(iv instanceof Uint8Array) || iv.length !== AES_GCM_IV_LEN) throw new Error('Failed to generate AES-GCM IV');
	const cryptoKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
	const plaintextBytes = new TextEncoder().encode(plaintext);
	const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: AES_GCM_TAG_LEN * 8 }, cryptoKey, plaintextBytes);
	const out = new Uint8Array(encrypted);
	if (out.length < AES_GCM_TAG_LEN) throw new Error('AES-GCM output too short');
	return { iv, ciphertext: out.slice(0, out.length - AES_GCM_TAG_LEN), tag: out.slice(out.length - AES_GCM_TAG_LEN) };
}

async function decryptAesGcmRaw(iv, ciphertext, tag, key) {
	if (!(iv instanceof Uint8Array) || iv.length < 8 || iv.length > 32) throw new Error('Invalid AES-GCM IV');
	if (!(ciphertext instanceof Uint8Array)) throw new Error('Invalid AES-GCM ciphertext');
	if (!(tag instanceof Uint8Array) || tag.length < 12 || tag.length > 32) throw new Error('Invalid AES-GCM tag');
	if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error('Decryption key must be 32 bytes');
	const payload = new Uint8Array(ciphertext.length + tag.length);
	payload.set(ciphertext);
	payload.set(tag, ciphertext.length);
	const cryptoKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
	const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: tag.length * 8 }, cryptoKey, payload);
	return new TextDecoder().decode(decrypted);
}

function readUint32BE(buffer, offset) {
	if (!(buffer instanceof Uint8Array) || !Number.isInteger(offset) || offset < 0 || offset + 4 > buffer.length) throw new Error('Invalid readUint32BE parameters');
	return ((buffer[offset] * 0x1000000) + ((buffer[offset + 1] << 16) >>> 0) + (buffer[offset + 2] << 8) + buffer[offset + 3]) >>> 0;
}

function readUint16BE(buffer, offset) {
	if (!(buffer instanceof Uint8Array) || !Number.isInteger(offset) || offset < 0 || offset + 2 > buffer.length) throw new Error('Invalid readUint16BE parameters');
	return ((buffer[offset] << 8) | buffer[offset + 1]) >>> 0;
}

function writeUint32BE(buffer, offset, value) {
	if (!(buffer instanceof Uint8Array) || !Number.isInteger(offset) || offset < 0 || offset + 4 > buffer.length) throw new Error('Invalid writeUint32BE parameters');
	const n = Math.floor(Number(value)) >>> 0;
	buffer[offset] = (n >>> 24) & 0xFF;
	buffer[offset + 1] = (n >>> 16) & 0xFF;
	buffer[offset + 2] = (n >>> 8) & 0xFF;
	buffer[offset + 3] = n & 0xFF;
}

function writeUint16BE(buffer, offset, value) {
	if (!(buffer instanceof Uint8Array) || !Number.isInteger(offset) || offset < 0 || offset + 2 > buffer.length) throw new Error('Invalid writeUint16BE parameters');
	const n = Math.floor(Number(value)) >>> 0;
	buffer[offset] = (n >>> 8) & 0xFF;
	buffer[offset + 1] = n & 0xFF;
}

function decodeCiphertext(ciphertext) {
	const envelope = decodeEnvelope(ciphertext);
	const kdfContext = extractKdfContext(envelope.payload, envelope.version);
	const parsedPayload = parseAuthenticatedPayload(envelope.payload, envelope.version, kdfContext);
	return {
		version: envelope.version,
		salt: kdfContext.salt,
		payload: envelope.payload,
		hmac: envelope.hmac,
		encryptedData: parsedPayload.encryptedData,
		iv: parsedPayload.iv,
		ciphertextPart: parsedPayload.ciphertextPart,
		tag: parsedPayload.tag,
		kdfParams: kdfContext.kdfParams,
	};
}

function getCipherVersion(ciphertext) {
	if (!ciphertext || typeof ciphertext !== 'string') return null;
	try {
		const data = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
		if (!data || data.length < 1) return null;
		const version = data[0];
		if (version !== LEGACY_VERSION && version !== CURRENT_VERSION) return null;
		return version;
	} catch {
		return null;
	}
}

export const SecureCipher = {
	encrypt,
	decrypt,
	deriveKeys,
	computeHMAC,
	hkdfExpand,
	constantTimeEqual,
	decodeCiphertext,
	getCipherVersion,
	VERSION: CURRENT_VERSION,
	LEGACY_VERSION,
};
