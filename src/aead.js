async function encryptAESGCM(plaintext, key) {
	if (!crypto?.subtle) { throw new Error('Web Crypto API not available'); }
	if (!crypto.getRandomValues) { throw new Error('Crypto random values not available'); }
	try {
		if (plaintext === null || plaintext === undefined) { throw new Error('Plaintext cannot be null or undefined'); }
		if (typeof plaintext !== 'string') { throw new Error('Plaintext must be a string'); }
		if (!key || !(key instanceof Uint8Array) || key.length !== 32) { throw new Error('Key must be a 32-byte Uint8Array'); }

		const iv = crypto.getRandomValues(new Uint8Array(12));
		if (!iv || iv.length !== 12) { throw new Error('Failed to generate IV'); }

		const plaintextBytes = new TextEncoder().encode(plaintext);

		const cryptoKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
		if (!cryptoKey) { throw new Error('Failed to import encryption key'); }

		let ciphertext;
		try {
			ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintextBytes);
		} catch (encryptError) {
			throw new Error(`Encryption operation failed: ${encryptError.message || 'Unknown error'}`);
		}

		if (!ciphertext) { throw new Error('Encryption produced null result'); }
		if (ciphertext.byteLength === 0 && plaintextBytes.length > 0) { throw new Error('Encryption produced empty result for non-empty input'); }

		const ciphertextArray = new Uint8Array(ciphertext);
		const result = new Uint8Array(iv.length + ciphertextArray.length);
		result.set(iv);
		result.set(ciphertextArray, iv.length);

		const chunkSize = 8192;
		const chunks = [];
		for (let i = 0; i < result.length; i += chunkSize) {
			const chunk = result.slice(i, i + chunkSize);
			chunks.push(String.fromCharCode(...chunk));
		}
		return btoa(chunks.join(''));
	} catch (error) {
		throw new Error(`AES-GCM encryption failed: ${error.message || 'Unknown error'}`);
	}
}

async function decryptAESGCM(ciphertext, key) {
	if (!crypto?.subtle) { throw new Error('Web Crypto API not available'); }

	try {
		if (!ciphertext || typeof ciphertext !== 'string') { throw new Error('Ciphertext must be a non-empty string'); }
		if (ciphertext.length === 0) { throw new Error('Ciphertext cannot be empty'); }
		if (!key || !(key instanceof Uint8Array) || key.length !== 32) { throw new Error('Key must be a 32-byte Uint8Array'); }

		let data;
		try {
			data = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
		} catch (base64Error) {
			throw new Error(`Invalid base64 ciphertext: ${base64Error.message || 'Unknown error'}`);
		}

		const MIN_CIPHERTEXT_LENGTH = 12 + 16;
		if (!data || data.length < MIN_CIPHERTEXT_LENGTH) { throw new Error('Invalid ciphertext: too short'); }

		const iv = data.slice(0, 12);
		const encrypted = data.slice(12);

		if (!iv || iv.length !== 12) { throw new Error('Invalid IV extracted from ciphertext'); }
		if (!encrypted || encrypted.length === 0) { throw new Error('No encrypted data found'); }

		const cryptoKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
		if (!cryptoKey) { throw new Error('Failed to import decryption key'); }

		let decrypted;
		try {
			decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, encrypted);
		} catch (decryptError) {
			throw new Error(`Decryption operation failed: ${decryptError.message || 'Unknown error'}`);
		}

		if (decrypted === null || decrypted === undefined) { throw new Error('Decryption failed - null result'); }

		return new TextDecoder().decode(decrypted);
	} catch (error) {
		throw new Error(`AES-GCM decryption failed: ${error.message || 'Unknown error'}`);
	}
}

export const AEAD = { encryptAESGCM, decryptAESGCM };
