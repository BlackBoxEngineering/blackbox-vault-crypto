function getRandomBytes(length) {
	try {
		if (typeof length !== 'number' || length <= 0 || length > 65536) { throw new Error('Invalid length: must be positive number <= 65536'); }
		return crypto.getRandomValues(new Uint8Array(length));
	} catch (error) {
		throw new Error(`Random bytes generation failed: ${error.message}`);
	}
}

function getRandomInt(max) {
	try {
		if (typeof max !== 'number' || max <= 0 || max > 0xFFFFFFFF) { throw new Error('Invalid max: must be positive number <= 2^32-1'); }
		const logValue = Math.log2(max);
		if (!Number.isFinite(logValue) || logValue < 0) { throw new Error('Invalid log2 calculation for max value'); }
		const bytes = Math.ceil(logValue / 8);
		if (bytes <= 0 || bytes > 8) { throw new Error('Invalid byte calculation for max value'); }

		let result;
		let attempts = 0;
		const maxAttempts = 1000;

		do {
			if (attempts++ > maxAttempts) { throw new Error(`Too many attempts to generate random int: ${attempts}`); }

			let randomBytes;
			try {
				randomBytes = getRandomBytes(bytes);
			} catch (bytesError) {
				throw new Error(`Failed to generate random bytes: ${bytesError.message || 'Unknown error'}`);
			}

			if (!randomBytes || randomBytes.length !== bytes) { throw new Error('Invalid random bytes generated'); }

			result = 0;
			let multiplier = 1;
			const bytesLength = randomBytes.length;
			for (let i = 0; i < bytesLength; i++) {
				result += randomBytes[i] * multiplier;
				multiplier *= 256;
			}

			if (typeof result !== 'number' || result < 0) { throw new Error('Invalid result from byte reduction'); }

		} while (result >= max);
		return result;
	} catch (error) {
		const sanitizedError = String(error.message).replace(/[<>\"'&]/g, '');
		throw new Error(`Random integer generation failed: ${sanitizedError}`);
	}
}

export const CSPRNG = { getRandomBytes, getRandomInt };
