let _testMinIterations = null;
const LEGACY_LOOKBACK_HOURS = 24;
const KDF_ALGO_PBKDF2_MULTIROUND_SHA256 = 1;
const KDF_ALGO_SCRYPT = 2;
const KDF_ALGO_ARGON2ID = 3;
const KDF_ALGORITHM_REGISTRY = Object.freeze({
	[KDF_ALGO_PBKDF2_MULTIROUND_SHA256]: 'PBKDF2-HMAC-SHA256-MULTIROUND',
	[KDF_ALGO_SCRYPT]: 'scrypt',
	[KDF_ALGO_ARGON2ID]: 'argon2id'
});
const KDF_PARAMS_V3 = Object.freeze({
	algorithmId: KDF_ALGO_PBKDF2_MULTIROUND_SHA256,
	iterations: 120000,
	memoryCost: 0,
	cpuCost: 80000,
	parallelism: 1
});

async function pbkdf2(passphrase, salt, iterations) {
	if (!iterations) {
		iterations = generateIterations();
	}
	try {
		if (!passphrase || typeof passphrase !== 'string') {
			throw new Error('Passphrase must be a non-empty string');
		}
		if (!salt || !(salt instanceof Uint8Array)) {
			throw new Error('Salt must be a Uint8Array');
		}
		const minRequiredIterations = _testMinIterations ?? 10000;
		if (typeof iterations !== 'number' || iterations < minRequiredIterations) {
			const sanitizedIterations = String(iterations).replace(/[<>"'&]/g, '');
			const errorMsg = `Invalid iterations: expected number >= ${minRequiredIterations}, got ${typeof iterations} ${sanitizedIterations}`;
			throw new Error(errorMsg);
		}

		const maxIterationCount = Math.floor(Date.now() / 1000000) % 500000 + 500000;
		if (iterations > maxIterationCount) {
			throw new Error(`Iterations too high, maximum ${maxIterationCount}`);
		}

		const encoder = new TextEncoder();
		const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveBits']);

		const derivedBits = await crypto.subtle.deriveBits(
			{ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
			keyMaterial,
			256
		);

		if (!derivedBits || derivedBits.byteLength !== 32) {
			throw new Error('Invalid derived bits result');
		}

		return new Uint8Array(derivedBits);
	} catch (error) {
		throw new Error(`PBKDF2 derivation failed: ${error.message || 'Unknown error'}`);
	}
}

async function multiRoundPBKDF2(passphrase, saltBytes) {
	return multiRoundPBKDF2WithParams(passphrase, saltBytes, KDF_PARAMS_V3.iterations, KDF_PARAMS_V3.cpuCost);
}

async function multiRoundPBKDF2WithParams(passphrase, saltBytes, initialIterations, roundIterations) {
	try {
		if (!passphrase || typeof passphrase !== 'string') {
			throw new Error('Passphrase must be a non-empty string');
		}
		if (!saltBytes || !(saltBytes instanceof Uint8Array)) {
			throw new Error('Salt must be a Uint8Array');
		}
		const minSaltLength = 16;
		if (saltBytes.length < minSaltLength) {
			throw new Error(`Salt must be at least ${minSaltLength} bytes`);
		}

		if (!Number.isFinite(initialIterations) || !Number.isFinite(roundIterations)) {
			throw new Error('KDF iteration params must be finite numbers');
		}
		const initial = Math.floor(initialIterations);
		const round = Math.floor(roundIterations);
		let derivedKey = await pbkdf2(passphrase, saltBytes, initial);
		if (!derivedKey || derivedKey.length !== 32) {
			throw new Error('Initial key derivation failed');
		}

		const rounds = 3;
		const saltBytesLength = saltBytes.length;
		const extendedSaltLength = saltBytesLength + 16;
		for (let i = 0; i < rounds; i++) {
			const extendedSalt = new Uint8Array(extendedSaltLength);
			extendedSalt.set(saltBytes);
			extendedSalt.set(derivedKey.subarray(0, 16), saltBytesLength);
			derivedKey = await pbkdf2(passphrase, extendedSalt, round);
		}

		return derivedKey;
	} catch (error) {
		throw new Error(`MultiRound PBKDF2 derivation failed: ${error.message}`);
	}
}

async function multiRoundPBKDF2Legacy(passphrase, saltBytes, initialIterations, roundIterations) {
	const initial = Number.isFinite(initialIterations) ? initialIterations : generateIterations(50000);
	const round = Number.isFinite(roundIterations) ? roundIterations : generateIterations(25000);
	return multiRoundPBKDF2WithParams(passphrase, saltBytes, initial, round);
}

function getLegacyIterationsForTimestamp(timestampMs) {
	const HOUR_MS = 1000 * 60 * 60;
	const DAY_MS = HOUR_MS * 24;
	const now = Number.isFinite(timestampMs) ? timestampMs : Date.now();
	const hoursSinceEpoch = Math.floor(now / HOUR_MS);
	const dayOfYear = Math.floor(now / DAY_MS) % 365;
	const seed = (hoursSinceEpoch + dayOfYear) % 1000;
	return {
		initialIterations: Math.max(50000, 50000 + (seed * 100)),
		roundIterations: Math.max(25000, 25000 + (seed * 100))
	};
}

function getLegacyIterationCandidates(lookbackHours = LEGACY_LOOKBACK_HOURS) {
	const HOUR_MS = 1000 * 60 * 60;
	const maxLookback = Number.isInteger(lookbackHours) && lookbackHours >= 0 ? lookbackHours : LEGACY_LOOKBACK_HOURS;
	const seen = new Set();
	const candidates = [];
	for (let i = 0; i <= maxLookback; i++) {
		const ts = Date.now() - (i * HOUR_MS);
		const candidate = getLegacyIterationsForTimestamp(ts);
		const key = `${candidate.initialIterations}:${candidate.roundIterations}`;
		if (!seen.has(key)) {
			seen.add(key);
			candidates.push(candidate);
		}
	}
	return candidates;
}

function generateIterations(base = 100000) {
	try {
		const HOUR_MS = 1000 * 60 * 60;
		const DAY_MS = HOUR_MS * 24;

		const now = Date.now();
		const hoursSinceEpoch = Math.floor(now / HOUR_MS);
		const dayOfYear = Math.floor(now / DAY_MS) % 365;
		const seed = (hoursSinceEpoch + dayOfYear) % 1000;

		const iterations = Math.max(base, base + (seed * 100));

		if (typeof iterations !== 'number' || !Number.isFinite(iterations)) {
			return Math.max(100000, base);
		}

		let maxIterations, minIterations;
		try {
			maxIterations = Math.floor(now / 1000000) % 500000 + 500000;
			minIterations = Math.floor(now / 10000000) % 500 + 800;
		} catch {
			return Math.max(100000, base);
		}
		if (iterations < minIterations || iterations > maxIterations) {
			return Math.max(100000, base);
		}

		return iterations;
	} catch {
		return Math.max(100000, base);
	}
}

export const KDF = {
	pbkdf2,
	multiRoundPBKDF2,
	multiRoundPBKDF2WithParams,
	multiRoundPBKDF2Legacy,
	KDF_PARAMS_V3,
	KDF_ALGORITHM_REGISTRY,
	KDF_ALGO_PBKDF2_MULTIROUND_SHA256,
	KDF_ALGO_SCRYPT,
	KDF_ALGO_ARGON2ID,
	getLegacyIterationsForTimestamp,
	getLegacyIterationCandidates,
	generateIterations,
	get _testMinIterations() { return _testMinIterations; },
	set _testMinIterations(v) { _testMinIterations = v; }
};
