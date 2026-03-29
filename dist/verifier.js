import { jwtVerify } from 'jose';
import { computeCredentialHash } from './issuer.js';
/**
 * Verify a DORS status assertion JWT per Section 12.4.
 */
export async function verifyDORSAssertion(config) {
    try {
        // Step 1: Verify JWS signature and decode
        const { payload, protectedHeader } = await jwtVerify(config.assertionJwt, config.statusAuthorityPublicKey);
        // Step 1: Check typ
        if (protectedHeader.typ !== 'mcpi-status+jwt') {
            return { valid: false, error: `Invalid typ: expected "mcpi-status+jwt", got "${protectedHeader.typ}"` };
        }
        const claims = payload;
        // Step 3: Check iss
        if (claims.iss !== config.statusAuthorityDid) {
            return { valid: false, error: `iss mismatch: expected "${config.statusAuthorityDid}", got "${claims.iss}"` };
        }
        // Step 4: Check sub
        if (claims.sub !== config.expectedStatusId) {
            return { valid: false, error: `sub mismatch: expected "${config.expectedStatusId}", got "${claims.sub}"` };
        }
        // Step 5: Check credential_hash_alg
        if (claims.credential_hash_alg !== 'sha-256') {
            return { valid: false, error: `Unsupported credential_hash_alg: "${claims.credential_hash_alg}"` };
        }
        // Step 6: Compute and check credential_hash
        const expectedHash = computeCredentialHash(config.credentialCompactJws);
        if (claims.credential_hash !== expectedHash) {
            return { valid: false, error: 'credential_hash mismatch' };
        }
        // Step 7: Check exp (jose already checks this, but be explicit)
        const now = Math.floor(Date.now() / 1000);
        if (claims.exp <= now) {
            return { valid: false, error: 'DORS assertion expired' };
        }
        // Step 8: Check iat not in the future (with clock skew)
        if (claims.iat > now + config.policy.allowedClockSkewSeconds) {
            return { valid: false, error: 'DORS assertion iat is in the future beyond allowed clock skew' };
        }
        // Step 9: Check TTL bounds
        const ttl = claims.exp - claims.iat;
        if (ttl > config.policy.maxTtlSeconds) {
            return { valid: false, error: `DORS assertion TTL (${ttl}s) exceeds policy max (${config.policy.maxTtlSeconds}s)` };
        }
        return { valid: true, claims };
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return { valid: false, error: `DORS assertion verification failed: ${message}` };
    }
}
/**
 * Fetch a live DORS assertion from a service endpoint (Section 12.5).
 */
export async function fetchDORSAssertion(config) {
    const body = {
        status_id: config.statusId,
        credential_hash: computeCredentialHash(config.credentialCompactJws),
        credential_hash_alg: 'sha-256',
    };
    if (config.nonce) {
        body.nonce = config.nonce;
    }
    const response = await fetch(config.serviceEndpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/jwt',
        },
        body: JSON.stringify(body),
    });
    if (!response.ok) {
        throw new Error(`DORS service returned ${response.status}: ${await response.text()}`);
    }
    return await response.text();
}
