import type { DORSVerifierPolicy, DORSVerificationResult } from './types.js';
/**
 * Verify a DORS status assertion JWT per Section 12.4.
 */
export declare function verifyDORSAssertion(config: {
    assertionJwt: string;
    expectedStatusId: string;
    credentialCompactJws: string;
    statusAuthorityPublicKey: CryptoKey;
    statusAuthorityDid: string;
    policy: DORSVerifierPolicy;
}): Promise<DORSVerificationResult>;
/**
 * Fetch a live DORS assertion from a service endpoint (Section 12.5).
 */
export declare function fetchDORSAssertion(config: {
    serviceEndpoint: string;
    statusId: string;
    credentialCompactJws: string;
    nonce?: string;
}): Promise<string>;
