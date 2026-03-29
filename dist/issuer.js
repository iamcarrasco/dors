import { createHash, randomUUID } from 'node:crypto';
/**
 * Compute the credential hash per Section 8.1:
 * base64url( SHA-256( ASCII( compactJws ) ) )
 */
export function computeCredentialHash(compactJws) {
    const digest = createHash('sha256').update(compactJws, 'ascii').digest();
    return digest.toString('base64url');
}
/**
 * Create a MCPIDORSStatusEntry for embedding in a VC.
 * Generates a random UUID v4 as the statusId.
 */
export function createDORSStatusEntry(statusService) {
    const entry = {
        type: 'MCPIDORSStatusEntry',
        statusId: `urn:uuid:${randomUUID()}`,
    };
    if (statusService) {
        entry.statusService = statusService;
    }
    return entry;
}
/**
 * Build an IssuanceRecord to register with the DORS responder.
 */
export function createIssuanceRecord(issuerDid, statusId, compactJws) {
    return {
        issuerDid,
        statusId,
        credentialHash: computeCredentialHash(compactJws),
        credentialHashAlg: 'sha-256',
        status: 'active',
        issuedAt: Math.floor(Date.now() / 1000),
    };
}
