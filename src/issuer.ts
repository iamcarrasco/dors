import { createHash, randomUUID } from 'node:crypto';
import type { MCPIDORSStatusEntry, IssuanceRecord } from './types.js';

/**
 * Compute the credential hash per Section 8.1:
 * base64url( SHA-256( ASCII( compactJws ) ) )
 */
export function computeCredentialHash(compactJws: string): string {
  const digest = createHash('sha256').update(compactJws, 'ascii').digest();
  return digest.toString('base64url');
}

/**
 * Create a MCPIDORSStatusEntry for embedding in a VC.
 * Generates a random UUID v4 as the statusId.
 */
export function createDORSStatusEntry(statusService?: string): MCPIDORSStatusEntry {
  const entry: MCPIDORSStatusEntry = {
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
export function createIssuanceRecord(
  issuerDid: string,
  statusId: string,
  compactJws: string,
): IssuanceRecord {
  return {
    issuerDid,
    statusId,
    credentialHash: computeCredentialHash(compactJws),
    credentialHashAlg: 'sha-256',
    status: 'active',
    issuedAt: Math.floor(Date.now() / 1000),
  };
}
