import type { MCPIDORSStatusEntry, IssuanceRecord } from './types.js';
/**
 * Compute the credential hash per Section 8.1:
 * base64url( SHA-256( ASCII( compactJws ) ) )
 */
export declare function computeCredentialHash(compactJws: string): string;
/**
 * Create a MCPIDORSStatusEntry for embedding in a VC.
 * Generates a random UUID v4 as the statusId.
 */
export declare function createDORSStatusEntry(statusService?: string): MCPIDORSStatusEntry;
/**
 * Build an IssuanceRecord to register with the DORS responder.
 */
export declare function createIssuanceRecord(issuerDid: string, statusId: string, compactJws: string): IssuanceRecord;
