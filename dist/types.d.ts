export type DORSStatus = 'active' | 'revoked' | 'suspended' | 'unknown';
export type DORSReasonCode = 'key_compromise' | 'privilege_withdrawn' | 'superseded' | 'administrative_suspend' | 'cessation_of_operation' | 'unspecified';
export interface MCPIDORSStatusEntry {
    type: 'MCPIDORSStatusEntry';
    statusId: string;
    statusService?: string;
}
export interface DORSServiceEntry {
    id: string;
    type: 'MCPIDelegationRevocationService';
    serviceEndpoint: string;
    statusAuthority: string;
    maxTtlSeconds?: number;
    formats?: string[];
}
export interface DORSStatusQuery {
    status_id: string;
    credential_hash: string;
    credential_hash_alg: 'sha-256';
    nonce?: string;
}
export interface DORSAssertionClaims {
    iss: string;
    sub: string;
    jti: string;
    iat: number;
    exp: number;
    credential_hash: string;
    credential_hash_alg: 'sha-256';
    status: DORSStatus;
    reason?: DORSReasonCode | string;
    status_changed_at?: number;
    nonce?: string;
}
export interface IssuanceRecord {
    issuerDid: string;
    statusId: string;
    credentialHash: string;
    credentialHashAlg: 'sha-256';
    status: 'active' | 'revoked' | 'suspended';
    issuedAt: number;
    statusChangedAt?: number;
    reason?: DORSReasonCode | string;
}
export interface DORSVerifierPolicy {
    maxTtlSeconds: number;
    allowedClockSkewSeconds: number;
    requireDORS: boolean;
    allowLiveLookup: boolean;
}
export interface DORSResponderConfig {
    statusAuthorityDid: string;
    statusAuthorityKid: string;
    privateKey: CryptoKey | Uint8Array;
    defaultTtlSeconds: number;
}
export interface DORSVerificationResult {
    valid: boolean;
    claims?: DORSAssertionClaims;
    error?: string;
}
