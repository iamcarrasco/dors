// DORS Status Values (Section 10.3)
export type DORSStatus = 'active' | 'revoked' | 'suspended' | 'unknown';

// DORS Reason Codes (Section 10.4)
export type DORSReasonCode =
  | 'key_compromise'
  | 'privilege_withdrawn'
  | 'superseded'
  | 'administrative_suspend'
  | 'cessation_of_operation'
  | 'unspecified';

// Credential status entry embedded in a VC (Section 7.1)
export interface MCPIDORSStatusEntry {
  type: 'MCPIDORSStatusEntry';
  statusId: string;
  statusService?: string;
}

// DID service entry in the issuer DID document (Section 7.2)
export interface DORSServiceEntry {
  id: string;
  type: 'MCPIDelegationRevocationService';
  serviceEndpoint: string;
  statusAuthority: string;
  maxTtlSeconds?: number;
  formats?: string[];
}

// Status query request body (Section 9.2)
export interface DORSStatusQuery {
  status_id: string;
  credential_hash: string;
  credential_hash_alg: 'sha-256';
  nonce?: string;
}

// JWT claims in a DORS status assertion (Section 10.2)
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

// Issuance record stored by the DORS responder (Section 8)
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

// Verifier policy configuration
export interface DORSVerifierPolicy {
  maxTtlSeconds: number;
  allowedClockSkewSeconds: number;
  requireDORS: boolean;
  allowLiveLookup: boolean;
}

// DORSResponder constructor config
export interface DORSResponderConfig {
  statusAuthorityDid: string;
  statusAuthorityKid: string;
  privateKey: CryptoKey | Uint8Array;
  defaultTtlSeconds: number;
}

// Verification result
export interface DORSVerificationResult {
  valid: boolean;
  claims?: DORSAssertionClaims;
  error?: string;
}
