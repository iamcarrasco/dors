import { randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import type {
  DORSResponderConfig,
  DORSStatusQuery,
  DORSAssertionClaims,
  IssuanceRecord,
  DORSReasonCode,
} from './types.js';

export class DORSResponder {
  private records = new Map<string, IssuanceRecord>();
  private config: DORSResponderConfig;

  constructor(config: DORSResponderConfig) {
    this.config = config;
  }

  /** Register a new credential issuance. */
  registerIssuance(record: IssuanceRecord): void {
    this.records.set(record.statusId, { ...record });
  }

  /** Answer a status query — returns a signed compact JWS. */
  async queryStatus(query: DORSStatusQuery): Promise<string> {
    const record = this.records.get(query.status_id);

    let status: DORSAssertionClaims['status'];
    let reason: string | undefined;
    let statusChangedAt: number | undefined;

    if (!record || record.credentialHash !== query.credential_hash) {
      status = 'unknown';
    } else {
      status = record.status === 'active' ? 'active'
        : record.status === 'revoked' ? 'revoked'
        : record.status === 'suspended' ? 'suspended'
        : 'unknown';
      reason = record.reason;
      statusChangedAt = record.statusChangedAt;
    }

    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = {
      sub: query.status_id,
      jti: `urn:uuid:${randomUUID()}`,
      credential_hash: query.credential_hash,
      credential_hash_alg: query.credential_hash_alg,
      status,
    };

    if (reason) claims['reason'] = reason;
    if (statusChangedAt) claims['status_changed_at'] = statusChangedAt;
    if (query.nonce) claims['nonce'] = query.nonce;

    const jwt = await new SignJWT(claims)
      .setProtectedHeader({
        alg: 'EdDSA',
        typ: 'mcpi-status+jwt',
        kid: this.config.statusAuthorityKid,
      })
      .setIssuer(this.config.statusAuthorityDid)
      .setIssuedAt(now)
      .setExpirationTime(now + this.config.defaultTtlSeconds)
      .sign(this.config.privateKey as CryptoKey);

    return jwt;
  }

  /** Revoke a single credential. */
  revoke(statusId: string, reason?: DORSReasonCode | string): void {
    const record = this.records.get(statusId);
    if (record) {
      record.status = 'revoked';
      record.reason = reason ?? 'unspecified';
      record.statusChangedAt = Math.floor(Date.now() / 1000);
    }
  }

  /** Bulk revoke all credentials for an issuer DID. Returns count of revoked credentials. */
  revokeByIssuer(issuerDid: string, reason: DORSReasonCode | string): number {
    let count = 0;
    const now = Math.floor(Date.now() / 1000);
    for (const record of this.records.values()) {
      if (record.issuerDid === issuerDid && record.status !== 'revoked') {
        record.status = 'revoked';
        record.reason = reason;
        record.statusChangedAt = now;
        count++;
      }
    }
    return count;
  }

  /** Suspend a credential. */
  suspend(statusId: string): void {
    const record = this.records.get(statusId);
    if (record && record.status === 'active') {
      record.status = 'suspended';
      record.reason = 'administrative_suspend';
      record.statusChangedAt = Math.floor(Date.now() / 1000);
    }
  }

  /** Unsuspend a credential (return to active). */
  unsuspend(statusId: string): void {
    const record = this.records.get(statusId);
    if (record && record.status === 'suspended') {
      record.status = 'active';
      record.reason = undefined;
      record.statusChangedAt = Math.floor(Date.now() / 1000);
    }
  }

  /** Get all issuance records (for debug/admin). */
  getRecords(): IssuanceRecord[] {
    return Array.from(this.records.values());
  }
}
