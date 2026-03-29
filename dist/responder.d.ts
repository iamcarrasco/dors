import type { DORSResponderConfig, DORSStatusQuery, IssuanceRecord, DORSReasonCode } from './types.js';
export declare class DORSResponder {
    private records;
    private config;
    constructor(config: DORSResponderConfig);
    /** Register a new credential issuance. */
    registerIssuance(record: IssuanceRecord): void;
    /** Answer a status query — returns a signed compact JWS. */
    queryStatus(query: DORSStatusQuery): Promise<string>;
    /** Revoke a single credential. */
    revoke(statusId: string, reason?: DORSReasonCode | string): void;
    /** Bulk revoke all credentials for an issuer DID. Returns count of revoked credentials. */
    revokeByIssuer(issuerDid: string, reason: DORSReasonCode | string): number;
    /** Suspend a credential. */
    suspend(statusId: string): void;
    /** Unsuspend a credential (return to active). */
    unsuspend(statusId: string): void;
    /** Get all issuance records (for debug/admin). */
    getRecords(): IssuanceRecord[];
}
