# DORS PoC Design — TypeScript Proof of Concept

**Date:** 2026-03-29
**Status:** Approved
**Approach:** DORS library in `dors/` repo, integrated into `mcp-i-room-booking/` as a local dependency

---

## Goal

Build a working proof of concept that demonstrates DORS protecting MCP-I delegation credentials against key compromise. The PoC has two deliverables:

1. A reusable, framework-agnostic DORS library (`dors/src/`)
2. Integration into the existing `mcp-i-room-booking` demo with a web UI "Simulate Key Compromise" button

The demo must convincingly show both the happy path (credential active, booking succeeds) and the key compromise scenario (credential revoked via DORS, booking rejected despite valid VC signature).

---

## Architecture

Two repos, four services:

```
dors/                              mcp-i-room-booking/
├── src/                           ├── src/
│   ├── index.ts                   │   ├── dors-service.ts      NEW    (Express :3002)
│   ├── types.ts                   │   ├── consent-server.ts    MODIFIED
│   ├── issuer.ts                  │   ├── web-server.ts        MODIFIED
│   ├── responder.ts               │   ├── server.ts            MODIFIED
│   └── verifier.ts                │   └── public/index.html    MODIFIED
├── package.json                   └── package.json
└── tsconfig.json                      + "dors": "file:../dors"
```

Running services:
- **Web UI + Agent** — `:3000` (web-server.ts)
- **Consent Server** — `:3001` (consent-server.ts)
- **DORS Service** — `:3002` (dors-service.ts, NEW)
- **MCP Server** — stdio (spawned by web-server.ts)

---

## Part 1: DORS Library (`dors/src/`)

Framework-agnostic. Single external dependency: `jose` for JWT signing/verification.

### types.ts

All interfaces from the DORS spec:

- `MCPIDORSStatusEntry` — credential status entry (Section 7.1): `type`, `statusId`, `statusService?`
- `DORSServiceEntry` — DID service entry (Section 7.2): `id`, `type`, `serviceEndpoint`, `statusAuthority`, `maxTtlSeconds?`, `formats?`
- `DORSStatusQuery` — status query (Section 9.2): `status_id`, `credential_hash`, `credential_hash_alg`, `nonce?`
- `DORSAssertionClaims` — JWT claims (Section 10.2): `iss`, `sub`, `jti`, `iat`, `exp`, `credential_hash`, `credential_hash_alg`, `status`, `reason?`, `status_changed_at?`, `nonce?`
- `IssuanceRecord` — issuance binding (Section 8): `issuerDid`, `statusId`, `credentialHash`, `credentialHashAlg`, `status`, `issuedAt`, `statusChangedAt?`, `reason?`
- `DORSVerifierPolicy` — verifier config: `maxTtlSeconds`, `allowedClockSkewSeconds`, `requireDORS`, `allowLiveLookup`
- Status type: `"active" | "revoked" | "suspended" | "unknown"`
- Reason codes: `"key_compromise" | "privilege_withdrawn" | "superseded" | "administrative_suspend" | "cessation_of_operation" | "unspecified"`

### issuer.ts

Helpers for the credential issuance side:

- `computeCredentialHash(compactJws: string): string` — SHA-256 of the compact JWS, base64url encoded (Section 8.1)
- `createDORSStatusEntry(statusService?: string): MCPIDORSStatusEntry` — generates a UUID v4 `statusId`
- `createIssuanceRecord(issuerDid: string, statusId: string, compactJws: string): IssuanceRecord` — builds the record to register with the DORS responder

### responder.ts

Core DORS service logic:

```typescript
class DORSResponder {
  constructor(config: {
    statusAuthorityDid: string
    statusAuthorityKid: string
    privateKey: KeyLike | Uint8Array
    defaultTtlSeconds: number
  })

  registerIssuance(record: IssuanceRecord): void
  queryStatus(query: DORSStatusQuery): Promise<string>  // returns compact JWS
  revoke(statusId: string, reason?: string): void
  revokeByIssuer(issuerDid: string, reason: string): number  // returns count
  suspend(statusId: string): void
  unsuspend(statusId: string): void
}
```

- Stores issuance records in an in-memory Map keyed by `statusId`
- `queryStatus` validates the `(statusId, credential_hash)` tuple, returns `unknown` if not found
- Signs JWTs with `typ: "mcpi-status+jwt"`, `alg: "EdDSA"`, using the status authority key
- `revokeByIssuer` supports bulk revocation by issuer DID — the key compromise scenario

### verifier.ts

Edge verifier logic:

```typescript
verifyDORSAssertion(config: {
  assertionJwt: string
  expectedStatusId: string
  credentialCompactJws: string
  statusAuthorityPublicKey: KeyLike
  statusAuthorityDid: string
  policy: DORSVerifierPolicy
}): Promise<{
  valid: boolean
  claims?: DORSAssertionClaims
  error?: string
}>

fetchDORSAssertion(config: {
  serviceEndpoint: string
  statusId: string
  credentialCompactJws: string
  nonce?: string
}): Promise<string>
```

`verifyDORSAssertion` implements Section 12.4:
1. Check `typ == "mcpi-status+jwt"`
2. Verify JWS signature against status authority public key
3. Check `iss == statusAuthorityDid`
4. Check `sub == expectedStatusId`
5. Check `credential_hash_alg == "sha-256"`
6. Compute hash of credential, check `credential_hash` matches
7. Check `now < exp`
8. Check `iat <= now + allowedClockSkewSeconds`
9. Check `(exp - iat) <= policy.maxTtlSeconds`

`fetchDORSAssertion` implements Section 12.5 (live lookup fallback).

---

## Part 2: Room Booking Integration

### New: `src/dors-service.ts` (Express on :3002)

Thin Express wrapper around `DORSResponder`:

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/status` | POST | Spec Section 9 — status query, returns `application/jwt` |
| `/admin/register` | POST | Called by consent server after issuance |
| `/admin/revoke` | POST | Single credential revocation |
| `/admin/revoke-by-issuer` | POST | Bulk revoke — key compromise scenario |
| `/admin/records` | GET | List all issuance records (debug) |
| `/.well-known/dors` | GET | Status authority DID + public key JWK |

Generates its own Ed25519 key pair on startup (separate from consent server). This is the independent status authority.

### Modified: `src/consent-server.ts`

After issuing a delegation VC in the approve handler:

1. Call `createDORSStatusEntry()` to generate a `statusId`
2. Serialize the VC to compact JWS
3. Call `createIssuanceRecord()` to build the binding
4. POST the record to DORS service at `/admin/register`
5. Store `dors.statusId` and `dors.credentialCompactJws` alongside the credential
6. Return DORS metadata in the credential polling response (`GET /api/credential/:token`)

### Modified: `src/web-server.ts`

Agent-side changes:

- Store DORS metadata (`statusId`, `credentialCompactJws`) in agent state after credential approval
- New endpoint `POST /api/fetch-dors-assertion`: calls `fetchDORSAssertion()` from the DORS library, stores the compact JWT in state
- Modified `POST /api/book-room-with-delegation`: passes `_mcpi_dors_assertion` field in tool call arguments alongside `_mcpi_delegation`
- New endpoint `POST /api/simulate-key-compromise`: calls DORS service `/admin/revoke-by-issuer` with the consent server's issuer DID and `reason: "key_compromise"`
- New endpoint `POST /api/retry-after-compromise`: fetches a fresh DORS assertion (which will return `revoked`), then attempts the booking (which will be rejected)

### Modified: `src/server.ts`

Edge verifier changes in the `book-room` handler, after delegation middleware passes:

1. Extract `_mcpi_dors_assertion` from tool call arguments
2. Fetch status authority public key from DORS service `/.well-known/dors`
3. Call `verifyDORSAssertion()` with the assertion, credential, and policy
4. If status is not `active`, reject with `error: "dors_rejected"` including `status`, `reason`, and explanation
5. If DORS assertion is missing and policy doesn't require it, proceed (L2 behavior)

### Modified: `src/public/index.html`

- **Step 3.5 (new)**: After credential approval, show DORS assertion fetch — displays status (`active`), TTL, signing authority DID, and truncated JWT
- **Security panel**: Collapsible panel visible after a credential is issued
  - "Simulate Key Compromise" button — calls `/api/simulate-key-compromise`
  - Shows revocation confirmation with count of affected credentials
  - "Try Booking Again" button — calls `/api/retry-after-compromise`
  - Rejection display: shows "VC signature: valid" alongside "DORS status: revoked, reason: key_compromise, Result: REQUEST DENIED"
  - Explanatory text: "The delegation key was compromised, but the independent status authority (DORS) caught it."

### Transport Adaptation

The DORS spec defines `MCP-I-Status-Assertion` as an HTTP header. Since the room booking demo uses MCP over stdio (not HTTP), the DORS assertion is passed as a `_mcpi_dors_assertion` string field in the tool call arguments. Same data, different transport envelope.

---

## Error Handling

- **DORS service unavailable**: Default L2 behavior — log warning, allow booking. Security panel could include L3 toggle (fail closed) for reviewers.
- **Expired assertion**: Verifier rejects; agent auto-fetches a fresh one.
- **Hash mismatch**: `verifyDORSAssertion()` returns `error: "credential_hash mismatch"`. Verifier rejects.
- **Unknown status**: DORS responder returns `status: "unknown"` for unrecognized `(statusId, credential_hash)` tuples. Verifier rejects.

---

## Out of Scope

- No auth on DORS admin endpoints (demo only)
- No persistent storage (in-memory Maps, same as existing app)
- No DID document resolution (public keys passed directly — everything runs locally)
- No Bitstring Status List integration
- No unit test framework (manual testing via web UI)

---

## Testing

Manual via the web UI — three scenarios:

1. **Happy path**: Connect → List → Book → Approve → DORS fetch (active) → Book succeeds
2. **Key compromise**: After successful booking → "Simulate Key Compromise" → Try booking again → Rejected with `reason: key_compromise`
3. **Forged credential** (stretch): Debug button sends modified credential hash → DORS returns `unknown` → Verifier rejects

---

## Running the Demo

```bash
# In mcp-i-room-booking/
npm run demo
# Starts consent server (:3001), DORS service (:3002), and web UI (:3000)
# Open http://localhost:3000
```
