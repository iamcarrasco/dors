export type {
  DORSStatus,
  DORSReasonCode,
  MCPIDORSStatusEntry,
  DORSServiceEntry,
  DORSStatusQuery,
  DORSAssertionClaims,
  IssuanceRecord,
  DORSVerifierPolicy,
  DORSResponderConfig,
  DORSVerificationResult,
} from './types.js';

export {
  computeCredentialHash,
  createDORSStatusEntry,
  createIssuanceRecord,
} from './issuer.js';

export { DORSResponder } from './responder.js';

export {
  verifyDORSAssertion,
  fetchDORSAssertion,
} from './verifier.js';
