import { AuthenticationRequestDetails } from "verus-typescript-primitives";
import { GenericEnvelope } from "verus-typescript-primitives/dist/vdxf/classes/envelope/GenericEnvelope";
/** Identity chosen to answer an authentication request, including its resolved parent. */
export interface AuthenticationRecipient {
    identityID: string;
    systemID: string;
    parentID?: string;
}
/** Validate authentication fields without requiring optional correlation or expiry fields. */
export declare function validateAuthenticationRequestDetails(authentication: AuthenticationRequestDetails): void;
/** Require a signed authentication deadline that has not reached the current time. */
export declare function validateAuthenticationExpiry(authentication: AuthenticationRequestDetails, now?: number): void;
/** Match alternatives within each constraint type, requiring every requested type. */
export declare function validateAuthenticationRecipient(authentication: AuthenticationRequestDetails, recipient: AuthenticationRecipient): void;
/**
 * Check a signed envelope's version and field consistency. Encrypted details
 * require an explicit opt-in and subsequent authenticated decryption. This does
 * not verify cryptographic signatures or impose a request-specific app scope,
 * correlation identifier, creation time, expiry, or salt requirement.
 */
export declare function validateSignedGenericEnvelope(envelope: GenericEnvelope, requireSignature?: boolean, allowEncryptedDetails?: boolean): void;
