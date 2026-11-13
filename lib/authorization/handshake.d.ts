import BN from "bn.js";
import { GenericEnvelope } from "verus-typescript-primitives/dist/vdxf/classes/envelope/GenericEnvelope";
import { AppAuthorizationOffer, AppAuthorizationOfferRole, AppAuthorizationRequestDetails, AppAuthorizationResponseDetails, AppAuthorizationResponseDetailsInterface, AuthenticationRequestDetails, AuthenticationRequestDetailsInterface, CompactIAddressObject, GenericRequest, GenericRequestInterface, GenericResponse, SpendableKeyDetails } from "verus-typescript-primitives";
import { AuthenticationRecipient } from "../requests/validation";
import type { AppAuthorizationIdentity } from "verus-typescript-primitives";
export declare const APP_AUTHORIZATION_SALT_BYTES = 32;
export declare const DEFAULT_APP_AUTHORIZATION_GIFT_EXPIRY_SECONDS: number;
export interface AppAuthorizationRequestOptions {
    /** Unix seconds; injectable for deterministic admission tests. */
    now?: number;
    /** Disable only when correlating an already admitted operation's final response. */
    checkExpiry?: boolean;
    maxRequestBytes?: number;
    maxGiftBytes?: number;
}
export interface CreateAppAuthorizationRequestParams extends Pick<GenericRequestInterface, "responseURIs" | "encryptResponseToAddress" | "preferredHandler"> {
    appID: string;
    delegate: AppAuthorizationIdentity;
    requestID: string;
    recipientConstraints?: AuthenticationRequestDetailsInterface["recipientConstraints"];
    expiryTime?: BN;
    createdAt?: BN;
    salt?: Buffer;
    gift?: SpendableKeyDetails;
    offeredIdentities?: Array<{
        role: AppAuthorizationOfferRole;
        identity: string | CompactIAddressObject;
    }>;
    requiresSharedStorage?: boolean;
    isTestnet?: boolean;
}
export type AppAuthorizationResponseUser = AuthenticationRecipient;
export interface CreateAppAuthorizationResponseParams extends Omit<AppAuthorizationResponseDetailsInterface, "version" | "flags" | "requestSigningSystemID" | "delegateID" | "grantID"> {
    user: AppAuthorizationResponseUser;
    createdAt?: BN;
}
/** Normalize only the address representation; role validation and deduplication belong to the codec. */
export declare function normalizeAppAuthorizationOffers(offers: CreateAppAuthorizationRequestParams["offeredIdentities"]): AppAuthorizationOffer[] | undefined;
/** Detect the wire ordinal as well as its class so malformed payloads cannot bypass admission. */
export declare function hasAppAuthorizationRequest(request: GenericRequest): boolean;
/** Validate signed envelope fields shared by bootstrap, delegated requests and completions. */
export declare function validateAppAuthorizationEnvelope(envelope: GenericEnvelope, requireSignature?: boolean, allowEncryptedDetails?: boolean): void;
/** Structural admission only; callers must also verify the actual signature and current authority. */
export declare function validateAppAuthorizationRequest(request: GenericRequest, options?: AppAuthorizationRequestOptions): {
    authentication: AuthenticationRequestDetails;
    authorization: AppAuthorizationRequestDetails;
};
/** Construct a signing template; use the existing signGenericRequest method to sign it. */
export declare function createAppAuthorizationRequest(params: CreateAppAuthorizationRequestParams): GenericRequest;
/**
 * Stable across signature encoding changes and re-signing identical request data.
 * A wallet must durably reserve this ID before side effects; this helper is not a
 * replay cache and does not promise exactly-once execution across devices.
 */
export declare function getAppAuthorizationOperationID(request: GenericRequest): string;
/**
 * Correlate against the retained request and selected/resolved user; verify the
 * envelope signature separately. An acknowledgment never authorizes later work.
 */
export declare function validateAppAuthorizationResponse(response: GenericResponse, request: GenericRequest, user: AppAuthorizationResponseUser, maxResponseBytes?: number): AppAuthorizationResponseDetails;
/** Build a response only after the wallet has resolved the final outcome and selected U. */
export declare function createAppAuthorizationResponse(request: GenericRequest, params: CreateAppAuthorizationResponseParams): GenericResponse;
