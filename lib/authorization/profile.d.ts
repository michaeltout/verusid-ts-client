import { AppAuthorizationIdentity } from "verus-typescript-primitives";
import { IdentityContentSource } from "../identity/identityContent";
/** Compatibility name for the shared current-content RPC source. */
export type AppDelegatorProfileSource = IdentityContentSource;
/**
 * Reject future profiles without interpreting their values or caching absence.
 * Call again on continuation and immediately before sensitive execution. The
 * unsupported error propagates so the wallet can explain this policy rejection.
 */
export declare function assertAppDelegatorProfileSupportedV1(source: AppDelegatorProfileSource, binding: AppAuthorizationIdentity): Promise<void>;
