import {
  AppAuthorizationIdentity,
  DELEGATOR_PROFILE_VDXF_KEY,
  assertDelegatorProfileSupportedV1,
} from "verus-typescript-primitives";
import {
  IdentityContentSource,
  loadCurrentIdentityContent,
} from "../identity/identityContent";

/** Compatibility name for the shared current-content RPC source. */
export type AppDelegatorProfileSource = IdentityContentSource;

/**
 * Reject future profiles without interpreting their values or caching absence.
 * Call again on continuation and immediately before sensitive execution. The
 * unsupported error propagates so the wallet can explain this policy rejection.
 */
export async function assertAppDelegatorProfileSupportedV1(
  source: AppDelegatorProfileSource,
  binding: AppAuthorizationIdentity
): Promise<void> {
  const { revision } = await loadCurrentIdentityContent(
    source,
    binding,
    DELEGATOR_PROFILE_VDXF_KEY.vdxfid
  );

  // Filtered reads may include siblings; only this reserved outer key matters.
  assertDelegatorProfileSupportedV1(
    revision.identity.contentmultimap as Record<string, unknown>
  );
}
