import { GenericEnvelope } from "verus-typescript-primitives/dist/vdxf/classes/envelope/GenericEnvelope";
import { IdentityRevision as AuthorizationIdentityRevision } from "../identity/identityAuthority";
export { validateIdentityRevision as validateAuthorizationIdentity, loadIdentityRevision as loadAuthorizationIdentity, loadIdentityRevisionAtOutpoint as loadOriginalAuthorizationIdentity, } from "../identity/identityAuthority";
/** Preserve the original unary callback contract for existing Array.map callers. */
export declare const normalizeAuthorizationKeyID: (primary: string) => string;
export type { IdentityBinding as AuthorizationIdentityBinding, IdentitySource as AuthorizationIdentitySource, IdentityRevisionReference as AuthorizationOriginalRevision, IdentityRevision as AuthorizationIdentityRevision, } from "../identity/identityAuthority";
export interface AuthorizationSignerEvidence {
    signedHeight: number;
    /** Verified key-ID encodings; one recovered public key counts only once. */
    signedKeyIDs: string[];
    eligibleKeyIDs: string[];
    requiredSignatures: number;
    valid: boolean;
}
/**
 * Verify the original/current intersection on the very same signed digest used
 * by ordinary identity verification. Omit original only for bootstrap admission.
 * This proves signer policy, not user control, effective grant membership, or
 * storage eligibility; callers must still establish those independently.
 */
export declare function inspectAuthorizationSigners(envelope: GenericEnvelope, signedIdentity: AuthorizationIdentityRevision, currentIdentity: AuthorizationIdentityRevision, originalIdentity?: AuthorizationIdentityRevision): AuthorizationSignerEvidence;
