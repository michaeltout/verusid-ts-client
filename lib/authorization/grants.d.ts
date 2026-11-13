import { AppAuthorizationIdentity, AuthorizationCredential, AuthorizationStorageBindingCredential, AuthorizationStorageKeyCredential, AuthorizationStorageRecord, Credential } from "verus-typescript-primitives";
import { IdentityRevision } from "../identity/identityAuthority";
export type AppAuthorizationRecord = AuthorizationCredential | AuthorizationStorageRecord;
/** Retain the exact encrypted CMM value; reserializing plaintext cannot identify a removal. */
export interface AppAuthorizationCredentialSource extends AppAuthorizationIdentity {
    outerKey: string;
    storedValue: Buffer;
}
export interface AppAuthorizationCredentialEntry {
    credential: Credential | Buffer;
    source: AppAuthorizationCredentialSource;
}
export interface SourcedAppAuthorizationRecord<T extends AppAuthorizationRecord = AppAuthorizationRecord> {
    record: T;
    source: AppAuthorizationCredentialSource;
}
/**
 * Decode locally decrypted generic credentials while preserving their origin.
 * Unknown credential types are unrelated user content. Malformed authorization
 * records throw rather than silently creating a partially usable grant index.
 *
 * The wallet must supply a complete, effective bucket from the selected user's
 * confirmed content view, and retain that view's outpoint and chain context.
 * Neither decrypted records nor this decoder prove current on-chain membership.
 */
export declare function decodeAppAuthorizationRecords(entries: AppAuthorizationCredentialEntry[]): SourcedAppAuthorizationRecord[];
export interface DelegatedAppAuthorizationOptions {
    /** Complete effective records; never merge independently aggregated height windows. */
    records: SourcedAppAuthorizationRecord[];
    user: AppAuthorizationIdentity;
    /** These bindings must come from the verified envelope, not request display data. */
    delegate: AppAuthorizationIdentity;
    appID: string;
    /** Assert current effective delegator CMM has no unsupported profile marker. */
    verifyDelegatorProfile: (delegator: AppAuthorizationIdentity) => Promise<void>;
    /** Check current independent user control, dependencies, profile and content freshness. */
    verifyUserControl: (user: AppAuthorizationIdentity) => Promise<boolean>;
    /** Verify the same request against this grant's own original/current signer policy. */
    verifyAuthority: (grant: AuthorizationCredential) => Promise<boolean>;
    /**
     * Check current S is active and 1-of-N, retains the selected independent user
     * key and applicable app keys, and has usable user-controlled R/C dependencies.
     * Resolve S/R/C on binding.storageSystemID, even if U is on another system.
     */
    verifyStorageControl: (binding: AuthorizationStorageBindingCredential, keys: AuthorizationStorageKeyCredential[]) => Promise<boolean>;
}
/**
 * Check the public half of a stored relationship against fresh RPC state.
 * Wallet ownership of the user key and R/C (including their dependencies) is a
 * separate required check; a matching public address does not prove control.
 */
export declare function verifyAppAuthorizationStorageState(binding: AuthorizationStorageBindingCredential, keys: AuthorizationStorageKeyCredential[], current: IdentityRevision): boolean;
/**
 * Find one complete grant whose authority and current control checks all pass.
 * This is deliberately separate from cryptographic envelope verification and
 * handler approval: delegation does not authorize unattended wallet operations.
 * Call again immediately before execution or key release after asynchronous UI.
 *
 * Missing records, failed callbacks and RPC errors fail closed. Each candidate
 * uses its own baseline and management set; no signers or records are pooled
 * between grants. There is no implicit unscoped or self-controlled fallback.
 * UnsupportedDelegatorProfileError propagates so callers can explain why a
 * future profile cannot be handled by this version.
 */
export declare function verifyDelegatedAppAuthorization(options: DelegatedAppAuthorizationOptions): Promise<SourcedAppAuthorizationRecord<AuthorizationCredential> | undefined>;
