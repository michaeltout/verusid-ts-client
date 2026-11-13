import {
  AppAuthorizationIdentity,
  AuthorizationCredential,
  AuthorizationStorageBindingCredential,
  AuthorizationStorageKeyCredential,
  AuthorizationStorageRecord,
  Credential,
  I_ADDR_VERSION,
  UnsupportedDelegatorProfileError,
  decodeDestination,
  verifyAppAuthorizationStorageManifest,
} from "verus-typescript-primitives";
import { snapshotRequestValue } from "../utils/requestSnapshot";
import {
  IdentityRevision,
  validateIdentityRevision,
} from "../identity/identityAuthority";

export type AppAuthorizationRecord =
  | AuthorizationCredential
  | AuthorizationStorageRecord;

/** Retain the exact encrypted CMM value; reserializing plaintext cannot identify a removal. */
export interface AppAuthorizationCredentialSource extends AppAuthorizationIdentity {
  outerKey: string;
  storedValue: Buffer;
}

export interface AppAuthorizationCredentialEntry {
  credential: Credential | Buffer;
  source: AppAuthorizationCredentialSource;
}

export interface SourcedAppAuthorizationRecord<
  T extends AppAuthorizationRecord = AppAuthorizationRecord
> {
  record: T;
  source: AppAuthorizationCredentialSource;
}

function validateSource(source: AppAuthorizationCredentialSource): void {
  for (const address of [source.systemID, source.identityID, source.outerKey]) {
    decodeDestination(address, I_ADDR_VERSION);
  }

  if (!Buffer.isBuffer(source.storedValue) || source.storedValue.length === 0) {
    throw new Error("Authorization credentials require their original stored CMM bytes.");
  }
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
export function decodeAppAuthorizationRecords(
  entries: AppAuthorizationCredentialEntry[]
): SourcedAppAuthorizationRecord[] {
  const decoded: SourcedAppAuthorizationRecord[] = [];

  for (const entry of entries) {
    validateSource(entry.source);
    let credential: Credential;

    if (Buffer.isBuffer(entry.credential)) {
      credential = new Credential();

      if (credential.fromBuffer(entry.credential) !== entry.credential.length) {
        throw new Error("Trailing authorization credential bytes.");
      }
    } else {
      // Preserve the original flags for validation; reconstruction from JSON can
      // recalculate them and hide an inconsistent envelope.
      credential = snapshotRequestValue(entry.credential);
    }

    if (!credential.isValid() || !credential.flags.eq(credential.calcFlags())) {
      throw new Error("Invalid credential envelope in authorization content.");
    }

    let record: AppAuthorizationRecord;

    switch (credential.credentialKey) {
      case AuthorizationCredential.CREDENTIAL_KEY:
        record = AuthorizationCredential.fromCredential(credential);
        break;
      case AuthorizationStorageBindingCredential.CREDENTIAL_KEY:
        record = AuthorizationStorageBindingCredential.fromCredential(credential);
        break;
      case AuthorizationStorageKeyCredential.CREDENTIAL_KEY:
        record = AuthorizationStorageKeyCredential.fromCredential(credential);
        break;
      default:
        continue;
    }

    decoded.push({ record, source: snapshotRequestValue(entry.source) });
  }

  return decoded;
}

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
  verifyStorageControl: (
    binding: AuthorizationStorageBindingCredential,
    keys: AuthorizationStorageKeyCredential[]
  ) => Promise<boolean>;
}

/**
 * Check the public half of a stored relationship against fresh RPC state.
 * Wallet ownership of the user key and R/C (including their dependencies) is a
 * separate required check; a matching public address does not prove control.
 */
export function verifyAppAuthorizationStorageState(
  binding: AuthorizationStorageBindingCredential,
  keys: AuthorizationStorageKeyCredential[],
  current: IdentityRevision
): boolean {
  try {
    binding.toPayload();
    const data = binding.data;

    const primaryKeys = validateIdentityRevision(current, {
      identityID: data.storageID,
      systemID: data.storageSystemID,
    });

    if (
      current.status !== "active" ||
      current.identity.minimumsignatures !== 1 ||
      current.identity.revocationauthority !== data.revocationID ||
      current.identity.recoveryauthority !== data.recoveryID ||
      data.storageID === data.revocationID ||
      data.storageID === data.recoveryID ||
      keys.length !== data.keyCount
    ) {
      return false;
    }

    const userKeyID = data.userKeyID.toLowerCase();
    const appKeyIDs = new Set<string>();
    const keyIndices = new Set<number>();

    if (!primaryKeys.has(userKeyID)) return false;

    for (const key of keys) {
      key.toPayload();
      const keyID = key.data.keyID.toLowerCase();

      if (
        key.data.grantID.toLowerCase() !== data.grantID.toLowerCase() ||
        key.data.relationshipIndex !== data.relationshipIndex ||
        key.data.keyIndex >= data.keyCount ||
        keyIndices.has(key.data.keyIndex) ||
        appKeyIDs.has(keyID) ||
        keyID === userKeyID ||
        !primaryKeys.has(keyID)
      ) {
        return false;
      }

      keyIndices.add(key.data.keyIndex);
      appKeyIDs.add(keyID);
    }

    return true;
  } catch {
    return false;
  }
}

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
export async function verifyDelegatedAppAuthorization(
  options: DelegatedAppAuthorizationOptions
): Promise<SourcedAppAuthorizationRecord<AuthorizationCredential> | undefined> {
  // Snapshot before any callback can await or mutate caller-owned records.
  const { records, user, delegate, appID } = snapshotRequestValue(options);
  const { verifyDelegatorProfile, verifyUserControl, verifyAuthority, verifyStorageControl } = options;

  try {
    for (const address of [
      user.systemID, user.identityID, delegate.systemID, delegate.identityID, appID,
    ]) {
      decodeDestination(address, I_ADDR_VERSION);
    }

    if (
      typeof verifyDelegatorProfile !== "function" ||
      typeof verifyUserControl !== "function" ||
      typeof verifyAuthority !== "function" ||
      typeof verifyStorageControl !== "function"
    ) {
      return undefined;
    }

    // Existing approvals cannot bypass a profile introduced after they were
    // written. This policy is scoped to A on D's signing system, never U's.
    await verifyDelegatorProfile({ identityID: appID, systemID: delegate.systemID });
    if (await verifyUserControl(snapshotRequestValue(user)) !== true) return undefined;

    // Never let a management record from another U or system complete a grant.
    const sourcedRecords = records.filter(({ source }) =>
      source.identityID === user.identityID && source.systemID === user.systemID
    );

    for (const { record, source } of sourcedRecords) {
      validateSource(source);
      record.toPayload();
    }

    const grants = sourcedRecords.filter(
      (entry): entry is SourcedAppAuthorizationRecord<AuthorizationCredential> =>
        entry.record instanceof AuthorizationCredential &&
        entry.record.data.signingSystemID === delegate.systemID &&
        entry.record.data.delegateID === delegate.identityID &&
        entry.record.data.appID === appID
    );

    for (const grant of grants) {
      const grantID = grant.record.data.grantID.toLowerCase();
      const payload = JSON.stringify(grant.record.toPayload());
      const sameGrant = sourcedRecords.filter(
        ({ record }) => record.data.grantID.toLowerCase() === grantID
      );

      // Multiple stored copies are allowed, but one ID cannot describe competing
      // approvals. Preserve all copies in the decoded index for later deletion.
      if (sameGrant.some(({ record }) =>
        record instanceof AuthorizationCredential &&
        JSON.stringify(record.toPayload()) !== payload
      )) {
        continue;
      }

      const storageRecords = sameGrant
        .map(({ record }) => record)
        .filter((record): record is AuthorizationStorageRecord =>
          record instanceof AuthorizationStorageBindingCredential ||
          record instanceof AuthorizationStorageKeyCredential
        );

      if (!verifyAppAuthorizationStorageManifest(grant.record, storageRecords)) {
        continue;
      }

      const bindings = new Map<number, AuthorizationStorageBindingCredential>();
      const keys = new Map<string, AuthorizationStorageKeyCredential>();

      for (const record of storageRecords) {
        if (record instanceof AuthorizationStorageBindingCredential) {
          bindings.set(record.data.relationshipIndex, record);
        } else {
          keys.set(record.recordID, record);
        }
      }

      // The manifest proves record completeness, not relationship suitability.
      if ([...bindings.values()].some(({ data }) =>
        data.storageSystemID !== delegate.systemID ||
        data.storageID === user.identityID ||
        data.storageID === data.revocationID ||
        data.storageID === data.recoveryID
      )) {
        continue;
      }

      let storageValid = true;

      try {
        if (await verifyAuthority(snapshotRequestValue(grant.record)) !== true) {
          continue;
        }

        for (const binding of bindings.values()) {
          const relationshipKeys = [...keys.values()].filter(
            ({ data }) => data.relationshipIndex === binding.data.relationshipIndex
          );

          if (await verifyStorageControl(
            snapshotRequestValue(binding),
            snapshotRequestValue(relationshipKeys)
          ) !== true) {
            storageValid = false;
            break;
          }
        }
      } catch (error) {
        if (error instanceof UnsupportedDelegatorProfileError) throw error;
        // Another independently approved grant may still satisfy every check.
        continue;
      }

      if (storageValid) {
        // Wallet/control callbacks may await user interaction or RPC work.
        // Failure here rejects the entire operation, not just this candidate.
        await verifyDelegatorProfile({ identityID: appID, systemID: delegate.systemID });
        return grant;
      }
    }
  } catch (error) {
    if (error instanceof UnsupportedDelegatorProfileError) throw error;
    // An incomplete/malformed view or unavailable user state cannot authorize.
  }

  return undefined;
}
