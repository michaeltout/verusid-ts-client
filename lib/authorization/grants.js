"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decodeAppAuthorizationRecords = decodeAppAuthorizationRecords;
exports.verifyAppAuthorizationStorageState = verifyAppAuthorizationStorageState;
exports.verifyDelegatedAppAuthorization = verifyDelegatedAppAuthorization;
const verus_typescript_primitives_1 = require("verus-typescript-primitives");
const requestSnapshot_1 = require("../utils/requestSnapshot");
const identityAuthority_1 = require("../identity/identityAuthority");
function validateSource(source) {
    for (const address of [source.systemID, source.identityID, source.outerKey]) {
        (0, verus_typescript_primitives_1.decodeDestination)(address, verus_typescript_primitives_1.I_ADDR_VERSION);
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
function decodeAppAuthorizationRecords(entries) {
    const decoded = [];
    for (const entry of entries) {
        validateSource(entry.source);
        let credential;
        if (Buffer.isBuffer(entry.credential)) {
            credential = new verus_typescript_primitives_1.Credential();
            if (credential.fromBuffer(entry.credential) !== entry.credential.length) {
                throw new Error("Trailing authorization credential bytes.");
            }
        }
        else {
            // Preserve the original flags for validation; reconstruction from JSON can
            // recalculate them and hide an inconsistent envelope.
            credential = (0, requestSnapshot_1.snapshotRequestValue)(entry.credential);
        }
        if (!credential.isValid() || !credential.flags.eq(credential.calcFlags())) {
            throw new Error("Invalid credential envelope in authorization content.");
        }
        let record;
        switch (credential.credentialKey) {
            case verus_typescript_primitives_1.AuthorizationCredential.CREDENTIAL_KEY:
                record = verus_typescript_primitives_1.AuthorizationCredential.fromCredential(credential);
                break;
            case verus_typescript_primitives_1.AuthorizationStorageBindingCredential.CREDENTIAL_KEY:
                record = verus_typescript_primitives_1.AuthorizationStorageBindingCredential.fromCredential(credential);
                break;
            case verus_typescript_primitives_1.AuthorizationStorageKeyCredential.CREDENTIAL_KEY:
                record = verus_typescript_primitives_1.AuthorizationStorageKeyCredential.fromCredential(credential);
                break;
            default:
                continue;
        }
        decoded.push({ record, source: (0, requestSnapshot_1.snapshotRequestValue)(entry.source) });
    }
    return decoded;
}
/**
 * Check the public half of a stored relationship against fresh RPC state.
 * Wallet ownership of the user key and R/C (including their dependencies) is a
 * separate required check; a matching public address does not prove control.
 */
function verifyAppAuthorizationStorageState(binding, keys, current) {
    try {
        binding.toPayload();
        const data = binding.data;
        const primaryKeys = (0, identityAuthority_1.validateIdentityRevision)(current, {
            identityID: data.storageID,
            systemID: data.storageSystemID,
        });
        if (current.status !== "active" ||
            current.identity.minimumsignatures !== 1 ||
            current.identity.revocationauthority !== data.revocationID ||
            current.identity.recoveryauthority !== data.recoveryID ||
            data.storageID === data.revocationID ||
            data.storageID === data.recoveryID ||
            keys.length !== data.keyCount) {
            return false;
        }
        const userKeyID = data.userKeyID.toLowerCase();
        const appKeyIDs = new Set();
        const keyIndices = new Set();
        if (!primaryKeys.has(userKeyID))
            return false;
        for (const key of keys) {
            key.toPayload();
            const keyID = key.data.keyID.toLowerCase();
            if (key.data.grantID.toLowerCase() !== data.grantID.toLowerCase() ||
                key.data.relationshipIndex !== data.relationshipIndex ||
                key.data.keyIndex >= data.keyCount ||
                keyIndices.has(key.data.keyIndex) ||
                appKeyIDs.has(keyID) ||
                keyID === userKeyID ||
                !primaryKeys.has(keyID)) {
                return false;
            }
            keyIndices.add(key.data.keyIndex);
            appKeyIDs.add(keyID);
        }
        return true;
    }
    catch (_a) {
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
function verifyDelegatedAppAuthorization(options) {
    return __awaiter(this, void 0, void 0, function* () {
        // Snapshot before any callback can await or mutate caller-owned records.
        const { records, user, delegate, appID } = (0, requestSnapshot_1.snapshotRequestValue)(options);
        const { verifyDelegatorProfile, verifyUserControl, verifyAuthority, verifyStorageControl } = options;
        try {
            for (const address of [
                user.systemID, user.identityID, delegate.systemID, delegate.identityID, appID,
            ]) {
                (0, verus_typescript_primitives_1.decodeDestination)(address, verus_typescript_primitives_1.I_ADDR_VERSION);
            }
            if (typeof verifyDelegatorProfile !== "function" ||
                typeof verifyUserControl !== "function" ||
                typeof verifyAuthority !== "function" ||
                typeof verifyStorageControl !== "function") {
                return undefined;
            }
            // Existing approvals cannot bypass a profile introduced after they were
            // written. This policy is scoped to A on D's signing system, never U's.
            yield verifyDelegatorProfile({ identityID: appID, systemID: delegate.systemID });
            if ((yield verifyUserControl((0, requestSnapshot_1.snapshotRequestValue)(user))) !== true)
                return undefined;
            // Never let a management record from another U or system complete a grant.
            const sourcedRecords = records.filter(({ source }) => source.identityID === user.identityID && source.systemID === user.systemID);
            for (const { record, source } of sourcedRecords) {
                validateSource(source);
                record.toPayload();
            }
            const grants = sourcedRecords.filter((entry) => entry.record instanceof verus_typescript_primitives_1.AuthorizationCredential &&
                entry.record.data.signingSystemID === delegate.systemID &&
                entry.record.data.delegateID === delegate.identityID &&
                entry.record.data.appID === appID);
            for (const grant of grants) {
                const grantID = grant.record.data.grantID.toLowerCase();
                const payload = JSON.stringify(grant.record.toPayload());
                const sameGrant = sourcedRecords.filter(({ record }) => record.data.grantID.toLowerCase() === grantID);
                // Multiple stored copies are allowed, but one ID cannot describe competing
                // approvals. Preserve all copies in the decoded index for later deletion.
                if (sameGrant.some(({ record }) => record instanceof verus_typescript_primitives_1.AuthorizationCredential &&
                    JSON.stringify(record.toPayload()) !== payload)) {
                    continue;
                }
                const storageRecords = sameGrant
                    .map(({ record }) => record)
                    .filter((record) => record instanceof verus_typescript_primitives_1.AuthorizationStorageBindingCredential ||
                    record instanceof verus_typescript_primitives_1.AuthorizationStorageKeyCredential);
                if (!(0, verus_typescript_primitives_1.verifyAppAuthorizationStorageManifest)(grant.record, storageRecords)) {
                    continue;
                }
                const bindings = new Map();
                const keys = new Map();
                for (const record of storageRecords) {
                    if (record instanceof verus_typescript_primitives_1.AuthorizationStorageBindingCredential) {
                        bindings.set(record.data.relationshipIndex, record);
                    }
                    else {
                        keys.set(record.recordID, record);
                    }
                }
                // The manifest proves record completeness, not relationship suitability.
                if ([...bindings.values()].some(({ data }) => data.storageSystemID !== delegate.systemID ||
                    data.storageID === user.identityID ||
                    data.storageID === data.revocationID ||
                    data.storageID === data.recoveryID)) {
                    continue;
                }
                let storageValid = true;
                try {
                    if ((yield verifyAuthority((0, requestSnapshot_1.snapshotRequestValue)(grant.record))) !== true) {
                        continue;
                    }
                    for (const binding of bindings.values()) {
                        const relationshipKeys = [...keys.values()].filter(({ data }) => data.relationshipIndex === binding.data.relationshipIndex);
                        if ((yield verifyStorageControl((0, requestSnapshot_1.snapshotRequestValue)(binding), (0, requestSnapshot_1.snapshotRequestValue)(relationshipKeys))) !== true) {
                            storageValid = false;
                            break;
                        }
                    }
                }
                catch (error) {
                    if (error instanceof verus_typescript_primitives_1.UnsupportedDelegatorProfileError)
                        throw error;
                    // Another independently approved grant may still satisfy every check.
                    continue;
                }
                if (storageValid) {
                    // Wallet/control callbacks may await user interaction or RPC work.
                    // Failure here rejects the entire operation, not just this candidate.
                    yield verifyDelegatorProfile({ identityID: appID, systemID: delegate.systemID });
                    return grant;
                }
            }
        }
        catch (error) {
            if (error instanceof verus_typescript_primitives_1.UnsupportedDelegatorProfileError)
                throw error;
            // An incomplete/malformed view or unavailable user state cannot authorize.
        }
        return undefined;
    });
}
