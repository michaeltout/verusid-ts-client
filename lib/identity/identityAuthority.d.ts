import { AppAuthorizationIdentity, AuthorizationCredentialData, GetIdentityResponse, Identity } from "verus-typescript-primitives";
import { VerusdRpcInterface } from "verusd-rpc-ts-client";
export declare const MAX_IDENTITY_PRIMARY_AUTHORITIES = 25;
export declare const MAX_IDENTITY_SIGNATURE_THRESHOLD = 13;
export type IdentityBinding = AppAuthorizationIdentity;
export type IdentityRevisionReference = AuthorizationCredentialData["originalRevision"];
/** The system comes from the configured RPC connection, not request display data. */
export interface IdentitySource {
    rpc: Pick<VerusdRpcInterface, "chain" | "getIdentity" | "request">;
    systemID: string;
}
/** Keep lookup-chain provenance separate from an identity's home systemid. */
export type IdentityRevision = GetIdentityResponse["result"] & {
    systemID: string;
};
/** Check before upgrading, which would also promote invalid old versions. */
export declare function validateIdentityVersion(version: Identity["version"]): void;
/** Share the daemon's threshold bounds between JSON authorities and typed identity builders. */
export declare function validateIdentityThreshold(minimumSignatures: Identity["minSigs"] | number, keyCount?: number): void;
/** Public-key and public-key-hash representations identify the same authority. */
export declare function normalizeIdentityKeyID(primary: string | Buffer, network?: {
    pubKeyHash: number;
}): string;
/** Normalize primary membership without letting duplicate encodings inflate the threshold. */
export declare function getIdentityPrimaryKeyIDs(primaryAddresses: readonly string[], minimumSignatures: number, network?: {
    pubKeyHash: number;
}): Set<string>;
/** Validate RPC state and its source binding, returning normalized primary membership. */
export declare function validateIdentityRevision(revision: IdentityRevision, binding: IdentityBinding): Set<string>;
/** Always fetch current state anew when height is omitted; no authority cache. */
export declare function loadIdentityRevision(source: IdentitySource, binding: IdentityBinding, height?: number): Promise<IdentityRevision>;
/** Resolve the approved outpoint exactly, including multiple updates in one block. */
export declare function loadIdentityRevisionAtOutpoint(source: IdentitySource, binding: IdentityBinding, original: IdentityRevisionReference): Promise<IdentityRevision>;
