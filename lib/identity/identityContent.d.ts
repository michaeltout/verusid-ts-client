import { VerusdRpcInterface } from "verusd-rpc-ts-client";
import { IdentityBinding, IdentityRevision, IdentitySource } from "./identityAuthority";
/** The source system identifies the configured lookup chain, not an identity's home system. */
export interface IdentityContentSource extends IdentitySource {
    rpc: IdentitySource["rpc"] & Pick<VerusdRpcInterface, "getInfo" | "getBlock" | "getIdentityContent">;
}
export interface IdentityContentSnapshot {
    /** Raw effective CMM is retained under revision.identity.contentmultimap. */
    revision: IdentityRevision;
    readHeight: number;
    blockHash: string;
}
/**
 * Load complete removal-aware content for a key at a confirmed chain revision.
 * Recheck the active block and identity outpoint before returning the snapshot.
 * Values are not decoded and results are not cached; consumers apply their own
 * credential/profile policy to the raw CMM after this provenance check.
 */
export declare function loadCurrentIdentityContent(source: IdentityContentSource, binding: IdentityBinding, vdxfKey: string): Promise<IdentityContentSnapshot>;
