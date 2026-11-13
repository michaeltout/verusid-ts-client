export interface VerifiedIdentitySigner {
    /** Canonical compressed public-key bytes identify the underlying EC point. */
    publicKey: string;
    /** Actual signed encodings retain their distinct Core key-ID membership. */
    keyIDs: string[];
}
/**
 * Recover distinct actual signers from compact identity signatures over a digest.
 * Invalid signatures contribute no signer. Authority membership and thresholds
 * remain the caller's policy; a signer may have no authority for the operation.
 */
export declare function recoverIdentitySignatureSigners(digest: Buffer, signatures: readonly Buffer[]): VerifiedIdentitySigner[];
