import { crypto, ECPair, ECSignature, networks } from "@bitgo/utxo-lib";

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
export function recoverIdentitySignatureSigners(
  digest: Buffer,
  signatures: readonly Buffer[]
): VerifiedIdentitySigner[] {
  const signers = new Map<string, Set<string>>();

  for (const bytes of signatures) {
    try {
      const parsed = ECSignature.parseCompact(bytes);
      const key = ECPair.recoverFromSignature(digest, bytes, networks.verus);

      if (key.verify(digest, parsed.signature)) {
        // Membership follows the compact signature's encoding. Counting follows
        // the curve point so toggling compression cannot create a second signer.
        const keyID = crypto.hash160(key.getPublicKeyBuffer()).toString("hex");
        key.compressed = true;
        const publicKey = key.getPublicKeyBuffer().toString("hex");
        const encodings = signers.get(publicKey) || new Set<string>();
        encodings.add(keyID);
        signers.set(publicKey, encodings);
      }
    } catch {
      // Match ordinary identity verification without logging malformed signatures.
    }
  }

  return [...signers].map(([publicKey, keyIDs]) => ({
    publicKey,
    keyIDs: [...keyIDs],
  }));
}
