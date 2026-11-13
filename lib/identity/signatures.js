"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.recoverIdentitySignatureSigners = recoverIdentitySignatureSigners;
const utxo_lib_1 = require("@bitgo/utxo-lib");
/**
 * Recover distinct actual signers from compact identity signatures over a digest.
 * Invalid signatures contribute no signer. Authority membership and thresholds
 * remain the caller's policy; a signer may have no authority for the operation.
 */
function recoverIdentitySignatureSigners(digest, signatures) {
    const signers = new Map();
    for (const bytes of signatures) {
        try {
            const parsed = utxo_lib_1.ECSignature.parseCompact(bytes);
            const key = utxo_lib_1.ECPair.recoverFromSignature(digest, bytes, utxo_lib_1.networks.verus);
            if (key.verify(digest, parsed.signature)) {
                // Membership follows the compact signature's encoding. Counting follows
                // the curve point so toggling compression cannot create a second signer.
                const keyID = utxo_lib_1.crypto.hash160(key.getPublicKeyBuffer()).toString("hex");
                key.compressed = true;
                const publicKey = key.getPublicKeyBuffer().toString("hex");
                const encodings = signers.get(publicKey) || new Set();
                encodings.add(keyID);
                signers.set(publicKey, encodings);
            }
        }
        catch (_a) {
            // Match ordinary identity verification without logging malformed signatures.
        }
    }
    return [...signers].map(([publicKey, keyIDs]) => ({
        publicKey,
        keyIDs: [...keyIDs],
    }));
}
