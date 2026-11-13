"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeAuthorizationKeyID = exports.loadOriginalAuthorizationIdentity = exports.loadAuthorizationIdentity = exports.validateAuthorizationIdentity = void 0;
exports.inspectAuthorizationSigners = inspectAuthorizationSigners;
const bn_js_1 = __importDefault(require("bn.js"));
const utxo_lib_1 = require("@bitgo/utxo-lib");
const verus_typescript_primitives_1 = require("verus-typescript-primitives");
const identityAuthority_1 = require("../identity/identityAuthority");
const signatures_1 = require("../identity/signatures");
// Preserve the first authorization API while exposing the underlying identity
// helpers from their general-purpose module.
var identityAuthority_2 = require("../identity/identityAuthority");
Object.defineProperty(exports, "validateAuthorizationIdentity", { enumerable: true, get: function () { return identityAuthority_2.validateIdentityRevision; } });
Object.defineProperty(exports, "loadAuthorizationIdentity", { enumerable: true, get: function () { return identityAuthority_2.loadIdentityRevision; } });
Object.defineProperty(exports, "loadOriginalAuthorizationIdentity", { enumerable: true, get: function () { return identityAuthority_2.loadIdentityRevisionAtOutpoint; } });
/** Preserve the original unary callback contract for existing Array.map callers. */
const normalizeAuthorizationKeyID = (primary) => (0, identityAuthority_1.normalizeIdentityKeyID)(primary);
exports.normalizeAuthorizationKeyID = normalizeAuthorizationKeyID;
/**
 * Verify the original/current intersection on the very same signed digest used
 * by ordinary identity verification. Omit original only for bootstrap admission.
 * This proves signer policy, not user control, effective grant membership, or
 * storage eligibility; callers must still establish those independently.
 */
function inspectAuthorizationSigners(envelope, signedIdentity, currentIdentity, originalIdentity) {
    var _a, _b;
    if (!envelope.isSigned() || !((_b = (_a = envelope.signature) === null || _a === void 0 ? void 0 : _a.signatureAsVch) === null || _b === void 0 ? void 0 : _b.length)) {
        throw new Error("Authorization requires a signed envelope.");
    }
    const metadata = envelope.signature;
    if (!bn_js_1.default.isBN(metadata.version) ||
        metadata.version.lt(verus_typescript_primitives_1.VerifiableSignatureData.FIRST_VERSION) ||
        metadata.version.gt(verus_typescript_primitives_1.VerifiableSignatureData.LAST_VERSION) ||
        !bn_js_1.default.isBN(metadata.flags) ||
        metadata.flags.isNeg() ||
        !metadata.flags
            .and(verus_typescript_primitives_1.VerifiableSignatureData.FLAG_HAS_SYSTEM)
            .eq(metadata.flags) ||
        !bn_js_1.default.isBN(metadata.signatureVersion) ||
        !bn_js_1.default.isBN(metadata.hashType) ||
        metadata.vdxfKeys !== undefined ||
        metadata.vdxfKeyNames !== undefined ||
        metadata.boundHashes !== undefined ||
        metadata.statements !== undefined) {
        throw new Error("Unsupported authorization signature metadata.");
    }
    // Extra signature metadata is deliberately unsupported in this protocol.
    // Check unflagged fields too: hashing and serialization must describe the
    // same request, even when the caller supplies a mutable in-memory object.
    for (const compact of [metadata.identityID, metadata.systemID]) {
        if (!(compact instanceof verus_typescript_primitives_1.CompactIAddressObject) ||
            !compact.BNType.eq(verus_typescript_primitives_1.CompactIAddressObject.TYPE_I_ADDRESS) ||
            compact.version.lt(verus_typescript_primitives_1.CompactIAddressObject.FIRST_VERSION) ||
            compact.version.gt(verus_typescript_primitives_1.CompactIAddressObject.LAST_VERSION)) {
            throw new Error("Signature identities must use canonical compact identity addresses.");
        }
    }
    const binding = {
        identityID: metadata.identityID.toIAddress(),
        systemID: metadata.systemID.toIAddress(),
    };
    if (!metadata.hasSystem() &&
        binding.systemID !==
            (envelope.isTestnet() ? verus_typescript_primitives_1.TESTNET_VERUS_CHAINID : verus_typescript_primitives_1.DEFAULT_VERUS_CHAINID)) {
        throw new Error("An unflagged signature system must match the envelope network default.");
    }
    const signedPolicy = (0, identityAuthority_1.validateIdentityRevision)(signedIdentity, binding);
    const currentPolicy = (0, identityAuthority_1.validateIdentityRevision)(currentIdentity, binding);
    const originalPolicy = originalIdentity
        ? (0, identityAuthority_1.validateIdentityRevision)(originalIdentity, binding)
        : currentPolicy;
    const signature = new utxo_lib_1.IdentitySignature(utxo_lib_1.networks.verus);
    const consumed = signature.fromBuffer(metadata.signatureAsVch, 0, binding.systemID, binding.identityID);
    // Supply storage explicitly: the dependency's allocator undercounts multiple
    // compact-signature length prefixes. Its existing writer remains canonical.
    const canonical = Buffer.alloc(metadata.signatureAsVch.length);
    const written = signature.toBuffer(canonical);
    if (consumed !== metadata.signatureAsVch.length ||
        written !== canonical.length ||
        !canonical.equals(metadata.signatureAsVch) ||
        !metadata.signatureVersion.eqn(signature.version) ||
        !metadata.hashType.eqn(signature.hashType)) {
        throw new Error("Inconsistent or noncanonical authorization signature.");
    }
    (0, verus_typescript_primitives_1.assertUint32)(signature.blockHeight);
    if (signedIdentity.blockheight > signature.blockHeight) {
        throw new Error("Signed identity revision is newer than the signature.");
    }
    const eligible = new Set([...originalPolicy].filter((key) => currentPolicy.has(key)));
    const requiredSignatures = Math.max(currentIdentity.identity.minimumsignatures, (originalIdentity === null || originalIdentity === void 0 ? void 0 : originalIdentity.identity.minimumsignatures) ||
        currentIdentity.identity.minimumsignatures);
    const evidence = {
        signedHeight: signature.blockHeight,
        signedKeyIDs: [],
        eligibleKeyIDs: [...eligible],
        requiredSignatures,
        valid: false,
    };
    if ([signedIdentity, currentIdentity, originalIdentity].some((revision) => revision && revision.status !== "active")) {
        return evidence;
    }
    if (!signature.signatures.length)
        return evidence;
    const digest = envelope.getDetailsIdentitySignatureHash(signature.blockHeight);
    const signers = (0, signatures_1.recoverIdentitySignatureSigners)(digest, signature.signatures);
    evidence.signedKeyIDs = signers.flatMap((signer) => signer.keyIDs);
    const signedAtHeight = signers.filter((signer) => signer.keyIDs.some((key) => signedPolicy.has(key))).length;
    const eligibleSigners = signers.filter((signer) => signer.keyIDs.some((key) => eligible.has(key))).length;
    evidence.valid =
        signedAtHeight >= signedIdentity.identity.minimumsignatures &&
            eligibleSigners >= requiredSignatures;
    return evidence;
}
