import BN from "bn.js";
import { IdentitySignature, networks } from "@bitgo/utxo-lib";
import {
  CompactIAddressObject,
  DEFAULT_VERUS_CHAINID,
  TESTNET_VERUS_CHAINID,
  VerifiableSignatureData,
  assertUint32,
} from "verus-typescript-primitives";
import { GenericEnvelope } from "verus-typescript-primitives/dist/vdxf/classes/envelope/GenericEnvelope";
import {
  IdentityRevision as AuthorizationIdentityRevision,
  normalizeIdentityKeyID,
  validateIdentityRevision as validateAuthorizationIdentity,
} from "../identity/identityAuthority";
import { recoverIdentitySignatureSigners } from "../identity/signatures";

// Preserve the first authorization API while exposing the underlying identity
// helpers from their general-purpose module.
export {
  validateIdentityRevision as validateAuthorizationIdentity,
  loadIdentityRevision as loadAuthorizationIdentity,
  loadIdentityRevisionAtOutpoint as loadOriginalAuthorizationIdentity,
} from "../identity/identityAuthority";

/** Preserve the original unary callback contract for existing Array.map callers. */
export const normalizeAuthorizationKeyID = (primary: string): string =>
  normalizeIdentityKeyID(primary);
export type {
  IdentityBinding as AuthorizationIdentityBinding,
  IdentitySource as AuthorizationIdentitySource,
  IdentityRevisionReference as AuthorizationOriginalRevision,
  IdentityRevision as AuthorizationIdentityRevision,
} from "../identity/identityAuthority";

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
export function inspectAuthorizationSigners(
  envelope: GenericEnvelope,
  signedIdentity: AuthorizationIdentityRevision,
  currentIdentity: AuthorizationIdentityRevision,
  originalIdentity?: AuthorizationIdentityRevision
): AuthorizationSignerEvidence {
  if (!envelope.isSigned() || !envelope.signature?.signatureAsVch?.length) {
    throw new Error("Authorization requires a signed envelope.");
  }

  const metadata = envelope.signature;

  if (
    !BN.isBN(metadata.version) ||
    metadata.version.lt(VerifiableSignatureData.FIRST_VERSION) ||
    metadata.version.gt(VerifiableSignatureData.LAST_VERSION) ||
    !BN.isBN(metadata.flags) ||
    metadata.flags.isNeg() ||
    !metadata.flags
      .and(VerifiableSignatureData.FLAG_HAS_SYSTEM)
      .eq(metadata.flags) ||
    !BN.isBN(metadata.signatureVersion) ||
    !BN.isBN(metadata.hashType) ||
    metadata.vdxfKeys !== undefined ||
    metadata.vdxfKeyNames !== undefined ||
    metadata.boundHashes !== undefined ||
    metadata.statements !== undefined
  ) {
    throw new Error("Unsupported authorization signature metadata.");
  }

  // Extra signature metadata is deliberately unsupported in this protocol.
  // Check unflagged fields too: hashing and serialization must describe the
  // same request, even when the caller supplies a mutable in-memory object.
  for (const compact of [metadata.identityID, metadata.systemID]) {
    if (
      !(compact instanceof CompactIAddressObject) ||
      !compact.BNType.eq(CompactIAddressObject.TYPE_I_ADDRESS) ||
      compact.version.lt(CompactIAddressObject.FIRST_VERSION) ||
      compact.version.gt(CompactIAddressObject.LAST_VERSION)
    ) {
      throw new Error(
        "Signature identities must use canonical compact identity addresses."
      );
    }
  }

  const binding = {
    identityID: metadata.identityID.toIAddress(),
    systemID: metadata.systemID.toIAddress(),
  };

  if (
    !metadata.hasSystem() &&
    binding.systemID !==
      (envelope.isTestnet() ? TESTNET_VERUS_CHAINID : DEFAULT_VERUS_CHAINID)
  ) {
    throw new Error(
      "An unflagged signature system must match the envelope network default."
    );
  }

  const signedPolicy = validateAuthorizationIdentity(signedIdentity, binding);
  const currentPolicy = validateAuthorizationIdentity(currentIdentity, binding);
  const originalPolicy = originalIdentity
    ? validateAuthorizationIdentity(originalIdentity, binding)
    : currentPolicy;

  const signature = new IdentitySignature(networks.verus);
  const consumed = signature.fromBuffer(
    metadata.signatureAsVch,
    0,
    binding.systemID,
    binding.identityID
  );
  // Supply storage explicitly: the dependency's allocator undercounts multiple
  // compact-signature length prefixes. Its existing writer remains canonical.
  const canonical = Buffer.alloc(metadata.signatureAsVch.length);
  const written = signature.toBuffer(canonical);

  if (
    consumed !== metadata.signatureAsVch.length ||
    written !== canonical.length ||
    !canonical.equals(metadata.signatureAsVch) ||
    !metadata.signatureVersion.eqn(signature.version) ||
    !metadata.hashType.eqn(signature.hashType)
  ) {
    throw new Error("Inconsistent or noncanonical authorization signature.");
  }

  assertUint32(signature.blockHeight);

  if (signedIdentity.blockheight > signature.blockHeight) {
    throw new Error("Signed identity revision is newer than the signature.");
  }

  const eligible = new Set(
    [...originalPolicy].filter((key) => currentPolicy.has(key))
  );
  const requiredSignatures = Math.max(
    currentIdentity.identity.minimumsignatures,
    originalIdentity?.identity.minimumsignatures ||
      currentIdentity.identity.minimumsignatures
  );
  const evidence: AuthorizationSignerEvidence = {
    signedHeight: signature.blockHeight,
    signedKeyIDs: [],
    eligibleKeyIDs: [...eligible],
    requiredSignatures,
    valid: false,
  };

  if (
    [signedIdentity, currentIdentity, originalIdentity].some(
      (revision) => revision && revision.status !== "active"
    )
  ) {
    return evidence;
  }

  if (!signature.signatures.length) return evidence;

  const digest = envelope.getDetailsIdentitySignatureHash(
    signature.blockHeight
  );
  const signers = recoverIdentitySignatureSigners(digest, signature.signatures);
  evidence.signedKeyIDs = signers.flatMap((signer) => signer.keyIDs);

  const signedAtHeight = signers.filter((signer) =>
    signer.keyIDs.some((key) => signedPolicy.has(key))
  ).length;
  const eligibleSigners = signers.filter((signer) =>
    signer.keyIDs.some((key) => eligible.has(key))
  ).length;

  evidence.valid =
    signedAtHeight >= signedIdentity.identity.minimumsignatures &&
    eligibleSigners >= requiredSignatures;
  return evidence;
}
