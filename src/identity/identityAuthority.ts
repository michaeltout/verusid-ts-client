import BN from "bn.js";
import { crypto, ECPair, networks } from "@bitgo/utxo-lib";
import {
  ApiRequest,
  AppAuthorizationIdentity,
  AuthorizationCredentialData,
  GetIdentityResponse,
  IDENTITY_FLAG_REVOKED,
  Identity,
  assertUint32,
  fromBase58Check,
  normalizeFixedLengthHex,
} from "verus-typescript-primitives";
import {
  HASH160_BYTE_LENGTH,
  HASH256_BYTE_LENGTH,
} from "verus-typescript-primitives/dist/constants/vdxf";
import { VerusdRpcInterface } from "verusd-rpc-ts-client";
import { validAddress } from "./fundingPrimitives";

export const MAX_IDENTITY_PRIMARY_AUTHORITIES = 25;
export const MAX_IDENTITY_SIGNATURE_THRESHOLD = 13;
const GET_IDENTITY_HISTORY = "getidentityhistory";

export type IdentityBinding = AppAuthorizationIdentity;
export type IdentityRevisionReference =
  AuthorizationCredentialData["originalRevision"];

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
export function validateIdentityVersion(version: Identity["version"]): void {
  if (
    !BN.isBN(version) ||
    version.lt(Identity.VERSION_FIRSTVALID) ||
    version.gt(Identity.VERSION_LASTVALID)
  ) {
    throw new Error("Unsupported identity version.");
  }
}

/** Share the daemon's threshold bounds between JSON authorities and typed identity builders. */
export function validateIdentityThreshold(
  minimumSignatures: Identity["minSigs"] | number,
  keyCount = MAX_IDENTITY_PRIMARY_AUTHORITIES
): void {
  const valid = BN.isBN(minimumSignatures)
    ? minimumSignatures.gten(1) &&
      minimumSignatures.lten(MAX_IDENTITY_SIGNATURE_THRESHOLD) &&
      minimumSignatures.lten(keyCount)
    : Number.isInteger(minimumSignatures) &&
      minimumSignatures! >= 1 &&
      minimumSignatures! <= MAX_IDENTITY_SIGNATURE_THRESHOLD &&
      minimumSignatures! <= keyCount;

  if (!valid) {
    throw new Error(
      `Identity signature threshold must be 1 to ${MAX_IDENTITY_SIGNATURE_THRESHOLD} and no greater than its primary key count.`
    );
  }
}

/** Public-key and public-key-hash representations identify the same authority. */
export function normalizeIdentityKeyID(
  primary: string | Buffer,
  network: { pubKeyHash: number } = networks.verus
): string {
  if (
    Buffer.isBuffer(primary) ||
    (typeof primary === "string" &&
      /^(?:(?:02|03)[0-9a-fA-F]{64}|04[0-9a-fA-F]{128})$/.test(primary))
  ) {
    const publicKey = Buffer.isBuffer(primary)
      ? primary
      : Buffer.from(primary, "hex");
    // Curve validation is independent of address versions; ECPair requires a
    // complete network object even when only validating public-key bytes.
    ECPair.fromPublicKeyBuffer(publicKey, networks.verus);
    return crypto.hash160(publicKey).toString("hex");
  }

  if (typeof primary !== "string") {
    throw new Error(
      "Identity primary authority must be a public key or key hash."
    );
  }

  const decoded = fromBase58Check(primary);

  if (
    decoded.version !== network.pubKeyHash ||
    decoded.hash.length !== HASH160_BYTE_LENGTH ||
    decoded.hash.equals(Buffer.alloc(HASH160_BYTE_LENGTH))
  ) {
    throw new Error(
      "Identity primary authority must be a nonnull public key or key hash."
    );
  }

  return decoded.hash.toString("hex");
}

/** Normalize primary membership without letting duplicate encodings inflate the threshold. */
export function getIdentityPrimaryKeyIDs(
  primaryAddresses: readonly string[],
  minimumSignatures: number,
  network: { pubKeyHash: number } = networks.verus
): Set<string> {
  if (
    !Array.isArray(primaryAddresses) ||
    primaryAddresses.length < 1 ||
    primaryAddresses.length > MAX_IDENTITY_PRIMARY_AUTHORITIES ||
    primaryAddresses.some((primary) => typeof primary !== "string")
  ) {
    throw new Error("Invalid identity primary authorities.");
  }

  if (!Number.isInteger(minimumSignatures)) {
    throw new Error("Identity signature threshold must be an integer.");
  }

  const keys = new Set(
    primaryAddresses.map((primary) => normalizeIdentityKeyID(primary, network))
  );
  validateIdentityThreshold(minimumSignatures, keys.size);

  return keys;
}

/** Validate RPC state and its source binding, returning normalized primary membership. */
export function validateIdentityRevision(
  revision: IdentityRevision,
  binding: IdentityBinding
): Set<string> {
  validAddress(binding.identityID, true);
  validAddress(binding.systemID, true);

  if (
    !revision ||
    revision.systemID !== binding.systemID ||
    revision.identity?.identityaddress !== binding.identityID
  ) {
    throw new Error("The identity or lookup system does not match.");
  }

  const { version, flags } = revision.identity;

  if (
    !Number.isInteger(version) ||
    (revision.status !== "active" && revision.status !== "revoked")
  ) {
    throw new Error("Unsupported identity state.");
  }

  validateIdentityVersion(new BN(version!));
  assertUint32(flags!);
  const revoked = !new BN(flags!).and(IDENTITY_FLAG_REVOKED).isZero();

  if (revoked !== (revision.status === "revoked")) {
    throw new Error("Inconsistent identity revocation state.");
  }

  assertUint32(revision.blockheight);
  assertUint32(revision.vout);
  normalizeFixedLengthHex(revision.txid, HASH256_BYTE_LENGTH);
  return getIdentityPrimaryKeyIDs(
    revision.identity.primaryaddresses,
    revision.identity.minimumsignatures
  );
}

/** Always fetch current state anew when height is omitted; no authority cache. */
export async function loadIdentityRevision(
  source: IdentitySource,
  binding: IdentityBinding,
  height?: number
): Promise<IdentityRevision> {
  validAddress(binding.systemID, true);
  validAddress(binding.identityID, true);

  if (source.systemID !== binding.systemID) {
    throw new Error("Identity RPC is connected to a different system.");
  }

  if (height !== undefined) assertUint32(height);

  const response = await source.rpc.getIdentity(binding.identityID, height);

  if (response.error || !response.result) {
    throw new Error(response.error?.message || "Identity was not found.");
  }

  const revision = { ...response.result, systemID: source.systemID };
  validateIdentityRevision(revision, binding);

  if (height !== undefined && revision.blockheight > height) {
    throw new Error("Identity revision is newer than the requested height.");
  }

  return {
    ...revision,
    txid: normalizeFixedLengthHex(revision.txid, HASH256_BYTE_LENGTH),
  };
}

// The existing RPC transport supports arbitrary ApiRequests, but has no typed
// getidentityhistory method. Keep this narrow adapter local to revision lookup.
class IdentityHistoryRequest extends ApiRequest {
  constructor(
    chain: string,
    private readonly identityID: string,
    private readonly height: number
  ) {
    super(chain, GET_IDENTITY_HISTORY);
  }

  getParams() {
    return [this.identityID, this.height, this.height];
  }

  toJson() {
    return {
      chain: this.chain,
      identityID: this.identityID,
      height: this.height,
    };
  }
}

/** Resolve the approved outpoint exactly, including multiple updates in one block. */
export async function loadIdentityRevisionAtOutpoint(
  source: IdentitySource,
  binding: IdentityBinding,
  original: IdentityRevisionReference
): Promise<IdentityRevision> {
  assertUint32(original.lookupHeight);
  assertUint32(original.vout);
  const txid = normalizeFixedLengthHex(original.txid, HASH256_BYTE_LENGTH);
  const atHeight = await loadIdentityRevision(
    source,
    binding,
    original.lookupHeight
  );

  if (atHeight.txid === txid && atHeight.vout === original.vout)
    return atHeight;

  const response = await source.rpc.request<{
    history: Array<{
      identity: GetIdentityResponse["result"]["identity"];
      height: number;
      output: { txid: string; voutnum: number };
    }>;
  }>(
    new IdentityHistoryRequest(
      source.rpc.chain,
      binding.identityID,
      original.lookupHeight
    )
  );

  if (response.error || !Array.isArray(response.result?.history)) {
    throw new Error(
      response.error?.message || "Identity revision history is unavailable."
    );
  }

  const matches = response.result!.history.filter(
    (entry) =>
      entry?.output?.txid?.toLowerCase() === txid &&
      entry.output.voutnum === original.vout
  );

  if (matches.length !== 1 || matches[0].height !== original.lookupHeight) {
    throw new Error("The exact original identity revision was not found.");
  }

  const entry = matches[0];
  assertUint32(entry.identity?.flags!);

  const revision: IdentityRevision = {
    identity: entry.identity,
    status: new BN(entry.identity.flags!).and(IDENTITY_FLAG_REVOKED).isZero()
      ? "active"
      : "revoked",
    blockheight: entry.height,
    txid,
    vout: entry.output.voutnum,
    systemID: source.systemID,
    // Historical entries do not report wallet-local capabilities. They must
    // never be interpreted as proof that this wallet controls the identity.
    cansignfor: false,
    canspendfor: false,
  };

  validateIdentityRevision(revision, binding);
  return revision;
}
