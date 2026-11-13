import {
  GetIdentityResponse,
  Identity,
  assertUint32,
  normalizeFixedLengthHex,
} from "verus-typescript-primitives";
import { HASH256_BYTE_LENGTH } from "verus-typescript-primitives/dist/constants/vdxf";
import { VerusdRpcInterface } from "verusd-rpc-ts-client";
import {
  IdentityBinding,
  IdentityRevision,
  IdentitySource,
  loadIdentityRevision,
  validateIdentityRevision,
} from "./identityAuthority";
import { validAddress } from "./fundingPrimitives";

const CONFIRMED_BLOCK_VERBOSITY = 1;
const FIRST_CONTENT_HEIGHT = 0;
const DEFAULT_TX_PROOF_HEIGHT = 0;

/** The source system identifies the configured lookup chain, not an identity's home system. */
export interface IdentityContentSource extends IdentitySource {
  rpc: IdentitySource["rpc"] &
    Pick<VerusdRpcInterface, "getInfo" | "getBlock" | "getIdentityContent">;
}

// Core supplies these bounds in addition to the ordinary identity response.
// Preserve them locally until the RPC response type exposes them directly.
type EffectiveIdentityContent = GetIdentityResponse["result"] & {
  fromheight: number;
  toheight: number;
};

async function confirmedBlockHash(
  rpc: IdentityContentSource["rpc"],
  height: number
): Promise<string> {
  const response = await rpc.getBlock(
    String(height),
    CONFIRMED_BLOCK_VERBOSITY
  );
  const block = response.result;

  if (
    response.error ||
    !block ||
    typeof block === "string" ||
    block.height !== height ||
    !Number.isSafeInteger(block.confirmations) ||
    block.confirmations < 1
  ) {
    throw new Error(
      "A confirmed active block is required to read identity content."
    );
  }

  return normalizeFixedLengthHex(block.hash, HASH256_BYTE_LENGTH);
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
export async function loadCurrentIdentityContent(
  source: IdentityContentSource,
  binding: IdentityBinding,
  vdxfKey: string
): Promise<IdentityContentSnapshot> {
  const { rpc, systemID } = source;
  const chain = rpc.chain;
  const expected = { ...binding };
  const capturedSource = { rpc, systemID };
  const sourceUnchanged = () =>
    source.rpc === rpc &&
    source.systemID === systemID &&
    rpc.chain === chain &&
    binding.systemID === expected.systemID &&
    binding.identityID === expected.identityID;

  if (systemID !== expected.systemID) {
    throw new Error(
      "Identity content must be read on the bound lookup system."
    );
  }

  validAddress(expected.identityID, true);
  validAddress(expected.systemID, true);
  validAddress(vdxfKey, true);

  const infoResponse = await rpc.getInfo();
  const info = infoResponse.result;

  if (
    infoResponse.error ||
    !info ||
    info.chainid !== systemID ||
    info.blocks < 1 ||
    !Number.isSafeInteger(info.longestchain) ||
    info.longestchain < 0 ||
    info.longestchain > info.blocks ||
    !sourceUnchanged()
  ) {
    throw new Error(
      "A synchronized RPC on the bound lookup system is required to read identity content."
    );
  }

  const readHeight = assertUint32(info.blocks);
  const blockHash = await confirmedBlockHash(rpc, readHeight);
  const contentResponse = await rpc.getIdentityContent(
    expected.identityID,
    FIRST_CONTENT_HEIGHT,
    readHeight,
    false,
    DEFAULT_TX_PROOF_HEIGHT,
    vdxfKey
  );
  const content = contentResponse.result as EffectiveIdentityContent | null;

  if (
    contentResponse.error ||
    !content ||
    content.fromheight !== FIRST_CONTENT_HEIGHT ||
    content.toheight !== readHeight ||
    !sourceUnchanged()
  ) {
    throw new Error("A complete effective identity content read is required.");
  }

  const revision = { ...content, systemID };
  validateIdentityRevision(revision, expected);
  const hasEffectiveCmm = Object.prototype.hasOwnProperty.call(
    content.identity,
    "contentmultimap"
  );

  if (
    revision.blockheight < 1 ||
    revision.blockheight > readHeight ||
    (!hasEffectiveCmm &&
      revision.identity.version! >= Identity.VERSION_PBAAS.toNumber())
  ) {
    throw new Error(
      "Identity content is missing its confirmed revision or effective CMM."
    );
  }

  if (!hasEffectiveCmm) {
    // Core omits CMM for legacy identities, which cannot carry multimap content.
    // Normalize a copy so the caller's RPC response remains unchanged.
    revision.identity = { ...revision.identity, contentmultimap: {} };
  }

  const effectiveCmm = revision.identity.contentmultimap;

  if (
    effectiveCmm == null ||
    typeof effectiveCmm !== "object" ||
    (Object.getPrototypeOf(effectiveCmm) !== Object.prototype &&
      Object.getPrototypeOf(effectiveCmm) !== null)
  ) {
    throw new Error("Expected a raw effective identity CMM object.");
  }

  const [currentBlockHash, current] = await Promise.all([
    confirmedBlockHash(rpc, readHeight),
    loadIdentityRevision(capturedSource, expected),
  ]);

  if (
    !sourceUnchanged() ||
    currentBlockHash !== blockHash ||
    current.txid !== revision.txid.toLowerCase() ||
    current.vout !== revision.vout ||
    current.blockheight !== revision.blockheight
  ) {
    throw new Error(
      "Identity state changed while reading effective content; retry the read."
    );
  }

  return { revision, readHeight, blockHash };
}
