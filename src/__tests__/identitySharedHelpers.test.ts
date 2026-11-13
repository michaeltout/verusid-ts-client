import BN from "bn.js";
import { ECPair, networks } from "@bitgo/utxo-lib";
import {
  DELEGATOR_PROFILE_VDXF_KEY,
  Identity,
  IdentityID,
  assertDelegatorProfileSupportedV1,
} from "verus-typescript-primitives";
import {
  getIdentityPrimaryKeyIDs,
  normalizeIdentityKeyID,
  validateIdentityThreshold,
} from "../identity/identityAuthority";
import {
  IdentityContentSource,
  loadCurrentIdentityContent,
} from "../identity/identityContent";

const key = ECPair.fromPrivateKeyBuffer(Buffer.alloc(32, 1), networks.verus);
const IDENTITY = new IdentityID(Buffer.alloc(20, 2)).toAddress()!;
const SYSTEM = new IdentityID(Buffer.alloc(20, 3)).toAddress()!;

describe("shared identity authority helpers", () => {
  test("normalizes public-key and matching key-hash authorities on the selected network", () => {
    const bitcoinKey = ECPair.fromPrivateKeyBuffer(
      Buffer.alloc(32, 1),
      networks.bitcoin
    );
    const publicKey = key.getPublicKeyBuffer().toString("hex");
    const expected = normalizeIdentityKeyID(key.getAddress());

    expect(normalizeIdentityKeyID(publicKey.toUpperCase())).toBe(expected);
    expect(normalizeIdentityKeyID(key.getPublicKeyBuffer())).toBe(expected);
    const addressNetwork = { pubKeyHash: networks.bitcoin.pubKeyHash };
    expect(
      normalizeIdentityKeyID(key.getPublicKeyBuffer(), addressNetwork)
    ).toBe(expected);
    expect(normalizeIdentityKeyID(publicKey, addressNetwork)).toBe(expected);
    expect(
      normalizeIdentityKeyID(bitcoinKey.getAddress(), addressNetwork)
    ).toBe(expected);
    expect(
      normalizeIdentityKeyID(bitcoinKey.getAddress(), networks.bitcoin)
    ).toBe(expected);
    expect(() => normalizeIdentityKeyID(bitcoinKey.getAddress())).toThrow(
      /key hash/
    );
  });

  test("deduplicates aliases before deciding whether a threshold is attainable", () => {
    const aliases = [
      key.getAddress(),
      key.getPublicKeyBuffer().toString("hex"),
    ];
    expect(getIdentityPrimaryKeyIDs(aliases, 1).size).toBe(1);
    expect(() => getIdentityPrimaryKeyIDs(aliases, 2)).toThrow(/threshold/);
    // RPC authority thresholds remain native integers despite builder BN support.
    expect(() => getIdentityPrimaryKeyIDs(aliases, new BN(1) as any)).toThrow(
      /integer/
    );
    expect(() =>
      getIdentityPrimaryKeyIDs([key.getPublicKeyBuffer()] as any, 1)
    ).toThrow(/primary/);
  });

  test.each([0, 14, Number.NaN, 1.5])(
    "rejects invalid numeric threshold %s",
    (threshold) => {
      expect(() => validateIdentityThreshold(threshold, 25)).toThrow(
        /threshold/
      );
    }
  );

  test("uses identical threshold bounds for JSON authorities and typed builders", () => {
    expect(() => validateIdentityThreshold(13, 25)).not.toThrow();
    expect(() => validateIdentityThreshold(new BN(13), 25)).not.toThrow();
    expect(() => validateIdentityThreshold(new BN(2), 1)).toThrow(/threshold/);
    expect(() => validateIdentityThreshold(new BN(1).shln(128), 25)).toThrow(
      /threshold/
    );
  });
});

function contentFixture() {
  const blockHeight = 100;
  const blockHash = "ab".repeat(32);
  const rawCmm = { [DELEGATOR_PROFILE_VDXF_KEY.vdxfid]: null };
  const identity = {
    identity: {
      version: Identity.VERSION_PBAAS.toNumber(),
      flags: 0,
      identityaddress: IDENTITY,
      primaryaddresses: [key.getAddress()],
      minimumsignatures: 1,
      name: "fixture",
      parent: SYSTEM,
      systemid: SYSTEM,
      contentmultimap: rawCmm,
    },
    status: "active",
    blockheight: 90,
    txid: "cd".repeat(32),
    vout: 1,
    canspendfor: false,
    cansignfor: false,
  };
  const source: IdentityContentSource = {
    systemID: SYSTEM,
    rpc: {
      chain: SYSTEM,
      getInfo: jest.fn(async () => ({
        result: {
          chainid: SYSTEM,
          blocks: blockHeight,
          longestchain: blockHeight,
        },
      })),
      getBlock: jest.fn(async () => ({
        result: { hash: blockHash, height: blockHeight, confirmations: 1 },
      })),
      getIdentityContent: jest.fn(async () => ({
        result: { ...identity, fromheight: 0, toheight: blockHeight },
      })),
      getIdentity: jest.fn(async () => ({ result: identity })),
    } as any,
  };

  return { source, identity, rawCmm, blockHeight, blockHash };
}

test("the shared content loader returns confirmed raw content without applying profile policy", async () => {
  const { source, identity, rawCmm, blockHeight, blockHash } = contentFixture();
  const snapshot = await loadCurrentIdentityContent(
    source,
    { identityID: IDENTITY, systemID: SYSTEM },
    DELEGATOR_PROFILE_VDXF_KEY.vdxfid
  );

  expect(snapshot).toMatchObject({
    readHeight: blockHeight,
    blockHash,
    revision: { systemID: SYSTEM, txid: identity.txid, vout: identity.vout },
  });
  expect(snapshot.revision.identity.contentmultimap).toBe(rawCmm);
  expect(() => assertDelegatorProfileSupportedV1(rawCmm)).toThrow(
    /unsupported/
  );
  expect(source.rpc.getIdentityContent).toHaveBeenCalledWith(
    IDENTITY,
    0,
    blockHeight,
    false,
    0,
    DELEGATOR_PROFILE_VDXF_KEY.vdxfid
  );
});

test.each([
  Identity.VERSION_FIRSTVALID.toNumber(),
  Identity.VERSION_VAULT.toNumber(),
])("normalizes omitted version %i CMM without changing the RPC response", async (version) => {
  const { source, identity } = contentFixture();
  identity.identity.version = version;
  delete (identity.identity as any).contentmultimap;

  const snapshot = await loadCurrentIdentityContent(
    source,
    { identityID: IDENTITY, systemID: SYSTEM },
    DELEGATOR_PROFILE_VDXF_KEY.vdxfid
  );

  expect(snapshot.revision.identity.contentmultimap).toEqual({});
  expect(() =>
    assertDelegatorProfileSupportedV1(
      snapshot.revision.identity.contentmultimap as Record<string, unknown>
    )
  ).not.toThrow();
  expect(identity.identity).not.toHaveProperty("contentmultimap");
  expect(source.rpc.getIdentity).toHaveBeenCalledWith(IDENTITY, undefined);
  expect(source.rpc.getBlock).toHaveBeenCalledTimes(2);
});

test("rejects omitted CMM on a PBaaS identity", async () => {
  const { source, identity } = contentFixture();
  delete (identity.identity as any).contentmultimap;

  await expect(
    loadCurrentIdentityContent(
      source,
      { identityID: IDENTITY, systemID: SYSTEM },
      DELEGATOR_PROFILE_VDXF_KEY.vdxfid
    )
  ).rejects.toThrow(/missing.*effective CMM/);
});

test.each([
  Identity.VERSION_FIRSTVALID.toNumber(),
  Identity.VERSION_VAULT.toNumber(),
  Identity.VERSION_PBAAS.toNumber(),
])("rejects malformed present CMM on version %i identities", async (version) => {
  for (const malformed of [undefined, null, [], "", new Date(0)]) {
    const { source, identity } = contentFixture();
    identity.identity.version = version;
    (identity.identity as any).contentmultimap = malformed;

    await expect(
      loadCurrentIdentityContent(
        source,
        { identityID: IDENTITY, systemID: SYSTEM },
        DELEGATOR_PROFILE_VDXF_KEY.vdxfid
      )
    ).rejects.toThrow(/raw effective identity CMM/);
  }
});
