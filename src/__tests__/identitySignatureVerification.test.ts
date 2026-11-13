import BN from "bn.js";
import { ECPair, IdentitySignature, networks } from "@bitgo/utxo-lib";
import {
  AuthenticationRequestOrdinalVDXFObject,
  CompactIAddressObject,
  EHashTypes,
  LoginConsentChallenge,
  VerifiableSignatureData,
} from "verus-typescript-primitives";
import VerusIdInterface from "../VerusIdInterface";
import { normalizeAuthorizationKeyID } from "../authorization/authority";
import { TEST_ID, VERUSTEST_I_ADDR } from "./fixtures/verusid";

const HEIGHT = 100;
const CREATED_AT = 1_800_000_000;
const DIGEST = Buffer.alloc(32, 7);
const SIGNATURE_VERSION = 2;
const SIGNATURE_HEADER_BYTES = 7;
const COMPACT_SIGNATURE_BYTES = 65;
const COMPACT_SIZE_PREFIX_BYTES = 1;
const keys = [1, 2].map(seed => ECPair.fromPrivateKeyBuffer(Buffer.alloc(32, seed), networks.verus));

function identity(primaryaddresses = [keys[0].getAddress()], minimumsignatures = 1) {
  return { ...TEST_ID, identity: { ...TEST_ID.identity, primaryaddresses, minimumsignatures } };
}

function signedHash(signingKeys: Array<typeof ECPair>): string {
  const signature = new IdentitySignature(
    networks.verus, SIGNATURE_VERSION, EHashTypes.HASH_SHA256, HEIGHT,
    undefined, VERUSTEST_I_ADDR, TEST_ID.identity.identityaddress
  );
  signingKeys.forEach(key => signature.signHashOffline(DIGEST, key));
  // Supply the existing writer's buffer because its default allocation omits
  // the extra compact-length prefix when more than one signature is present.
  const bytes = Buffer.alloc(SIGNATURE_HEADER_BYTES + signingKeys.length * (COMPACT_SIGNATURE_BYTES + COMPACT_SIZE_PREFIX_BYTES));
  signature.toBuffer(bytes);
  return bytes.toString("base64");
}

describe("shared identity signature verification", () => {
  const client = new VerusIdInterface(VERUSTEST_I_ADDR, "http://unused.invalid");
  const verify = (signature: string, state = identity(), digest = DIGEST) =>
    client.verifyHash(TEST_ID.identity.identityaddress, signature, digest, state, VERUSTEST_I_ADDR);

  test("verifies distinct signers with public-key and key-hash authority representations", async () => {
    const state = identity([keys[0].getPublicKeyBuffer().toString("hex"), keys[1].getAddress()], 2);
    expect(await verify(signedHash(keys), state)).toBe(true);
    expect(await verify(signedHash([keys[0]]), state)).toBe(false);
    expect(await verify(signedHash(keys), state, Buffer.alloc(32, 8))).toBe(false);
  });

  test("does not count repeated signatures or public-key aliases as extra signers", async () => {
    const duplicate = signedHash([keys[0], keys[0]]);
    expect(await verify(duplicate, identity(keys.map(key => key.getAddress()), 2))).toBe(false);
    expect(await verify(duplicate, identity([keys[0].getAddress(), keys[0].getPublicKeyBuffer().toString("hex")], 2))).toBe(false);
  });

  test("counts distinct compressed and uncompressed key IDs in ordinary verification", async () => {
    const uncompressed = ECPair.fromPrivateKeyBuffer(Buffer.alloc(32, 1), networks.verus);
    uncompressed.compressed = false;
    const state = identity([keys[0].getAddress(), uncompressed.getAddress()], 2);

    expect(await verify(signedHash([uncompressed]), identity([uncompressed.getAddress()]))).toBe(true);
    expect(await verify(signedHash([keys[0], uncompressed]), state)).toBe(true);
    expect(await verify(signedHash([keys[0]]), state)).toBe(false);
    expect(await verify(signedHash([uncompressed]), state)).toBe(false);
    expect(await verify(signedHash([keys[0], keys[0]]), state)).toBe(false);
  });

  test("keeps message hashing and name resolution compatible with ordinary signing", async () => {
    const state = identity();
    const message = "shared verifier message";
    const signature = await client.signMessage(TEST_ID.identity.identityaddress, message, keys[0].toWIF(), state, HEIGHT, VERUSTEST_I_ADDR);
    client.interface.getIdentity = jest.fn(async () => ({ result: state, error: null })) as any;

    expect(await client.verifyMessage("test@", signature, message, state, VERUSTEST_I_ADDR)).toBe(true);
    expect(await client.verifyMessage("test@", signature, message + "!", state, VERUSTEST_I_ADDR)).toBe(false);
    expect(await client.getSignatureInfo("test@", signature, VERUSTEST_I_ADDR)).toMatchObject({ height: HEIGHT });
  });

  test("preserves the original unary normalization helper when passed to Array.map", () => {
    const addresses = keys.map(key => key.getAddress());
    expect(addresses.map(normalizeAuthorizationKeyID)).toEqual(addresses.map(address => normalizeAuthorizationKeyID(address)));
  });
});

describe("shared signature creation-time check", () => {
  test("uses the same boundary and invalid-time rejection for legacy and generic requests", async () => {
    const client = new VerusIdInterface(VERUSTEST_I_ADDR, "http://unused.invalid");
    const state = identity();
    const signer = TEST_ID.identity.identityaddress;
    const legacy = await client.createLoginConsentRequest(signer, new LoginConsentChallenge({
      challenge_id: signer, created_at: CREATED_AT,
    }), keys[0].toWIF(), state, HEIGHT, VERUSTEST_I_ADDR);
    const request = await client.createGenericRequest({
      createdAt: new BN(CREATED_AT),
      signature: new VerifiableSignatureData({
        version: VerifiableSignatureData.DEFAULT_VERSION,
        identityID: CompactIAddressObject.fromAddress(signer),
        systemID: CompactIAddressObject.fromAddress(VERUSTEST_I_ADDR),
      }),
      details: [new AuthenticationRequestOrdinalVDXFObject()],
    }, keys[0].toWIF(), state, HEIGHT, VERUSTEST_I_ADDR);

    for (const [blockTime, expected] of [[CREATED_AT + 3600, true], [CREATED_AT + 3601, false], [NaN, false]] as const) {
      expect(await client.verifyLoginConsentRequest(legacy, state, VERUSTEST_I_ADDR, blockTime)).toBe(expected);
      expect(await client.verifyGenericRequest(request, state, VERUSTEST_I_ADDR, blockTime)).toBe(expected);
    }
  });

  test("building an unsigned template does not resolve an unused RPC chain", async () => {
    const rpc = jest.fn(async () => { throw new Error("Unexpected RPC"); });
    const client = new VerusIdInterface("unresolved chain", "http://unused.invalid", undefined, rpc);
    const request = await client.createGenericRequest({ details: [new AuthenticationRequestOrdinalVDXFObject()] });

    expect(request.isSigned()).toBe(false);
    expect(rpc).not.toHaveBeenCalled();
  });
});
