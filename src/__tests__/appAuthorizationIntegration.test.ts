import BN from "bn.js";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { ECPair, networks } from "@bitgo/utxo-lib";
import {
  AppAuthorizationOutcome,
  AppAuthorizationResponseOrdinalVDXFObject,
  AuthorizationCredential,
  CompactIAddressObject,
  DataDescriptor,
  DataDescriptorKey,
  DataDescriptorOrdinalVDXFObject,
  DELEGATOR_PROFILE_VDXF_KEY,
  GenericRequest,
  GenericResponse,
  I_ADDR_VERSION,
  RecipientConstraint,
  SaplingPaymentAddress,
  UnsupportedDelegatorProfileError,
  VDXFDataDescriptor,
  VerusPayInvoiceDetails,
  VerusPayInvoiceDetailsOrdinalVDXFObject,
  toBase58Check,
} from "verus-typescript-primitives";
import VerusIdInterface, { VerifyDelegatedGenericRequestOptions } from "../VerusIdInterface";
import { createAppAuthorizationRequest, createAppAuthorizationResponse } from "../authorization/handshake";
import { decodeAppAuthorizationRecords } from "../authorization/grants";
import { TEST_SAPLING_ADDR } from "./fixtures/genericenvelope";

const NOW = 1800000000;
const SIGNED_HEIGHT = 100;
const ORIGINAL_HEIGHT = 90;
const READ_HEIGHT = 110;
const READ_BLOCK_HASH = "aa".repeat(32);
const identityAddress = (value: number) => toBase58Check(Buffer.alloc(20, value), I_ADDR_VERSION);
const SYSTEM = identityAddress(1);
const APP = identityAddress(2);
const DELEGATE = identityAddress(3);
const USER = { systemID: identityAddress(4), identityID: identityAddress(5) };
const KEY = ECPair.fromPrivateKeyBuffer(Buffer.alloc(32, 1), networks.verus);
const NEW_KEY = ECPair.fromPrivateKeyBuffer(Buffer.alloc(32, 2), networks.verus);

function identity(id = DELEGATE, height = SIGNED_HEIGHT, keys = [KEY.getAddress()]) {
  return {
    identity: {
      version: 3, flags: 0, identityaddress: id, name: "fixture", parent: SYSTEM,
      systemid: SYSTEM, primaryaddresses: keys, minimumsignatures: 1,
      revocationauthority: id, recoveryauthority: id, contentmap: {}, timelock: 0,
    },
    status: "active", blockheight: height, txid: height.toString(16).padStart(64, "0"),
    vout: 0, cansignfor: false, canspendfor: false,
  };
}

function fixture(system = SYSTEM, signer = DELEGATE) {
  const client = new VerusIdInterface(system, "http://unused.invalid");
  const signed = identity(signer);
  const current = identity(signer);
  const original = identity(signer, ORIGINAL_HEIGHT);
  const app = identity(APP);
  const effectiveCmm: Record<string, unknown> = {};
  client.interface.getIdentity = jest.fn(async (id: string, height?: number) => ({
    result: id === APP ? app : id !== signer ? identity(id) : height === ORIGINAL_HEIGHT ? original : height == null ? current : signed,
    error: null,
  })) as any;
  client.interface.getInfo = jest.fn(async () => ({
    result: { blocks: READ_HEIGHT, longestchain: READ_HEIGHT, chainid: system }, error: null,
  })) as any;
  client.interface.getBlock = jest.fn(async (height: string) => ({
    result: { time: NOW, height: Number(height), hash: READ_BLOCK_HASH, confirmations: 1 }, error: null,
  })) as any;
  client.interface.getIdentityContent = jest.fn(async () => ({
    result: {
      ...app, fromheight: 0, toheight: READ_HEIGHT,
      identity: { ...app.identity, contentmultimap: { ...effectiveCmm } },
    },
    error: null,
  })) as any;

  return { client, signed, current, original, app, effectiveCmm };
}

async function request(
  client: VerusIdInterface,
  signed: ReturnType<typeof identity>,
  bootstrap = true,
  recipientConstraints?: RecipientConstraint[]
) {
  const envelope = createAppAuthorizationRequest({
    appID: APP,
    delegate: { systemID: SYSTEM, identityID: DELEGATE },
    requestID: identityAddress(6),
    createdAt: new BN(NOW),
    expiryTime: new BN(NOW + 3600),
    recipientConstraints,
  });

  if (!bootstrap) {
    // An ordinary later authentication request uses the same delegated scope.
    envelope.details.pop();
    envelope.flags = envelope.flags.xor(GenericRequest.FLAG_MULTI_DETAILS);
  }

  return client.signGenericRequest(envelope, KEY.toWIF(), signed, SIGNED_HEIGHT);
}

function approval(original: ReturnType<typeof identity>): VerifyDelegatedGenericRequestOptions {
  const grant = new AuthorizationCredential({
    version: AuthorizationCredential.VERSION_CURRENT,
    flags: AuthorizationCredential.FLAGS_NONE,
    grantID: "ab".repeat(32),
    signingSystemID: SYSTEM, appID: APP, delegateID: DELEGATE,
    originalRevision: { lookupHeight: ORIGINAL_HEIGHT, txid: original.txid, vout: original.vout },
  });

  return {
    records: decodeAppAuthorizationRecords([{
      credential: grant.toCredential(),
      source: { ...USER, outerKey: identityAddress(7), storedValue: Buffer.from("encrypted stored value") },
    }]),
    user: USER,
    verifyUserControl: jest.fn(async () => true),
    verifyStorageControl: jest.fn(async () => true),
  };
}

beforeEach(() => jest.spyOn(Date, "now").mockReturnValue(NOW * 1000));
afterEach(() => jest.restoreAllMocks());

describe("authorization admission through VerusIdInterface", () => {
  test("requires the current delegate authority and resolves A on the request system", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed);
    expect(await f.client.verifyGenericRequest(envelope)).toBe(true);
    expect(f.client.interface.getIdentity).toHaveBeenCalledWith(APP, undefined);

    f.current.identity.primaryaddresses = [NEW_KEY.getAddress()];
    expect(await f.client.verifyGenericRequest(envelope, f.signed, SYSTEM, NOW, true)).toBe(false);
  });

  test("cannot use acceptUnsigned for bootstrap, while preserving other unsigned requests", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed);
    envelope.signature!.signatureAsVch = Buffer.alloc(0);
    expect(await f.client.verifyGenericRequest(envelope, undefined, SYSTEM, NOW, true)).toBe(false);
    expect(await f.client.verifyGenericRequest(new GenericRequest({ details: [] }), undefined, SYSTEM, NOW, true)).toBe(true);
  });

  test("rejects a mismatched RPC system and envelope mutations during admission", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed);
    f.client.interface.chain = USER.systemID;
    expect(await f.client.verifyGenericRequest(envelope)).toBe(false);
    f.client.interface.chain = SYSTEM;
    (f.client.interface.getBlock as jest.Mock).mockImplementation(async (height: string) => {
      if (height === SIGNED_HEIGHT.toString()) envelope.salt![0] ^= 1;
      return {
        result: { time: NOW, height: Number(height), hash: READ_BLOCK_HASH, confirmations: 1 }, error: null,
      };
    });
    expect(await f.client.verifyGenericRequest(envelope)).toBe(false);
  });
});

describe("delegated handler admission", () => {
  test("combines real signed-height signatures, the saved baseline, and current wallet control", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed, false);
    const options = approval(f.original);
    expect(await f.client.verifyDelegatedGenericRequest(envelope, options)).toBe(true);
    expect(f.client.interface.getIdentity).toHaveBeenCalledWith(DELEGATE, ORIGINAL_HEIGHT);
    expect(options.verifyUserControl).toHaveBeenCalledWith(USER);

    f.original.identity.primaryaddresses = [NEW_KEY.getAddress()];
    expect(await f.client.verifyDelegatedGenericRequest(envelope, options)).toBe(false);
  });

  test("deleted or mismatched grants do not fall back to ordinary signature validity", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed, false);
    expect(await f.client.verifyGenericRequest(envelope)).toBe(true);
    expect(await f.client.verifyDelegatedGenericRequest(envelope, { ...approval(f.original), records: [] })).toBe(false);
    const options = approval(f.original);
    options.user = { ...USER, identityID: APP };
    expect(await f.client.verifyDelegatedGenericRequest(envelope, options)).toBe(false);
  });

  test("checks current expiry and cannot override an expired authentication contract", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed, false);
    const options = { ...approval(f.original), verifyFreshness: jest.fn(async () => true) };
    (Date.now as jest.Mock).mockReturnValue((NOW + 3600) * 1000);
    expect(await f.client.verifyDelegatedGenericRequest(envelope, options)).toBe(false);
    expect(options.verifyFreshness).not.toHaveBeenCalled();
  });

  test("rejects request changes made while awaiting private wallet checks", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed, false);
    const options = approval(f.original);
    options.verifyUserControl = async () => {
      envelope.appOrDelegatorID = CompactIAddressObject.fromAddress(USER.identityID);
      return true;
    };
    expect(await f.client.verifyDelegatedGenericRequest(envelope, options)).toBe(false);
  });

  test("rechecks a handler freshness contract after asynchronous authorization", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed, false);
    const invoice = new VerusPayInvoiceDetails({ requestedcurrencyid: SYSTEM });
    invoice.setFlags({ acceptsAnyAmount: true, acceptsAnyDestination: true });
    envelope.details = [new VerusPayInvoiceDetailsOrdinalVDXFObject({ data: invoice })];
    await f.client.signGenericRequest(envelope, KEY.toWIF(), f.signed, SIGNED_HEIGHT);
    const verifyFreshness = jest.fn().mockResolvedValueOnce(true).mockResolvedValueOnce(false);
    expect(await f.client.verifyDelegatedGenericRequest(envelope, {
      ...approval(f.original), verifyFreshness,
    })).toBe(false);
    expect(verifyFreshness).toHaveBeenCalledTimes(2);
  });

  test("rejects a changed selected user even when the earlier user passed control checks", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed, false);
    const options = approval(f.original);
    options.user = { ...USER };
    options.verifyUserControl = async () => {
      options.user.identityID = APP;
      return true;
    };
    expect(await f.client.verifyDelegatedGenericRequest(envelope, options)).toBe(false);
  });
});

describe("future delegator profile compatibility", () => {
  test.each([
    { description: "empty", value: [] },
    { description: "null", value: null },
    { description: "encrypted", value: ["ciphertext"] },
    { description: "malformed", value: { unknownVersion: true } },
  ])("rejects an initial authorization with a $description profile value", async ({ value }) => {
    const f = fixture();
    const envelope = await request(f.client, f.signed);
    f.effectiveCmm[DELEGATOR_PROFILE_VDXF_KEY.vdxfid] = value;

    await expect(f.client.verifyGenericRequest(envelope)).rejects.toMatchObject({
      name: "UnsupportedDelegatorProfileError", code: "UNSUPPORTED_DELEGATOR_PROFILE",
    });
    expect(f.client.interface.getIdentityContent).toHaveBeenCalledWith(
      APP, 0, READ_HEIGHT, false, 0, DELEGATOR_PROFILE_VDXF_KEY.vdxfid
    );
  });

  test("recognizes the qualified outer key without interpreting its contents", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed);
    f.effectiveCmm[DELEGATOR_PROFILE_VDXF_KEY.qualifiedname.name] = undefined;

    await expect(f.client.verifyGenericRequest(envelope)).rejects.toBeInstanceOf(UnsupportedDelegatorProfileError);
  });

  test("checks existing grants before wallet control callbacks and permits effective removal", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed, false);
    const options = approval(f.original);
    f.effectiveCmm[DELEGATOR_PROFILE_VDXF_KEY.vdxfid] = [];

    await expect(f.client.verifyDelegatedGenericRequest(envelope, options)).rejects.toMatchObject({
      code: "UNSUPPORTED_DELEGATOR_PROFILE",
    });
    expect(options.verifyUserControl).not.toHaveBeenCalled();
    expect(options.verifyStorageControl).not.toHaveBeenCalled();

    delete f.effectiveCmm[DELEGATOR_PROFILE_VDXF_KEY.vdxfid];
    expect(await f.client.verifyDelegatedGenericRequest(envelope, options)).toBe(true);
  });

  test("rechecks current profile presence after asynchronous grant verification", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed, false);
    const options = approval(f.original);
    options.verifyUserControl = async () => {
      f.effectiveCmm[DELEGATOR_PROFILE_VDXF_KEY.vdxfid] = ["new profile"];
      return true;
    };

    await expect(f.client.verifyDelegatedGenericRequest(envelope, options)).rejects.toMatchObject({
      code: "UNSUPPORTED_DELEGATOR_PROFILE",
    });
  });

  test("does not release a delegated approval after a final freshness callback sees a new profile", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed, false);
    const options = approval(f.original);
    let freshnessChecks = 0;
    options.verifyFreshness = async () => {
      if (++freshnessChecks === 2) f.effectiveCmm[DELEGATOR_PROFILE_VDXF_KEY.vdxfid] = [];
      return true;
    };

    await expect(f.client.verifyDelegatedGenericRequest(envelope, options)).rejects.toMatchObject({
      code: "UNSUPPORTED_DELEGATOR_PROFILE",
    });
  });

  test("ignores unrelated outer keys and nested profile-shaped content", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed);
    f.effectiveCmm[identityAddress(8)] = [{ [DELEGATOR_PROFILE_VDXF_KEY.vdxfid]: null }];

    expect(await f.client.verifyGenericRequest(envelope)).toBe(true);
  });

  test.each(["rpcError", "missingMap", "malformedMap", "wrongIdentity", "unconfirmedRevision", "partialRange"])(
    "does not treat %s content as profile absence",
    async failure => {
      const f = fixture();
      const envelope = await request(f.client, f.signed);
      const result: any = {
        ...f.app, fromheight: 0, toheight: READ_HEIGHT,
        identity: { ...f.app.identity, contentmultimap: {} },
      };

      if (failure === "missingMap") delete result.identity.contentmultimap;
      if (failure === "malformedMap") result.identity.contentmultimap = null;
      if (failure === "wrongIdentity") result.identity.identityaddress = DELEGATE;
      if (failure === "unconfirmedRevision") result.blockheight = READ_HEIGHT + 1;
      if (failure === "partialRange") result.fromheight = SIGNED_HEIGHT;
      (f.client.interface.getIdentityContent as jest.Mock).mockResolvedValue({
        result,
        error: failure === "rpcError" ? { code: -1, message: "content unavailable" } : null,
      });

      expect(await f.client.verifyGenericRequest(envelope)).toBe(false);
    }
  );

  test.each(["wrongSystem", "unsynchronized", "unconfirmedBlock", "cancelledRead"])(
    "rejects %s chain context before accepting profile absence",
    async failure => {
      const f = fixture();
      const envelope = await request(f.client, f.signed);

      if (failure === "wrongSystem" || failure === "unsynchronized") {
        (f.client.interface.getInfo as jest.Mock).mockResolvedValue({
          result: {
            blocks: READ_HEIGHT,
            longestchain: failure === "unsynchronized" ? READ_HEIGHT + 1 : READ_HEIGHT,
            chainid: failure === "wrongSystem" ? USER.systemID : SYSTEM,
          },
          error: null,
        });
      }
      if (failure === "unconfirmedBlock") {
        (f.client.interface.getBlock as jest.Mock).mockResolvedValue({
          result: { time: NOW, height: READ_HEIGHT, hash: READ_BLOCK_HASH, confirmations: 0 }, error: null,
        });
      }
      if (failure === "cancelledRead") {
        (f.client.interface.getIdentityContent as jest.Mock).mockRejectedValue(new Error("Cancelled"));
      }

      expect(await f.client.verifyGenericRequest(envelope)).toBe(false);
    }
  );

  test("rejects content tied to an older app outpoint", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed);
    (f.client.interface.getIdentityContent as jest.Mock).mockResolvedValue({
      result: {
        ...f.app, fromheight: 0, toheight: READ_HEIGHT, txid: "bb".repeat(32),
        identity: { ...f.app.identity, contentmultimap: {} },
      },
      error: null,
    });

    expect(await f.client.verifyGenericRequest(envelope)).toBe(false);
  });

  test("rejects a reorganized content read instead of trusting its stale absence", async () => {
    const f = fixture();
    const envelope = await request(f.client, f.signed);
    let tipReads = 0;
    (f.client.interface.getBlock as jest.Mock).mockImplementation(async (height: string) => {
      if (height === READ_HEIGHT.toString()) tipReads += 1;

      return {
        result: {
          time: NOW, height: Number(height), confirmations: 1,
          hash: tipReads > 1 ? "cc".repeat(32) : READ_BLOCK_HASH,
        },
        error: null,
      };
    });

    expect(await f.client.verifyGenericRequest(envelope)).toBe(false);
  });
});

describe("signed completion correlation", () => {
  async function encryptedCompletion(
    detailsBytes = (response: GenericResponse) => response.getDetailsBuffer(),
    encodePlaintext = (wrapper: VDXFDataDescriptor) => wrapper.toBuffer()
  ) {
    const delegate = fixture();
    const envelope = await request(delegate.client, delegate.signed, true, [
      new RecipientConstraint({
        type: RecipientConstraint.REQUIRED_PARENT,
        identity: CompactIAddressObject.fromAddress(SYSTEM),
      }),
    ]);
    envelope.encryptResponseToAddress = SaplingPaymentAddress.fromAddressString(TEST_SAPLING_ADDR);
    envelope.setHasEncryptResponseToAddress();
    await delegate.client.signGenericRequest(envelope, KEY.toWIF(), delegate.signed, SIGNED_HEIGHT);
    const user = fixture(USER.systemID, USER.identityID);
    const response = createAppAuthorizationResponse(envelope, {
      user: { ...USER, parentID: SYSTEM },
      outcome: AppAuthorizationOutcome.SUCCESS,
      createdAt: new BN(NOW),
    });

    // Match Mobile's tagged plaintext wrapper. AES-GCM exercises authenticated
    // callback decryption here; this fixture does not assert Sapling interoperability.
    const plaintext = encodePlaintext(new VDXFDataDescriptor(
      new DataDescriptor({ objectdata: detailsBytes(response) }),
      DataDescriptorKey.vdxfid
    ));
    const keyBytes = 32;
    const nonceBytes = 12;
    const tagBytes = 16;
    const encryptionKey = randomBytes(keyBytes);
    const nonce = randomBytes(nonceBytes);
    const cipher = createCipheriv("aes-256-gcm", encryptionKey, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const descriptor = new DataDescriptor({
      flags: DataDescriptor.FLAG_ENCRYPTED_DATA,
      objectdata: Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]),
    });
    response.details = [new DataDescriptorOrdinalVDXFObject({ data: descriptor })];
    response.setDetailsAreEncrypted();
    await user.client.signGenericResponse(response, KEY.toWIF(), user.signed, SIGNED_HEIGHT);

    const received = new GenericResponse();
    const wire = response.toBuffer();
    expect(received.fromBuffer(wire)).toBe(wire.length);

    const decrypt = jest.fn((encrypted: DataDescriptor) => {
      const bytes = encrypted.objectdata;
      const decipher = createDecipheriv(
        "aes-256-gcm", encryptionKey, bytes.subarray(0, nonceBytes)
      );
      decipher.setAuthTag(bytes.subarray(nonceBytes, nonceBytes + tagBytes));
      return Buffer.concat([
        decipher.update(bytes.subarray(nonceBytes + tagBytes)),
        decipher.final(),
      ]);
    });

    return {
      ...user, request: envelope, response: received, selectedUser: { ...USER }, decrypt,
    };
  }

  test("permits a selected user on another system and completion after timely submission", async () => {
    const delegate = fixture();
    const envelope = await request(delegate.client, delegate.signed);
    const user = fixture(USER.systemID, USER.identityID);
    (Date.now as jest.Mock).mockReturnValue((NOW + 7200) * 1000);
    const response = createAppAuthorizationResponse(envelope, {
      user: USER, outcome: AppAuthorizationOutcome.SUCCESS, createdAt: new BN(NOW + 7200),
    });
    await user.client.signGenericResponse(response, KEY.toWIF(), user.signed, SIGNED_HEIGHT);
    const unusedDecrypt = jest.fn(() => { throw new Error("Plaintext needs no decryption"); });
    expect(await user.client.verifyAppAuthorizationResponse(response, envelope, USER, NOW + 7200, unusedDecrypt)).toBe(true);
    expect(unusedDecrypt).not.toHaveBeenCalled();
    expect(user.client.interface.getIdentityContent).not.toHaveBeenCalled();
    expect(await user.client.verifyAppAuthorizationResponse(response, envelope, { ...USER, identityID: APP }, NOW + 7200)).toBe(false);

    response.signature!.signatureAsVch[10] ^= 1;
    expect(await user.client.verifyAppAuthorizationResponse(response, envelope, USER, NOW + 7200)).toBe(false);
  });

  test("resolves response parent constraints from RPC instead of requiring a caller hint", async () => {
    const delegate = fixture();
    const envelope = createAppAuthorizationRequest({
      appID: APP, delegate: { systemID: SYSTEM, identityID: DELEGATE },
      requestID: identityAddress(6), createdAt: new BN(NOW), expiryTime: new BN(NOW + 3600),
      recipientConstraints: [{ type: RecipientConstraint.REQUIRED_PARENT, identity: CompactIAddressObject.fromAddress(SYSTEM) }],
    });
    await delegate.client.signGenericRequest(envelope, KEY.toWIF(), delegate.signed, SIGNED_HEIGHT);
    const user = fixture(USER.systemID, USER.identityID);
    const response = createAppAuthorizationResponse(envelope, {
      user: { ...USER, parentID: SYSTEM }, outcome: AppAuthorizationOutcome.SUCCESS,
    });
    await user.client.signGenericResponse(response, KEY.toWIF(), user.signed, SIGNED_HEIGHT);
    expect(await user.client.verifyAppAuthorizationResponse(response, envelope, USER)).toBe(true);
    user.current.identity.parent = APP;
    expect(await user.client.verifyAppAuthorizationResponse(response, envelope, USER)).toBe(false);
  });

  test("verifies signed encrypted completion after a wire roundtrip without changing retained bytes", async () => {
    const f = await encryptedCompletion();
    const responseBytes = f.response.toBuffer();
    const requestBytes = f.request.toBuffer();

    expect(await f.client.verifyAppAuthorizationResponse(
      f.response, f.request, f.selectedUser, NOW, f.decrypt
    )).toBe(true);
    expect(f.decrypt).toHaveBeenCalledTimes(1);
    expect(f.response.detailsAreEncrypted()).toBe(true);
    expect(f.response.toBuffer()).toEqual(responseBytes);
    expect(f.request.toBuffer()).toEqual(requestBytes);
  });

  test.each(["ciphertext", "signature", "currentUser"])(
    "rejects changed %s before decrypting a completion",
    async change => {
      const f = await encryptedCompletion();
      if (change === "ciphertext") {
        const ciphertext = (f.response.details[0] as DataDescriptorOrdinalVDXFObject).data.objectdata;
        ciphertext[ciphertext.length - 1] ^= 1;
      }
      if (change === "signature") f.response.signature!.signatureAsVch[10] ^= 1;
      if (change === "currentUser") f.current.identity.primaryaddresses = [NEW_KEY.getAddress()];

      expect(await f.client.verifyAppAuthorizationResponse(
        f.response, f.request, f.selectedUser, NOW, f.decrypt
      )).toBe(false);
      expect(f.decrypt).not.toHaveBeenCalled();
    }
  );

  test("rejects a signed ciphertext whose authentication fails", async () => {
    const f = await encryptedCompletion();
    const ciphertext = (f.response.details[0] as DataDescriptorOrdinalVDXFObject).data.objectdata;
    ciphertext[ciphertext.length - 1] ^= 1;
    await f.client.signGenericResponse(f.response, KEY.toWIF(), f.signed, SIGNED_HEIGHT);

    expect(await f.client.verifyAppAuthorizationResponse(
      f.response, f.request, f.selectedUser, NOW, f.decrypt
    )).toBe(false);
    expect(f.decrypt).toHaveBeenCalledTimes(1);
  });

  test.each(["missing", "throws", "nonBuffer"])(
    "rejects a %s completion decryptor",
    async failure => {
      const f = await encryptedCompletion();
      const decrypt = failure === "missing" ? undefined : jest.fn(() => {
        if (failure === "throws") throw new Error("Decryption unavailable");
        return "not bytes" as unknown as Buffer;
      });

      expect(await f.client.verifyAppAuthorizationResponse(
        f.response, f.request, f.selectedUser, NOW, decrypt
      )).toBe(false);
    }
  );

  test.each(["wrongGrant", "wrongType", "trailingBytes"])(
    "rejects authenticated completion details with %s",
    async failure => {
      const f = await encryptedCompletion(response => {
        if (failure === "wrongGrant") {
          (response.details[0] as AppAuthorizationResponseOrdinalVDXFObject).data.grantID = "ef".repeat(32);
        }
        if (failure === "wrongType") {
          return new DataDescriptorOrdinalVDXFObject({ data: new DataDescriptor() }).toBuffer();
        }
        const bytes = response.getDetailsBuffer();
        return failure === "trailingBytes" ? Buffer.concat([bytes, Buffer.from([0])]) : bytes;
      });

      expect(await f.client.verifyAppAuthorizationResponse(
        f.response, f.request, f.selectedUser, NOW, f.decrypt
      )).toBe(false);
      expect(f.decrypt).toHaveBeenCalledTimes(1);
    }
  );

  test.each(["request", "response", "user"])(
    "rejects caller %s mutation while decrypting a completion",
    async changed => {
      const f = await encryptedCompletion();
      const decrypt = async (descriptor: DataDescriptor) => {
        const plaintext = f.decrypt(descriptor);
        if (changed === "request") f.request.salt![0] ^= 1;
        if (changed === "response") f.response.requestHash![0] ^= 1;
        if (changed === "user") f.selectedUser.identityID = APP;
        return plaintext;
      };

      expect(await f.client.verifyAppAuthorizationResponse(
        f.response, f.request, f.selectedUser, NOW, decrypt
      )).toBe(false);
    }
  );

  test.each(["bareDetails", "trailingWrapperBytes", "unsupportedVersion", "nestedEncryption"])(
    "rejects authenticated plaintext with %s framing",
    async failure => {
      const f = await encryptedCompletion(undefined, wrapper => {
        if (failure === "bareDetails") return wrapper.dataDescriptor.objectdata;
        if (failure === "unsupportedVersion") wrapper.version = wrapper.version.addn(1);
        if (failure === "nestedEncryption") wrapper.dataDescriptor.flags = DataDescriptor.FLAG_ENCRYPTED_DATA;

        const bytes = wrapper.toBuffer();
        return failure === "trailingWrapperBytes" ? Buffer.concat([bytes, Buffer.from([0])]) : bytes;
      });

      expect(await f.client.verifyAppAuthorizationResponse(
        f.response, f.request, f.selectedUser, NOW, f.decrypt
      )).toBe(false);
      expect(f.decrypt).toHaveBeenCalledTimes(1);
    }
  );

  test("isolates the decryptor's descriptor from the signed response", async () => {
    const f = await encryptedCompletion();
    const originalBytes = f.response.toBuffer();
    const decrypt = async (descriptor: DataDescriptor) => {
      const plaintext = f.decrypt(descriptor);
      descriptor.objectdata.fill(0);
      descriptor.flags = new BN(0);
      return plaintext;
    };

    expect(await f.client.verifyAppAuthorizationResponse(
      f.response, f.request, f.selectedUser, NOW, decrypt
    )).toBe(true);
    expect(f.response.toBuffer()).toEqual(originalBytes);
  });

  test.each(["authority", "parent"])(
    "rechecks current user %s after asynchronous decryption",
    async changed => {
      const f = await encryptedCompletion();
      const updated = identity(USER.identityID, READ_HEIGHT);
      if (changed === "authority") updated.identity.primaryaddresses = [NEW_KEY.getAddress()];
      if (changed === "parent") updated.identity.parent = APP;
      const getIdentity = f.client.interface.getIdentity as jest.Mock;
      const originalLookup = getIdentity.getMockImplementation()!;
      let decrypted = false;

      // Return a new RPC object so an old retained revision cannot observe the
      // update accidentally through a shared fixture reference.
      getIdentity.mockImplementation(async (id: string, height?: number) => {
        if (decrypted && id === USER.identityID && height == null) {
          return { result: updated, error: null };
        }
        return originalLookup(id, height);
      });
      const decrypt = async (descriptor: DataDescriptor) => {
        const plaintext = f.decrypt(descriptor);
        decrypted = true;
        return plaintext;
      };

      expect(await f.client.verifyAppAuthorizationResponse(
        f.response, f.request, f.selectedUser, NOW, decrypt
      )).toBe(false);
      expect(f.decrypt).toHaveBeenCalledTimes(1);
    }
  );

  test("detaches callback plaintext before refreshing the current user", async () => {
    const f = await encryptedCompletion();
    const getIdentity = f.client.interface.getIdentity as jest.Mock;
    const originalLookup = getIdentity.getMockImplementation()!;
    let returnedPlaintext: Buffer | undefined;
    let currentReads = 0;

    getIdentity.mockImplementation(async (id: string, height?: number) => {
      if (id === USER.identityID && height == null && ++currentReads === 2) {
        returnedPlaintext!.fill(0);
      }
      return originalLookup(id, height);
    });
    const decrypt = (descriptor: DataDescriptor) => {
      returnedPlaintext = f.decrypt(descriptor);
      return returnedPlaintext;
    };

    expect(await f.client.verifyAppAuthorizationResponse(
      f.response, f.request, f.selectedUser, NOW, decrypt
    )).toBe(true);
    expect(currentReads).toBe(2);
    expect(returnedPlaintext!.equals(Buffer.alloc(returnedPlaintext!.length))).toBe(true);
  });
});
