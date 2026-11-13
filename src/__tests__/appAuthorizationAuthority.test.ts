import BN from "bn.js";
import { ECPair, IdentitySignature, networks } from "@bitgo/utxo-lib";
import {
  AuthenticationRequestOrdinalVDXFObject,
  CompactIAddressObject,
  GenericRequest,
  IdentityID,
  VerifiableSignatureData,
} from "verus-typescript-primitives";
import {
  AuthorizationIdentityRevision,
  AuthorizationIdentitySource,
  inspectAuthorizationSigners,
  loadAuthorizationIdentity,
  loadOriginalAuthorizationIdentity,
  normalizeAuthorizationKeyID,
} from "../authorization/authority";

const SYSTEM = new IdentityID(Buffer.alloc(20, 1)).toAddress()!;
const DELEGATE = new IdentityID(Buffer.alloc(20, 2)).toAddress()!;
const OTHER_SYSTEM = new IdentityID(Buffer.alloc(20, 3)).toAddress()!;
const SIGNED_HEIGHT = 100;
const ORIGINAL_HEIGHT = 50;
const ORIGINAL_TXID = "ab".repeat(32);
const CURRENT_TXID = "cd".repeat(32);
const binding = { systemID: SYSTEM, identityID: DELEGATE };
const keys = [1, 2, 3, 4, 5, 6].map((seed) =>
  ECPair.fromPrivateKeyBuffer(Buffer.alloc(32, seed), networks.verus)
);

function revision(
  indices = [0, 1, 2, 3, 4],
  threshold = 1
): AuthorizationIdentityRevision {
  return {
    systemID: SYSTEM,
    identity: {
      version: 3,
      flags: 0,
      identityaddress: DELEGATE,
      name: "delegate",
      parent: SYSTEM,
      systemid: SYSTEM,
      primaryaddresses: indices.map((index) => keys[index].getAddress()),
      minimumsignatures: threshold,
    },
    status: "active",
    blockheight: ORIGINAL_HEIGHT,
    txid: ORIGINAL_TXID,
    vout: 1,
    cansignfor: false,
    canspendfor: false,
  };
}

function signedRequest(signers: number[], signingKeys = keys): GenericRequest {
  const request = new GenericRequest({
    createdAt: new BN(1700000000),
    salt: Buffer.alloc(32, 9),
    details: [new AuthenticationRequestOrdinalVDXFObject()],
    signature: new VerifiableSignatureData({
      version: VerifiableSignatureData.DEFAULT_VERSION,
      systemID: CompactIAddressObject.fromAddress(SYSTEM),
      identityID: CompactIAddressObject.fromAddress(DELEGATE),
    }),
  });
  const signature = new IdentitySignature(
    networks.verus,
    2,
    5,
    SIGNED_HEIGHT,
    undefined,
    SYSTEM,
    DELEGATE
  );
  const digest = request.getDetailsIdentitySignatureHash(SIGNED_HEIGHT);

  signers.forEach((index) =>
    signature.signHashOffline(digest, signingKeys[index])
  );
  // The upstream allocator omits extra signature-length prefixes. Exercise the
  // same writer with caller-owned storage to produce real multisignature bytes.
  const SIGNATURE_HEADER_BYTES = 7;
  const COMPACT_SIGNATURE_BYTES = 65;
  const COMPACT_SIZE_PREFIX_BYTES = 1;
  const bytes = Buffer.alloc(
    SIGNATURE_HEADER_BYTES +
      signers.length * (COMPACT_SIGNATURE_BYTES + COMPACT_SIZE_PREFIX_BYTES)
  );
  signature.toBuffer(bytes);
  request.signature!.signatureAsVch = bytes;
  return request;
}

function source(identity = revision(), history: any[] = []) {
  const rpc = {
    chain: SYSTEM,
    getIdentity: jest.fn().mockResolvedValue({ result: identity, error: null }),
    request: jest.fn().mockResolvedValue({ result: { history }, error: null }),
  };

  return { rpc, systemID: SYSTEM } as unknown as AuthorizationIdentitySource & {
    rpc: typeof rpc;
  };
}

describe("authorization signer policy", () => {
  test.each([0, 1, 2, 3, 4])(
    "every originally approved 1-of-5 key may sign (%i)",
    (signer) => {
      const original = revision();
      const current = { ...revision(), blockheight: 150, txid: CURRENT_TXID };
      const evidence = inspectAuthorizationSigners(
        signedRequest([signer]),
        original,
        current,
        original
      );

      expect(evidence.valid).toBe(true);
      expect(evidence.signedHeight).toBe(SIGNED_HEIGHT);
      expect(evidence.signedKeyIDs).toEqual([
        normalizeAuthorizationKeyID(keys[signer].getAddress()),
      ]);
    }
  );

  test("does not combine disjoint original and current signer subsets", () => {
    const original = revision([0, 1, 2, 3, 4]);
    const current = revision([1, 2, 3, 4, 5]);
    const signed = revision([0, 5]);
    const evidence = inspectAuthorizationSigners(
      signedRequest([0, 5]),
      signed,
      current,
      original
    );

    expect(evidence.signedKeyIDs).toHaveLength(2);
    expect(evidence.eligibleKeyIDs).toHaveLength(4);
    expect(evidence.valid).toBe(false);
  });

  test.each([
    { signer: 0, valid: false },
    { signer: 1, valid: true },
    { signer: 5, valid: false },
  ])(
    "removed/new keys fail and retained keys pass: $signer",
    ({ signer, valid }) => {
      const original = revision([0, 1, 2, 3, 4]);
      const current = revision([1, 2, 3, 4, 5]);

      expect(
        inspectAuthorizationSigners(
          signedRequest([signer]),
          revision([0, 1, 2, 3, 4, 5]),
          current,
          original
        ).valid
      ).toBe(valid);
    }
  );

  test("a reinstated original key is eligible without a historical latch", () => {
    expect(
      inspectAuthorizationSigners(
        signedRequest([0]),
        revision(),
        revision(),
        revision()
      ).valid
    ).toBe(true);
  });

  test.each([
    { oldThreshold: 1, newThreshold: 2 },
    { oldThreshold: 2, newThreshold: 1 },
  ])(
    "preserves max($oldThreshold, $newThreshold)",
    ({ oldThreshold, newThreshold }) => {
      const original = revision([0, 1], oldThreshold);
      const current = revision([0, 1], newThreshold);
      const signed = revision([0, 1]);

      expect(
        inspectAuthorizationSigners(
          signedRequest([0]),
          signed,
          current,
          original
        ).valid
      ).toBe(false);
      const evidence = inspectAuthorizationSigners(
        signedRequest([0, 1]),
        signed,
        current,
        original
      );
      expect(evidence.requiredSignatures).toBe(2);
      expect(evidence.valid).toBe(true);
    }
  );

  test("also preserves ordinary authority at the actual signed height", () => {
    expect(
      inspectAuthorizationSigners(
        signedRequest([0]),
        revision([1]),
        revision([0]),
        revision([0])
      ).valid
    ).toBe(false);
  });

  test("bootstrap admission rejects a former controller even with a valid historical signature", () => {
    expect(
      inspectAuthorizationSigners(
        signedRequest([0]),
        revision([0]),
        revision([1])
      ).valid
    ).toBe(false);
    expect(
      inspectAuthorizationSigners(
        signedRequest([1]),
        revision([1]),
        revision([1])
      ).valid
    ).toBe(true);
  });

  test("duplicate signatures cannot satisfy a two-key threshold", () => {
    const evidence = inspectAuthorizationSigners(
      signedRequest([0, 0]),
      revision([0, 1]),
      revision([0, 1], 2),
      revision([0, 1], 2)
    );
    expect(evidence.signedKeyIDs).toHaveLength(1);
    expect(evidence.valid).toBe(false);
  });

  test("public key and key hash are one authority", () => {
    const original = revision([0]);
    original.identity.primaryaddresses.push(
      keys[0].getPublicKeyBuffer().toString("hex")
    );
    const evidence = inspectAuthorizationSigners(
      signedRequest([0]),
      original,
      original,
      original
    );

    expect(evidence.eligibleKeyIDs).toHaveLength(1);
    expect(evidence.signedKeyIDs).toHaveLength(1);
    expect(evidence.valid).toBe(true);

    original.identity.minimumsignatures = 2;
    expect(() =>
      inspectAuthorizationSigners(
        signedRequest([0]),
        original,
        original,
        original
      )
    ).toThrow(/threshold/);
  });

  test("uncompressed public keys and their matching key hashes remain eligible", () => {
    const uncompressed = ECPair.fromPrivateKeyBuffer(
      Buffer.alloc(32, 1),
      networks.verus
    );
    uncompressed.compressed = false;
    const original = revision([0]);
    original.identity.primaryaddresses = [
      uncompressed.getPublicKeyBuffer().toString("hex"),
    ];
    const current = revision([0]);
    current.identity.primaryaddresses = [uncompressed.getAddress()];
    const evidence = inspectAuthorizationSigners(
      signedRequest([0], [uncompressed]),
      current,
      current,
      original
    );

    expect(evidence.valid).toBe(true);
    expect(evidence.signedKeyIDs).toEqual([
      normalizeAuthorizationKeyID(uncompressed.getAddress()),
    ]);
    expect(evidence.eligibleKeyIDs).toEqual(evidence.signedKeyIDs);

    // Re-encoding the same public point must not grant membership in another
    // key ID that was absent from the original approval.
    expect(
      inspectAuthorizationSigners(
        signedRequest([0]),
        revision([0]),
        current,
        original
      ).valid
    ).toBe(false);
  });

  test("compressed and uncompressed encodings of one signer cannot satisfy two signatures", () => {
    const uncompressed = ECPair.fromPrivateKeyBuffer(
      Buffer.alloc(32, 1),
      networks.verus
    );
    uncompressed.compressed = false;
    const oneSignature = revision([0]);
    oneSignature.identity.primaryaddresses = [
      keys[0].getAddress(),
      uncompressed.getAddress(),
    ];
    const twoSignatures = {
      ...oneSignature,
      identity: { ...oneSignature.identity, minimumsignatures: 2 },
    };
    const request = signedRequest([0, 1], [keys[0], uncompressed]);
    const evidence = inspectAuthorizationSigners(
      request,
      oneSignature,
      twoSignatures,
      twoSignatures
    );

    expect(evidence.signedKeyIDs).toEqual([
      normalizeAuthorizationKeyID(keys[0].getAddress()),
      normalizeAuthorizationKeyID(uncompressed.getAddress()),
    ]);
    expect(evidence.eligibleKeyIDs).toHaveLength(2);
    expect(evidence.requiredSignatures).toBe(2);
    expect(evidence.valid).toBe(false);

    // The ordinary signed-height threshold receives the same protection.
    expect(
      inspectAuthorizationSigners(
        request,
        twoSignatures,
        oneSignature,
        oneSignature
      ).valid
    ).toBe(false);
    expect(
      inspectAuthorizationSigners(
        request,
        oneSignature,
        oneSignature,
        oneSignature
      ).valid
    ).toBe(true);
  });

  test("current revocation fails closed", () => {
    const current = revision();
    current.status = "revoked";
    current.identity.flags = 0x8000;
    expect(
      inspectAuthorizationSigners(
        signedRequest([0]),
        revision(),
        current,
        revision()
      ).valid
    ).toBe(false);
  });

  test.each([0, -1, 1.5, 14, Number.MAX_SAFE_INTEGER])(
    "rejects invalid threshold %s",
    (threshold) => {
      expect(() =>
        inspectAuthorizationSigners(
          signedRequest([0]),
          revision(),
          revision([0], threshold),
          revision()
        )
      ).toThrow(/threshold/);
    }
  );

  test("authority revisions remain bound to delegate and lookup system", () => {
    const wrongSystem = { ...revision(), systemID: OTHER_SYSTEM };
    expect(() =>
      inspectAuthorizationSigners(
        signedRequest([0]),
        revision(),
        wrongSystem,
        revision()
      )
    ).toThrow(/system/);

    const wrongIdentity = revision();
    wrongIdentity.identity.identityaddress = OTHER_SYSTEM;
    expect(() =>
      inspectAuthorizationSigners(
        signedRequest([0]),
        revision(),
        revision(),
        wrongIdentity
      )
    ).toThrow(/identity/);
  });

  test("cannot swap signed data or signature metadata", () => {
    const request = signedRequest([0]);
    request.salt = Buffer.alloc(32, 10);
    expect(
      inspectAuthorizationSigners(request, revision(), revision(), revision())
        .valid
    ).toBe(false);

    const alteredMetadata = signedRequest([0]);
    alteredMetadata.signature!.signatureVersion = new BN(1);
    expect(() =>
      inspectAuthorizationSigners(
        alteredMetadata,
        revision(),
        revision(),
        revision()
      )
    ).toThrow(/signature/);
  });

  test.each([0, 2])(
    "rejects unsupported signature metadata version %i",
    (version) => {
      const request = signedRequest([0]);
      request.signature!.version = new BN(version);
      expect(() =>
        inspectAuthorizationSigners(request, revision(), revision())
      ).toThrow(/metadata/);
    }
  );

  test.each(["vdxfKeys", "vdxfKeyNames", "boundHashes", "statements"] as const)(
    "rejects unflagged %s metadata",
    (field) => {
      const request = signedRequest([0]);
      request.signature![field] = [];
      expect(() =>
        inspectAuthorizationSigners(request, revision(), revision())
      ).toThrow(/metadata/);
    }
  );

  test("rejects unknown signature flags and an omitted nondefault system", () => {
    const request = signedRequest([0]);
    request.signature!.flags = request.signature!.flags.or(new BN(32));
    expect(() =>
      inspectAuthorizationSigners(request, revision(), revision())
    ).toThrow(/metadata/);

    request.signature!.flags = new BN(0);
    expect(() =>
      inspectAuthorizationSigners(request, revision(), revision())
    ).toThrow(/network default/);
  });

  test("rejects trailing signature bytes and future signed-height state", () => {
    const request = signedRequest([0]);
    request.signature!.signatureAsVch = Buffer.concat([
      request.signature!.signatureAsVch,
      Buffer.from([0]),
    ]);
    expect(() =>
      inspectAuthorizationSigners(request, revision(), revision(), revision())
    ).toThrow(/signature/);
    expect(() =>
      inspectAuthorizationSigners(
        signedRequest([0]),
        { ...revision(), blockheight: SIGNED_HEIGHT + 1 },
        revision()
      )
    ).toThrow(/newer/);
  });
});

describe("authorization identity revision lookup", () => {
  test("reads current state anew and retains lookup-system provenance", async () => {
    const identity = revision();
    identity.identity.systemid = OTHER_SYSTEM;
    const context = source(identity);
    const first = await loadAuthorizationIdentity(context, binding);
    await loadAuthorizationIdentity(context, binding);

    expect(first.systemID).toBe(SYSTEM);
    expect(first.identity.systemid).toBe(OTHER_SYSTEM);
    expect(context.rpc.getIdentity).toHaveBeenCalledTimes(2);
  });

  test("matches the exact outpoint returned at the recorded lookup height", async () => {
    const context = source();
    const loaded = await loadOriginalAuthorizationIdentity(context, binding, {
      lookupHeight: ORIGINAL_HEIGHT,
      txid: ORIGINAL_TXID.toUpperCase(),
      vout: 1,
    });

    expect(loaded.txid).toBe(ORIGINAL_TXID);
    expect(context.rpc.getIdentity).toHaveBeenCalledWith(
      DELEGATE,
      ORIGINAL_HEIGHT
    );
    expect(context.rpc.request).not.toHaveBeenCalled();
  });

  test("normalizes history output.voutnum for an earlier same-block revision", async () => {
    const original = revision();
    const context = source({ ...original, txid: CURRENT_TXID }, [
      {
        identity: original.identity,
        height: ORIGINAL_HEIGHT,
        output: { txid: ORIGINAL_TXID, voutnum: 1 },
      },
    ]);
    const loaded = await loadOriginalAuthorizationIdentity(context, binding, {
      lookupHeight: ORIGINAL_HEIGHT,
      txid: ORIGINAL_TXID,
      vout: 1,
    });

    expect(loaded.txid).toBe(ORIGINAL_TXID);
    expect(loaded.vout).toBe(1);
    const request = context.rpc.request.mock.calls[0][0];
    expect(request.cmd).toBe("getidentityhistory");
    expect(request.getParams()).toEqual([
      DELEGATE,
      ORIGINAL_HEIGHT,
      ORIGINAL_HEIGHT,
    ]);
  });

  test.each([
    [],
    [
      {
        identity: revision().identity,
        height: ORIGINAL_HEIGHT,
        output: { txid: ORIGINAL_TXID, voutnum: 2 },
      },
    ],
    [
      {
        identity: revision().identity,
        height: ORIGINAL_HEIGHT + 1,
        output: { txid: ORIGINAL_TXID, voutnum: 1 },
      },
    ],
  ])(
    "never substitutes a missing or different historical outpoint",
    async (...entries) => {
      const context = source({ ...revision(), txid: CURRENT_TXID }, entries);
      await expect(
        loadOriginalAuthorizationIdentity(context, binding, {
          lookupHeight: ORIGINAL_HEIGHT,
          txid: ORIGINAL_TXID,
          vout: 1,
        })
      ).rejects.toThrow(/exact original/);
    }
  );

  test("history entries must independently match the requested identity", async () => {
    const original = revision();
    original.identity.identityaddress = OTHER_SYSTEM;
    const context = source({ ...revision(), txid: CURRENT_TXID }, [
      {
        identity: original.identity,
        height: ORIGINAL_HEIGHT,
        output: { txid: ORIGINAL_TXID, voutnum: 1 },
      },
    ]);

    await expect(
      loadOriginalAuthorizationIdentity(context, binding, {
        lookupHeight: ORIGINAL_HEIGHT,
        txid: ORIGINAL_TXID,
        vout: 1,
      })
    ).rejects.toThrow(/identity/);
  });

  test("rejects mismatched source systems before issuing RPC calls", async () => {
    const context = source();
    context.systemID = OTHER_SYSTEM;
    await expect(loadAuthorizationIdentity(context, binding)).rejects.toThrow(
      /different system/
    );
    expect(context.rpc.getIdentity).not.toHaveBeenCalled();
  });

  test("rejects mismatched identities and invalid outpoint fields", async () => {
    const identity = revision();
    identity.identity.identityaddress = OTHER_SYSTEM;
    await expect(
      loadAuthorizationIdentity(source(identity), binding)
    ).rejects.toThrow(/identity/);
    await expect(
      loadAuthorizationIdentity(source({ ...revision(), vout: -1 }), binding)
    ).rejects.toThrow(/uint32/);
    await expect(
      loadAuthorizationIdentity(source({ ...revision(), txid: "123" }), binding)
    ).rejects.toThrow(/hex/);
  });

  test("unavailable history fails closed", async () => {
    const context = source({ ...revision(), txid: CURRENT_TXID });
    context.rpc.request.mockResolvedValue({
      result: undefined,
      error: { message: "History unavailable" },
    });
    await expect(
      loadOriginalAuthorizationIdentity(context, binding, {
        lookupHeight: ORIGINAL_HEIGHT,
        txid: ORIGINAL_TXID,
        vout: 1,
      })
    ).rejects.toThrow(/History unavailable/);
  });
});
