import { BN } from "bn.js";
import {
  AuthorizationCredential,
  AuthorizationStorageBindingCredential,
  AuthorizationStorageKeyCredential,
  ContentMultiMapRemove,
  Credential,
  IDENTITY_FLAG_REVOKED,
  Identity,
  I_ADDR_VERSION,
  R_ADDR_VERSION,
  UnsupportedDelegatorProfileError,
  deriveAppAuthorizationStorageManifest,
  toBase58Check,
} from "verus-typescript-primitives";
import {
  AppAuthorizationRecord,
  DelegatedAppAuthorizationOptions,
  decodeAppAuthorizationRecords,
  verifyAppAuthorizationStorageState,
  verifyDelegatedAppAuthorization,
} from "../authorization/grants";
import { AuthorizationIdentityRevision } from "../authorization/authority";

const address = (value: number) => toBase58Check(Buffer.alloc(20, value), I_ADDR_VERSION);
const USER = { identityID: address(1), systemID: address(2) };
const DELEGATE = { identityID: address(3), systemID: address(4) };
const APP_ID = address(5);
const GRANT_ID = "ab".repeat(32);
const OUTER_KEY = address(6);

function fixture(storage = false, grantID = GRANT_ID) {
  const binding = new AuthorizationStorageBindingCredential({
    version: AuthorizationStorageBindingCredential.VERSION_CURRENT,
    grantID,
    relationshipIndex: 0,
    storageSystemID: DELEGATE.systemID,
    storageID: address(7),
    userKeyID: "11".repeat(20),
    revocationID: address(8),
    recoveryID: address(9),
    keyCount: 1,
  });
  const key = new AuthorizationStorageKeyCredential({
    version: AuthorizationStorageKeyCredential.VERSION_CURRENT,
    grantID,
    relationshipIndex: 0,
    keyIndex: 0,
    keyID: "22".repeat(20),
  });
  const management = storage ? [binding, key] : [];
  const grant = new AuthorizationCredential({
    version: AuthorizationCredential.VERSION_CURRENT,
    flags: storage
      ? AuthorizationCredential.FLAG_CONTAINS_STORAGE_BINDINGS
      : AuthorizationCredential.FLAGS_NONE,
    grantID,
    signingSystemID: DELEGATE.systemID,
    appID: APP_ID,
    delegateID: DELEGATE.identityID,
    originalRevision: { lookupHeight: 10, txid: "33".repeat(32), vout: 1 },
    storageManifestHash: storage
      ? deriveAppAuthorizationStorageManifest(management)
      : undefined,
  });
  const entries = [grant, ...management].map((record, i) => ({
    credential: record.toCredential(),
    source: { ...USER, outerKey: OUTER_KEY, storedValue: Buffer.from([90, i]) },
  }));
  const records = decodeAppAuthorizationRecords(entries);
  const options: DelegatedAppAuthorizationOptions = {
    records,
    user: { ...USER },
    delegate: { ...DELEGATE },
    appID: APP_ID,
    verifyDelegatorProfile: jest.fn(async () => {}),
    verifyUserControl: jest.fn(async () => true),
    verifyAuthority: jest.fn(async () => true),
    verifyStorageControl: jest.fn(async () => true),
  };

  return { grant, binding, key, entries, records, options };
}

describe("authorization credential decoding", () => {
  test("retains immutable provenance for exact encrypted-value removal", () => {
    const f = fixture(true);
    const stored = Buffer.from(f.entries[0].source.storedValue);
    const encoded = f.entries[0].credential.toBuffer();
    const [decoded] = decodeAppAuthorizationRecords([
      { ...f.entries[0], credential: encoded },
    ]);

    f.entries[0].source.storedValue.fill(0);
    (f.entries[0].credential.credential as any).a = address(20);

    expect(decoded.source.storedValue).toEqual(stored);
    expect((decoded.record as AuthorizationCredential).data.appID).toBe(APP_ID);
    expect(ContentMultiMapRemove.removeStoredValue(
      decoded.source.outerKey, decoded.source.storedValue
    ).toBuffer()).toEqual(ContentMultiMapRemove.removeStoredValue(OUTER_KEY, stored).toBuffer());
  });

  test("skips unrelated credentials and rejects malformed authorization records", () => {
    const f = fixture();
    const unrelated = new Credential({
      version: Credential.VERSION_CURRENT,
      credentialKey: address(21),
      credential: { note: "Unrelated user data" },
    });
    expect(decodeAppAuthorizationRecords([
      { ...f.entries[0], credential: unrelated }, ...f.entries,
    ])).toHaveLength(1);

    (f.entries[0].credential.credential as any).f =
      AuthorizationCredential.FLAG_CONTAINS_PERMISSIONS.toNumber();
    expect(() => decodeAppAuthorizationRecords(f.entries)).toThrow(/flags/);
  });

  test("rejects trailing plaintext bytes, missing provenance, and inconsistent wrapper flags", () => {
    const f = fixture();
    const entry = f.entries[0];

    expect(() => decodeAppAuthorizationRecords([{
      ...entry, credential: Buffer.concat([entry.credential.toBuffer(), Buffer.from([0])]),
    }])).toThrow(/Trailing/);
    expect(() => decodeAppAuthorizationRecords([{
      ...entry, source: { ...entry.source, storedValue: Buffer.alloc(0) },
    }])).toThrow(/original stored/);
    entry.credential.flags = new BN(8);
    expect(() => decodeAppAuthorizationRecords([entry])).toThrow(/envelope/);
  });
});

describe("independent delegated grant checks", () => {
  test("requires current user and authority checks without requiring storage for a simple grant", async () => {
    const f = fixture();
    expect((await verifyDelegatedAppAuthorization(f.options))!.record.data.grantID).toBe(GRANT_ID);
    expect(f.options.verifyUserControl).toHaveBeenCalledWith(USER);
    expect(f.options.verifyAuthority).toHaveBeenCalledTimes(1);
    expect(f.options.verifyStorageControl).not.toHaveBeenCalled();
    expect(f.options.verifyDelegatorProfile).toHaveBeenCalledTimes(2);
    expect(f.options.verifyDelegatorProfile).toHaveBeenCalledWith({
      identityID: APP_ID, systemID: DELEGATE.systemID,
    });
  });

  test("requires a current profile check before evaluating an existing grant", async () => {
    const f = fixture();
    f.options.verifyDelegatorProfile = undefined as any;

    expect(await verifyDelegatedAppAuthorization(f.options)).toBeUndefined();
    expect(f.options.verifyUserControl).not.toHaveBeenCalled();
    expect(f.options.verifyAuthority).not.toHaveBeenCalled();
  });

  test("surfaces unsupported profile presence before private control or authority checks", async () => {
    const f = fixture();
    f.options.verifyDelegatorProfile = async () => { throw new UnsupportedDelegatorProfileError(); };

    await expect(verifyDelegatedAppAuthorization(f.options)).rejects.toMatchObject({
      code: "UNSUPPORTED_DELEGATOR_PROFILE",
    });
    expect(f.options.verifyUserControl).not.toHaveBeenCalled();
    expect(f.options.verifyAuthority).not.toHaveBeenCalled();
    expect(f.options.verifyStorageControl).not.toHaveBeenCalled();
  });

  test("does not swallow a profile added while checking a candidate grant", async () => {
    const f = fixture();
    f.options.records.push(...fixture(false, "cd".repeat(32)).records);
    f.options.verifyDelegatorProfile = jest.fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValue(new UnsupportedDelegatorProfileError());

    await expect(verifyDelegatedAppAuthorization(f.options)).rejects.toBeInstanceOf(UnsupportedDelegatorProfileError);
    expect(f.options.verifyAuthority).toHaveBeenCalledTimes(1);
  });

  test("does not interpret an unavailable profile read as an empty profile", async () => {
    const f = fixture();
    f.options.verifyDelegatorProfile = async () => { throw new Error("RPC unavailable"); };

    expect(await verifyDelegatedAppAuthorization(f.options)).toBeUndefined();
    expect(f.options.verifyUserControl).not.toHaveBeenCalled();
    expect(f.options.verifyAuthority).not.toHaveBeenCalled();
  });

  test("a failed final profile read rejects all grants for the same app", async () => {
    const f = fixture();
    f.options.records.push(...fixture(false, "cd".repeat(32)).records);
    f.options.verifyDelegatorProfile = jest.fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("RPC unavailable"))
      .mockResolvedValue(undefined);

    expect(await verifyDelegatedAppAuthorization(f.options)).toBeUndefined();
    expect(f.options.verifyAuthority).toHaveBeenCalledTimes(1);
  });

  test.each(["user", "userSystem", "delegate", "system", "app"])(
    "rejects a wrong %s binding", async mismatch => {
      const f = fixture();
      if (mismatch === "user") f.options.user.identityID = address(30);
      if (mismatch === "userSystem") f.options.user.systemID = address(30);
      if (mismatch === "delegate") f.options.delegate.identityID = address(30);
      if (mismatch === "system") f.options.delegate.systemID = address(30);
      if (mismatch === "app") f.options.appID = address(30);

      expect(await verifyDelegatedAppAuthorization(f.options)).toBeUndefined();
      expect(f.options.verifyAuthority).not.toHaveBeenCalled();
    }
  );

  test("does not authorize a missing/deleted grant or broaden failed control", async () => {
    const f = fixture();
    f.options.records = [];
    expect(await verifyDelegatedAppAuthorization(f.options)).toBeUndefined();
    f.options.records = f.records;
    f.options.verifyUserControl = async () => false;
    expect(await verifyDelegatedAppAuthorization(f.options)).toBeUndefined();
    expect(f.options.verifyAuthority).not.toHaveBeenCalled();
  });

  test("requires explicit callbacks and treats RPC exceptions as rejection", async () => {
    const f = fixture();
    f.options.verifyStorageControl = undefined as any;
    expect(await verifyDelegatedAppAuthorization(f.options)).toBeUndefined();
    f.options.verifyStorageControl = async () => true;
    f.options.verifyAuthority = async () => { throw new Error("RPC unavailable"); };
    expect(await verifyDelegatedAppAuthorization(f.options)).toBeUndefined();
  });

  test("validates a complete manifest, collapses identical copies for current storage checks", async () => {
    const f = fixture(true);
    f.options.records = decodeAppAuthorizationRecords([...f.entries, ...f.entries]);

    expect(await verifyDelegatedAppAuthorization(f.options)).toBeDefined();
    expect(f.options.verifyStorageControl).toHaveBeenCalledTimes(1);
    const [binding, keys] = (f.options.verifyStorageControl as jest.Mock).mock.calls[0];
    expect(binding.data.storageSystemID).toBe(DELEGATE.systemID);
    expect(keys).toHaveLength(1);
    expect(keys[0].data.keyID).toBe(f.key.data.keyID);
    expect(f.options.records).toHaveLength(6); // Copies remain available for deletion.
  });

  test.each(["missing", "substituted", "foreignSource", "foreignSystem", "conflict"])(
    "rejects %s management evidence before authority or storage callbacks", async change => {
      const f = fixture(true);
      if (change === "missing") f.options.records.pop();
      if (change === "substituted") {
        (f.records[2].record as AuthorizationStorageKeyCredential).data.keyID = "44".repeat(20);
      }
      if (change === "foreignSource") f.records[2].source.identityID = address(31);
      if (change === "foreignSystem") f.records[2].source.systemID = address(31);
      if (change === "conflict") {
        const conflict = fixture(true);
        (conflict.records[2].record as AuthorizationStorageKeyCredential).data.keyID = "44".repeat(20);
        f.options.records.push(conflict.records[2]);
      }

      expect(await verifyDelegatedAppAuthorization(f.options)).toBeUndefined();
      expect(f.options.verifyAuthority).not.toHaveBeenCalled();
      expect(f.options.verifyStorageControl).not.toHaveBeenCalled();
    }
  );

  test.each(["system", "user", "revocation", "recovery"])(
    "rejects unsuitable storage %s even with a matching manifest", async change => {
      const f = fixture(true);
      if (change === "system") f.binding.data.storageSystemID = USER.systemID;
      if (change === "user") f.binding.data.storageID = USER.identityID;
      if (change === "revocation") f.binding.data.storageID = f.binding.data.revocationID;
      if (change === "recovery") f.binding.data.storageID = f.binding.data.recoveryID;
      f.grant.data.storageManifestHash = deriveAppAuthorizationStorageManifest([f.binding, f.key]);
      const changed: AppAuthorizationRecord[] = [f.grant, f.binding, f.key];
      f.options.records = decodeAppAuthorizationRecords(changed.map((record, i) => ({
        ...f.entries[i], credential: record.toCredential(),
      })));

      expect(await verifyDelegatedAppAuthorization(f.options)).toBeUndefined();
      expect(f.options.verifyAuthority).not.toHaveBeenCalled();
    }
  );

  test("rejects invalid current storage independently of the committed arrangement", async () => {
    const f = fixture(true);
    f.options.verifyStorageControl = async () => false;
    expect(await verifyDelegatedAppAuthorization(f.options)).toBeUndefined();
  });

  test("does not pool partial success between grants, but accepts an independently complete grant", async () => {
    const first = fixture(true);
    const second = fixture(true, "cd".repeat(32));
    first.options.records.push(...second.records);
    first.options.verifyAuthority = async grant => grant.data.grantID === GRANT_ID;
    first.options.verifyStorageControl = async binding => binding.data.grantID !== GRANT_ID;
    expect(await verifyDelegatedAppAuthorization(first.options)).toBeUndefined();

    first.options.verifyAuthority = async grant => grant.data.grantID !== GRANT_ID;
    expect((await verifyDelegatedAppAuthorization(first.options))!.record.data.grantID)
      .toBe(second.grant.data.grantID);
  });

  test("conflicting stored copies cannot change a grant baseline", async () => {
    const f = fixture();
    const conflict = fixture();
    (conflict.records[0].record as AuthorizationCredential).data.originalRevision.vout++;
    f.options.records.push(...conflict.records);
    expect(await verifyDelegatedAppAuthorization(f.options)).toBeUndefined();
    expect(f.options.verifyAuthority).not.toHaveBeenCalled();
  });

  test("caller and callback mutations across awaits do not replace reviewed records", async () => {
    const f = fixture(true);
    const expectedTxid = f.grant.data.originalRevision.txid;
    f.options.verifyUserControl = async user => {
      user.identityID = address(40);
      (f.options.records[0].record as AuthorizationCredential).data.originalRevision.txid = "55".repeat(32);
      await Promise.resolve();
      return true;
    };
    f.options.verifyAuthority = async grant => {
      expect(grant.data.originalRevision.txid).toBe(expectedTxid);
      grant.data.originalRevision.txid = "66".repeat(32);
      return true;
    };
    f.options.verifyStorageControl = async (binding, keys) => {
      binding.data.storageID = USER.identityID;
      keys[0].data.keyID = "77".repeat(20);
      return true;
    };
    const result = await verifyDelegatedAppAuthorization(f.options);
    expect(result!.record.data.originalRevision.txid).toBe(expectedTxid);
    expect(result!.source.identityID).toBe(USER.identityID);
  });
});

describe("current public storage policy", () => {
  function storageFixture() {
    const f = fixture(true);
    const current: AuthorizationIdentityRevision = {
      systemID: DELEGATE.systemID,
      status: "active",
      blockheight: 12,
      txid: "99".repeat(32),
      vout: 0,
      friendlyname: "storage@",
      fullyqualifiedname: "storage@",
      cansignfor: false,
      canspendfor: false,
      identity: {
        version: Identity.VERSION_CURRENT.toNumber(),
        flags: 0,
        name: "storage",
        parent: DELEGATE.systemID,
        identityaddress: f.binding.data.storageID,
        minimumsignatures: 1,
        primaryaddresses: [f.binding.data.userKeyID, f.key.data.keyID].map(
          keyID => toBase58Check(Buffer.from(keyID, "hex"), R_ADDR_VERSION)
        ),
        revocationauthority: f.binding.data.revocationID,
        recoveryauthority: f.binding.data.recoveryID,
      },
    } as AuthorizationIdentityRevision;

    return { ...f, current, verify: () => verifyAppAuthorizationStorageState(f.binding, [f.key], current) };
  }

  test("accepts the recorded arrangement while preserving other instances' keys", () => {
    const f = storageFixture();
    f.current.identity.primaryaddresses.push(toBase58Check(Buffer.alloc(20, 88), R_ADDR_VERSION));
    expect(f.verify()).toBe(true);
  });

  test.each(["revoked", "threshold", "userKey", "appKey", "revocation", "recovery", "system", "identity"])(
    "rejects a changed current %s", change => {
      const f = storageFixture();
      if (change === "revoked") {
        f.current.status = "revoked";
        f.current.identity.flags = IDENTITY_FLAG_REVOKED.toNumber();
      }
      if (change === "threshold") f.current.identity.minimumsignatures = 2;
      if (change === "userKey") f.current.identity.primaryaddresses.shift();
      if (change === "appKey") f.current.identity.primaryaddresses.pop();
      if (change === "revocation") f.current.identity.revocationauthority = address(50);
      if (change === "recovery") f.current.identity.recoveryauthority = address(50);
      if (change === "system") f.current.systemID = USER.systemID;
      if (change === "identity") f.current.identity.identityaddress = USER.identityID;
      expect(f.verify()).toBe(false);
    }
  );

  test("requires complete distinct app-key records from this relationship", () => {
    const f = storageFixture();
    expect(verifyAppAuthorizationStorageState(f.binding, [], f.current)).toBe(false);
    f.key.data.relationshipIndex++;
    expect(f.verify()).toBe(false);
    f.key.data.relationshipIndex--;
    f.key.data.keyID = f.binding.data.userKeyID;
    expect(f.verify()).toBe(false);
  });
});
