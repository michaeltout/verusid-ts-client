import BN from "bn.js";
import {
  APP_AUTHORIZATION_REQUEST_VDXF_ORDINAL,
  AppAuthorizationOutcome,
  AppAuthorizationOfferRole,
  AppAuthorizationRequestDetails,
  AppAuthorizationRequestOrdinalVDXFObject,
  AppAuthorizationResponseOrdinalVDXFObject,
  AuthenticationRequestOrdinalVDXFObject,
  CompactIAddressObject,
  GenericRequest,
  GenericResponse,
  I_ADDR_VERSION,
  OrdinalVDXFObject,
  RecipientConstraint,
  ResponseURI,
  SaplingPaymentAddress,
  SpendableKeyDetails,
  toBase58Check,
} from "verus-typescript-primitives";
import {
  APP_AUTHORIZATION_SALT_BYTES,
  DEFAULT_APP_AUTHORIZATION_GIFT_EXPIRY_SECONDS,
  CreateAppAuthorizationRequestParams,
  createAppAuthorizationRequest,
  createAppAuthorizationResponse,
  getAppAuthorizationOperationID,
  hasAppAuthorizationRequest,
  normalizeAppAuthorizationOffers,
  validateAppAuthorizationRequest,
  validateAppAuthorizationResponse,
} from "../authorization/handshake";

const CREATED_AT = 1_700_000_000;
const EXPIRY_TIME = CREATED_AT + 60 * 60;
const address = (value: number) => toBase58Check(Buffer.alloc(20, value), I_ADDR_VERSION);
const delegate = { systemID: address(1), identityID: address(2) };
const user = { systemID: address(3), identityID: address(4), parentID: address(5) };

function makeRequest(overrides: Partial<CreateAppAuthorizationRequestParams> = {}): GenericRequest {
  const request = createAppAuthorizationRequest({
    appID: address(6),
    delegate,
    requestID: address(7),
    createdAt: new BN(CREATED_AT),
    expiryTime: new BN(EXPIRY_TIME),
    ...overrides,
  });

  // These tests exercise structural admission, never cryptographic verification.
  request.signature!.signatureAsVch = Buffer.from("structural-test-signature");

  return request;
}

function makeResponse(request = makeRequest()) {
  const response = createAppAuthorizationResponse(request, {
    user,
    outcome: AppAuthorizationOutcome.SUCCESS,
    createdAt: new BN(EXPIRY_TIME + 1),
  });
  response.signature!.signatureAsVch = Buffer.from("structural-test-response-signature");

  return { request, response };
}

function admit(request: GenericRequest) {
  return validateAppAuthorizationRequest(request, { now: CREATED_AT + 1 });
}

test("gift templates default to 24 hours and fresh cryptographic salts, preserving explicit deadlines", () => {
  const gift = new SpendableKeyDetails({ data: Buffer.from("fixture seed") });
  const first = makeRequest({ gift, expiryTime: undefined });
  const second = makeRequest({ gift, expiryTime: undefined });
  const { authentication } = admit(first);

  expect(authentication.expiryTime!.toNumber()).toBe(CREATED_AT + DEFAULT_APP_AUTHORIZATION_GIFT_EXPIRY_SECONDS);
  expect(first.salt).toHaveLength(APP_AUTHORIZATION_SALT_BYTES);
  expect(first.salt).not.toEqual(second.salt);
  expect(admit(makeRequest({ gift })).authentication.expiryTime!.toNumber()).toBe(EXPIRY_TIME);
  expect(() => makeRequest({ expiryTime: undefined })).toThrow(/explicit expiry/);
});

test("offer normalization preserves inventory order and compatible roles while rejecting duplicates and selectors", () => {
  const offers = normalizeAppAuthorizationOffers([
    { role: AppAuthorizationOfferRole.STORAGE, identity: address(8) },
    { role: AppAuthorizationOfferRole.AUTHORITY, identity: address(9) },
    { role: AppAuthorizationOfferRole.REVOCATION, identity: address(9) },
  ])!;

  expect(offers.map(offer => offer.identity.address)).toEqual([address(8), address(9), address(9)]);
  expect(() => normalizeAppAuthorizationOffers([offers[0], offers[0]])).toThrow(/Duplicate/);
  expect(() => normalizeAppAuthorizationOffers([{ ...offers[0], systemID: address(1) } as any])).toThrow();
  expect(() => normalizeAppAuthorizationOffers([{ role: AppAuthorizationOfferRole.STORAGE, identity: "name@" }])).toThrow();
  expect(() => normalizeAppAuthorizationOffers([{ role: 99 as AppAuthorizationOfferRole, identity: address(8) }])).toThrow();
});

test("strict authorization admission rejects missing signatures, altered ordering, duplicates, and unrelated operations", () => {
  const unsigned = createAppAuthorizationRequest({
    appID: address(6), delegate, requestID: address(7),
    createdAt: new BN(CREATED_AT), expiryTime: new BN(EXPIRY_TIME),
  });
  expect(() => admit(unsigned)).toThrow(/signed envelope/);

  for (const alter of [
    (request: GenericRequest) => request.details.reverse(),
    (request: GenericRequest) => request.details.push(request.details[1]),
    (request: GenericRequest) => request.details.push(new OrdinalVDXFObject()),
    (request: GenericRequest) => { request.details[0] = request.details[1]; },
  ]) {
    const request = makeRequest();
    alter(request);
    expect(() => admit(request)).toThrow(/exactly authentication/);
  }

  const malformed = makeRequest();
  malformed.details[1] = new OrdinalVDXFObject({ type: APP_AUTHORIZATION_REQUEST_VDXF_ORDINAL });
  expect(hasAppAuthorizationRequest(malformed)).toBe(true);
  expect(() => admit(malformed)).toThrow();
});

test("required correlation, expiry, salt, and supported flags fail closed", () => {
  for (const alter of [
    (request: GenericRequest) => { request.salt = Buffer.alloc(APP_AUTHORIZATION_SALT_BYTES - 1); },
    (request: GenericRequest) => { request.requestID = CompactIAddressObject.fromAddress(address(8)); },
    (request: GenericRequest) => { request.flags = request.flags.or(new BN(1 << 15)); },
    (request: GenericRequest) => { request.flags = request.flags.xor(GenericRequest.FLAG_MULTI_DETAILS); },
    (request: GenericRequest) => { (request.details[1] as AppAuthorizationRequestOrdinalVDXFObject).data.flags = AppAuthorizationRequestDetails.FLAG_CONTAINS_PERMISSIONS; },
    (request: GenericRequest) => { ((request.details[1] as AppAuthorizationRequestOrdinalVDXFObject).data as any).permissions = {}; },
  ]) {
    const request = makeRequest();
    alter(request);
    expect(() => admit(request)).toThrow();
  }

  expect(() => validateAppAuthorizationRequest(makeRequest(), { now: EXPIRY_TIME })).toThrow(/expired/);
});

test("caller admission limits cover the complete request and nested gift without a protocol size cap", () => {
  const request = makeRequest({ gift: new SpendableKeyDetails({ data: Buffer.alloc(2048, 1) }) });
  expect(() => admit(request)).not.toThrow();
  expect(() => validateAppAuthorizationRequest(request, { now: CREATED_AT, maxRequestBytes: 100 })).toThrow(/request exceeds/);
  expect(() => validateAppAuthorizationRequest(request, { now: CREATED_AT, maxGiftBytes: 100 })).toThrow(/gift exceeds/);
});

test("logical operation ID ignores signature encoding but binds signer/system and signed request data", () => {
  const request = makeRequest();
  const original = getAppAuthorizationOperationID(request);
  request.signature!.signatureAsVch = Buffer.from("different-signature-encoding");
  expect(getAppAuthorizationOperationID(request)).toBe(original);

  request.signature!.identityID = CompactIAddressObject.fromAddress(address(9));
  expect(getAppAuthorizationOperationID(request)).not.toBe(original);
  request.signature!.identityID = CompactIAddressObject.fromAddress(delegate.identityID);
  request.signature!.systemID = CompactIAddressObject.fromAddress(address(9));
  expect(getAppAuthorizationOperationID(request)).not.toBe(original);
  request.signature!.systemID = CompactIAddressObject.fromAddress(delegate.systemID);
  request.salt![0] ^= 1;
  expect(getAppAuthorizationOperationID(request)).not.toBe(original);
});

test("success permits late selected users and a response after expiry, including users on another system", () => {
  const { request, response } = makeResponse();
  expect(() => validateAppAuthorizationResponse(response, request, user)).not.toThrow();
  expect(response.signature!.systemID.address).not.toBe(request.signature!.systemID.address);
  expect(response.requestHash).toEqual(request.getRawDataSha256());
  expect(() => validateAppAuthorizationRequest(request, { now: EXPIRY_TIME + 1 })).toThrow(/expired/);
});

test("response correlation binds selected user, app, delegate, original signing system, request and derived grant ID", () => {
  for (const alter of [
    (response: ReturnType<typeof createAppAuthorizationResponse>) => { response.signature!.identityID = CompactIAddressObject.fromAddress(address(9)); },
    (response: ReturnType<typeof createAppAuthorizationResponse>) => { response.signature!.systemID = CompactIAddressObject.fromAddress(address(9)); },
    (response: ReturnType<typeof createAppAuthorizationResponse>) => { response.appOrDelegatorID = CompactIAddressObject.fromAddress(address(9)); },
    (response: ReturnType<typeof createAppAuthorizationResponse>) => { response.requestHash = Buffer.alloc(32); },
    (response: ReturnType<typeof createAppAuthorizationResponse>) => { response.signature!.signatureAsVch = Buffer.alloc(0); },
    (response: ReturnType<typeof createAppAuthorizationResponse>) => { (response.details[0] as AppAuthorizationResponseOrdinalVDXFObject).data.delegateID = address(9); },
    (response: ReturnType<typeof createAppAuthorizationResponse>) => { (response.details[0] as AppAuthorizationResponseOrdinalVDXFObject).data.requestSigningSystemID = address(9); },
    (response: ReturnType<typeof createAppAuthorizationResponse>) => { (response.details[0] as AppAuthorizationResponseOrdinalVDXFObject).data.grantID = "ab".repeat(32); },
  ]) {
    const { request, response } = makeResponse();
    alter(response);
    expect(() => validateAppAuthorizationResponse(response, request, user)).toThrow();
  }
});

test("recipient alternatives are ORed within type, with every type required and immediate parent checked", () => {
  const request = makeRequest({ recipientConstraints: [
    RecipientConstraint.requiredIDFromAddress(address(9)),
    RecipientConstraint.requiredIDFromAddress(user.identityID),
    RecipientConstraint.requiredSystemFromAddress(user.systemID),
    RecipientConstraint.requiredParentFromAddress(user.parentID),
  ] });
  const { response } = makeResponse(request);
  expect(() => validateAppAuthorizationResponse(response, request, user)).not.toThrow();
  expect(() => validateAppAuthorizationResponse(response, request, { ...user, parentID: address(9) })).toThrow(/recipient constraints/);
  expect(() => validateAppAuthorizationResponse(response, request, { ...user, parentID: undefined })).toThrow(/recipient constraints/);

  const authentication = (request.details[0] as AuthenticationRequestOrdinalVDXFObject).data;
  authentication.recipientConstraints![0].type = 99;
  expect(() => admit(request)).toThrow(/Unsupported authentication/);
});

test("required storage cannot complete without bindings and unsuccessful outcomes cannot claim a grant", () => {
  const request = makeRequest({ requiresSharedStorage: true });
  expect(() => makeResponse(request)).toThrow(/Incomplete success/);

  const response = createAppAuthorizationResponse(request, { user, outcome: AppAuthorizationOutcome.CANCELLED });
  response.signature!.signatureAsVch = Buffer.from("structural-test-signature");
  expect(validateAppAuthorizationResponse(response, request, user).grantID).toBeUndefined();
  expect(() => createAppAuthorizationResponse(request, {
    user, outcome: AppAuthorizationOutcome.CANCELLED,
    grantTransaction: { txid: "ab".repeat(32), vout: 0 },
  })).toThrow(/Non-success/);
});


test("constructed signed wire envelopes retain strict validation and response correlation after decoding", () => {
  const original = makeRequest({
    gift: new SpendableKeyDetails({ data: Buffer.from("fixture gift seed") }),
    offeredIdentities: [{ role: AppAuthorizationOfferRole.AUTHORITY, identity: user.identityID }],
    recipientConstraints: [RecipientConstraint.requiredSystemFromAddress(user.systemID)],
  });
  const decoded = new GenericRequest();
  expect(decoded.fromBuffer(original.toBuffer())).toBe(original.toBuffer().length);
  expect(() => admit(decoded)).not.toThrow();
  expect(getAppAuthorizationOperationID(decoded)).toBe(getAppAuthorizationOperationID(original));

  const { response } = makeResponse(decoded);
  expect(() => validateAppAuthorizationResponse(response, original, user)).not.toThrow();
});


test("request delivery fields must be covered by their signed presence flags", () => {
  const encryptionAddress = SaplingPaymentAddress.fromAddressString(
    "zs1wczplx4kegw32h8g0f7xwl57p5tvnprwdmnzmdnsw50chcl26f7tws92wk2ap03ykaq6jyyztfa"
  );
  const responseURIs = [ResponseURI.fromUriString("https://example.com/authorization")];
  const cases = [
    { flag: GenericRequest.FLAG_HAS_RESPONSE_URIS, property: "responseURIs", value: responseURIs },
    { flag: GenericRequest.FLAG_HAS_ENCRYPT_RESPONSE_TO_ADDRESS, property: "encryptResponseToAddress", value: encryptionAddress },
    { flag: GenericRequest.FLAG_HAS_PREFERRED_HANDLER, property: "preferredHandler", value: 0 },
  ];

  for (const { flag, property, value } of cases) {
    const request = makeRequest();
    const signedHash = request.getRawDataSha256();
    (request as any)[property] = value;
    expect(request.getRawDataSha256()).toEqual(signedHash);
    expect(() => admit(request)).toThrow(/response-delivery flags/);

    delete (request as any)[property];
    request.flags = request.flags.or(flag);
    expect(() => admit(request)).toThrow(/response-delivery flags/);
  }

  const request = makeRequest({ responseURIs, encryptResponseToAddress: encryptionAddress, preferredHandler: 0 });
  expect(() => admit(request)).not.toThrow();
  const parsed = new GenericRequest();
  parsed.fromBuffer(request.toBuffer());
  expect(() => admit(parsed)).not.toThrow();
});

test("response request IDs, salt, and handler metadata cannot hide outside signed bytes", () => {
  const { request, response } = makeResponse();
  response.flags = response.flags.xor(GenericResponse.FLAG_HAS_REQUEST_ID);
  expect(() => validateAppAuthorizationResponse(response, request, user)).toThrow(/envelope presence/);
  response.flags = response.flags.or(GenericResponse.FLAG_HAS_REQUEST_ID);

  response.salt = Buffer.alloc(APP_AUTHORIZATION_SALT_BYTES);
  expect(() => validateAppAuthorizationResponse(response, request, user)).toThrow(/envelope presence/);
  response.salt = undefined;

  response.handledBy = 0;
  expect(() => validateAppAuthorizationResponse(response, request, user)).toThrow(/response presence/);
  response.flags = response.flags.or(GenericResponse.FLAG_HAS_HANDLED_BY);
  expect(() => validateAppAuthorizationResponse(response, request, user)).not.toThrow();

  delete (response as any).handledBy;
  expect(() => validateAppAuthorizationResponse(response, request, user)).toThrow(/response presence/);
});
