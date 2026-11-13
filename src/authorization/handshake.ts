import BN from "bn.js";
import { GenericEnvelope } from "verus-typescript-primitives/dist/vdxf/classes/envelope/GenericEnvelope";
import { randomBytes } from "crypto";
import {
  APP_AUTHORIZATION_REQUEST_VDXF_ORDINAL,
  APP_AUTHORIZATION_RESPONSE_VDXF_ORDINAL,
  AUTHENTICATION_REQUEST_VDXF_ORDINAL,
  AppAuthorizationOffer,
  AppAuthorizationOfferRole,
  AppAuthorizationOutcome,
  AppAuthorizationRequestDetails,
  AppAuthorizationRequestOrdinalVDXFObject,
  AppAuthorizationResponseDetails,
  AppAuthorizationResponseDetailsInterface,
  AppAuthorizationResponseOrdinalVDXFObject,
  AuthenticationRequestDetails,
  AuthenticationRequestDetailsInterface,
  AuthenticationRequestOrdinalVDXFObject,
  CompactIAddressObject,
  EHashTypes,
  GenericRequest,
  GenericRequestInterface,
  GenericResponse,
  I_ADDR_VERSION,
  SpendableKeyDetails,
  VerifiableSignatureData,
  decodeDestination,
  deriveAppAuthorizationGrantID,
  hashData,
  rejectUnknownFields,
} from "verus-typescript-primitives";
import {
  AuthenticationRecipient,
  validateAuthenticationExpiry,
  validateAuthenticationRecipient,
  validateAuthenticationRequestDetails,
  validateSignedGenericEnvelope,
} from "../requests/validation";
import type { AppAuthorizationIdentity } from "verus-typescript-primitives";
import { SECONDS_PER_DAY } from "../constants/time";
import { getUnixTime } from "../utils/time";

export const APP_AUTHORIZATION_SALT_BYTES = 32;
export const DEFAULT_APP_AUTHORIZATION_GIFT_EXPIRY_SECONDS = SECONDS_PER_DAY;
const OPERATION_ID_DOMAIN = "VerusAppAuthorizationOperation/v1\0";

export interface AppAuthorizationRequestOptions {
  /** Unix seconds; injectable for deterministic admission tests. */
  now?: number;
  /** Disable only when correlating an already admitted operation's final response. */
  checkExpiry?: boolean;
  maxRequestBytes?: number;
  maxGiftBytes?: number;
}

export interface CreateAppAuthorizationRequestParams
  extends Pick<
    GenericRequestInterface,
    "responseURIs" | "encryptResponseToAddress" | "preferredHandler"
  > {
  appID: string;
  delegate: AppAuthorizationIdentity;
  requestID: string;
  recipientConstraints?: AuthenticationRequestDetailsInterface["recipientConstraints"];
  expiryTime?: BN;
  createdAt?: BN;
  salt?: Buffer;
  gift?: SpendableKeyDetails;
  offeredIdentities?: Array<{
    role: AppAuthorizationOfferRole;
    identity: string | CompactIAddressObject;
  }>;
  requiresSharedStorage?: boolean;
  isTestnet?: boolean;
}

export type AppAuthorizationResponseUser = AuthenticationRecipient;

export interface CreateAppAuthorizationResponseParams
  extends Omit<
    AppAuthorizationResponseDetailsInterface,
    "version" | "flags" | "requestSigningSystemID" | "delegateID" | "grantID"
  > {
  user: AppAuthorizationResponseUser;
  createdAt?: BN;
}

/** Normalize only the address representation; role validation and deduplication belong to the codec. */
export function normalizeAppAuthorizationOffers(
  offers: CreateAppAuthorizationRequestParams["offeredIdentities"]
): AppAuthorizationOffer[] | undefined {
  if (offers === undefined) return undefined;

  const normalized = offers.map((offer) => {
    // In particular, do not silently discard per-offer system selectors.
    rejectUnknownFields(offer, ["role", "identity"]);
    const identity =
      typeof offer.identity === "string"
        ? CompactIAddressObject.fromAddress(offer.identity)
        : offer.identity;

    return { role: offer.role, identity };
  });

  new AppAuthorizationRequestDetails({ offeredIdentities: normalized });

  return normalized;
}

/** Detect the wire ordinal as well as its class so malformed payloads cannot bypass admission. */
export function hasAppAuthorizationRequest(request: GenericRequest): boolean {
  return (
    Array.isArray(request.details) &&
    request.details.some(
      (detail) =>
        detail instanceof AppAuthorizationRequestOrdinalVDXFObject ||
        (BN.isBN(detail?.type) &&
          detail.type.eq(APP_AUTHORIZATION_REQUEST_VDXF_ORDINAL))
    )
  );
}

function validateSize(
  size: number,
  limit: number | undefined,
  description: string
): void {
  if (
    limit !== undefined &&
    (!Number.isSafeInteger(limit) || limit < 1 || size > limit)
  ) {
    throw new Error(`${description} exceeds its configured admission limit.`);
  }
}

/** Validate signed envelope fields shared by bootstrap, delegated requests and completions. */
export function validateAppAuthorizationEnvelope(
  envelope: GenericEnvelope,
  requireSignature = true,
  allowEncryptedDetails = false
): void {
  validateSignedGenericEnvelope(envelope, requireSignature, allowEncryptedDetails);

  if (!envelope.hasCreatedAt() || !envelope.hasAppOrDelegatorID()) {
    throw new Error("Authorization requires a creation time and app identity.");
  }
}

function validateRequest(
  request: GenericRequest,
  options: AppAuthorizationRequestOptions,
  requireSignature: boolean
): {
  authentication: AuthenticationRequestDetails;
  authorization: AppAuthorizationRequestDetails;
} {
  if (
    !Array.isArray(request.details) ||
    request.details.length !== 2 ||
    !(request.details[0] instanceof AuthenticationRequestOrdinalVDXFObject) ||
    !(request.details[1] instanceof AppAuthorizationRequestOrdinalVDXFObject) ||
    !request.details[0].type.eq(AUTHENTICATION_REQUEST_VDXF_ORDINAL) ||
    !request.details[1].type.eq(APP_AUTHORIZATION_REQUEST_VDXF_ORDINAL)
  ) {
    throw new Error(
      "Authorization requires exactly authentication then authorization details."
    );
  }

  validateAppAuthorizationEnvelope(request, requireSignature);

  const authentication = request.details[0].data;
  const authorization = request.details[1].data;

  if (options.checkExpiry === false) {
    if (
      options.now != null &&
      (!Number.isSafeInteger(options.now) || options.now < 0)
    ) {
      throw new Error("Invalid admission time.");
    }

    validateAuthenticationRequestDetails(authentication);
  } else {
    validateAuthenticationExpiry(authentication, options.now);
  }

  if (!authentication.hasRequestID() || !authentication.hasExpiryTime()) {
    throw new Error(
      "Authorization requires valid authentication, request correlation, and expiry."
    );
  }

  if (
    !request.hasRequestID() ||
    request.requestID!.address !== authentication.requestID!.address
  ) {
    throw new Error("Authorization request IDs do not match.");
  }

  if (authentication.expiryTime!.lte(request.createdAt!)) {
    throw new Error("Authorization expiry must follow its creation time.");
  }

  if (
    !request.hasSalt() ||
    request.salt!.length !== APP_AUTHORIZATION_SALT_BYTES
  ) {
    throw new Error(
      `Authorization requires a ${APP_AUTHORIZATION_SALT_BYTES}-byte request salt.`
    );
  }

  if (!(authorization instanceof AppAuthorizationRequestDetails)) {
    throw new Error("Invalid authorization details.");
  }

  rejectUnknownFields(authorization, [
    "version",
    "flags",
    "gift",
    "offeredIdentities",
  ]);
  authorization.validate();
  if (authorization.gift)
    validateSize(
      authorization.gift.toBuffer().length,
      options.maxGiftBytes,
      "Authorization gift"
    );
  validateSize(
    request.toBuffer().length,
    options.maxRequestBytes,
    "Authorization request"
  );

  return { authentication, authorization };
}

/** Structural admission only; callers must also verify the actual signature and current authority. */
export function validateAppAuthorizationRequest(
  request: GenericRequest,
  options: AppAuthorizationRequestOptions = {}
): {
  authentication: AuthenticationRequestDetails;
  authorization: AppAuthorizationRequestDetails;
} {
  return validateRequest(request, options, true);
}

/** Construct a signing template; use the existing signGenericRequest method to sign it. */
export function createAppAuthorizationRequest(
  params: CreateAppAuthorizationRequestParams
): GenericRequest {
  rejectUnknownFields(params, [
    "appID",
    "delegate",
    "requestID",
    "recipientConstraints",
    "expiryTime",
    "createdAt",
    "salt",
    "gift",
    "offeredIdentities",
    "requiresSharedStorage",
    "isTestnet",
    "responseURIs",
    "encryptResponseToAddress",
    "preferredHandler",
  ]);

  const createdAt = params.createdAt ?? new BN(getUnixTime());
  const expiryTime =
    params.expiryTime ??
    (params.gift
      ? createdAt.addn(DEFAULT_APP_AUTHORIZATION_GIFT_EXPIRY_SECONDS)
      : undefined);

  if (expiryTime === undefined)
    throw new Error(
      "An authorization request without a gift requires an explicit expiry."
    );

  const authorization = new AppAuthorizationRequestDetails({
    gift: params.gift,
    offeredIdentities: normalizeAppAuthorizationOffers(
      params.offeredIdentities
    ),
  });

  if (params.requiresSharedStorage) {
    authorization.flags = authorization.flags.or(
      AppAuthorizationRequestDetails.FLAG_REQUIRES_SHARED_STORAGE
    );
  }

  const requestID = CompactIAddressObject.fromAddress(params.requestID);
  const request = new GenericRequest({
    flags: params.isTestnet
      ? GenericRequest.FLAG_IS_TESTNET
      : GenericRequest.BASE_FLAGS,
    signature: new VerifiableSignatureData({
      version: VerifiableSignatureData.DEFAULT_VERSION,
      systemID: CompactIAddressObject.fromAddress(params.delegate.systemID),
      identityID: CompactIAddressObject.fromAddress(params.delegate.identityID),
      isTestnet: params.isTestnet,
    }),
    appOrDelegatorID: CompactIAddressObject.fromAddress(params.appID),
    requestID,
    createdAt,
    salt: params.salt ?? randomBytes(APP_AUTHORIZATION_SALT_BYTES),
    responseURIs: params.responseURIs,
    encryptResponseToAddress: params.encryptResponseToAddress,
    preferredHandler: params.preferredHandler,
    details: [
      new AuthenticationRequestOrdinalVDXFObject({
        data: new AuthenticationRequestDetails({
          requestID,
          expiryTime,
          recipientConstraints: params.recipientConstraints,
        }),
      }),
      new AppAuthorizationRequestOrdinalVDXFObject({ data: authorization }),
    ],
  });

  validateRequest(request, { checkExpiry: false }, false);

  return request;
}

/**
 * Stable across signature encoding changes and re-signing identical request data.
 * A wallet must durably reserve this ID before side effects; this helper is not a
 * replay cache and does not promise exactly-once execution across devices.
 */
export function getAppAuthorizationOperationID(
  request: GenericRequest
): string {
  validateAppAuthorizationRequest(request, { checkExpiry: false });

  return hashData(
    Buffer.concat([
      Buffer.from(OPERATION_ID_DOMAIN, "utf8"),
      decodeDestination(request.signature!.systemID.address, I_ADDR_VERSION),
      decodeDestination(request.signature!.identityID.address, I_ADDR_VERSION),
      request.getRawDataSha256(),
    ]),
    EHashTypes.HASH_SHA256
  ).toString("hex");
}

function validateResponse(
  response: GenericResponse,
  request: GenericRequest,
  user: AppAuthorizationResponseUser,
  requireSignature: boolean,
  maxResponseBytes?: number
): AppAuthorizationResponseDetails {
  // Timely submission may confirm after expiry; correlation must remain possible.
  const { authentication, authorization } = validateAppAuthorizationRequest(
    request,
    { checkExpiry: false }
  );
  validateAuthenticationRecipient(authentication, user);

  if (
    !Array.isArray(response.details) ||
    response.details.length !== 1 ||
    !(
      response.details[0] instanceof AppAuthorizationResponseOrdinalVDXFObject
    ) ||
    !response.details[0].type.eq(APP_AUTHORIZATION_RESPONSE_VDXF_ORDINAL)
  ) {
    throw new Error("Expected exactly one authorization response detail.");
  }

  validateAppAuthorizationEnvelope(response, requireSignature);
  const details = response.details[0].data;

  if (!(details instanceof AppAuthorizationResponseDetails)) {
    throw new Error("Invalid authorization response details.");
  }

  rejectUnknownFields(details, [
    "version",
    "flags",
    "outcome",
    "requestSigningSystemID",
    "delegateID",
    "grantID",
    "storageBindings",
    "grantTransaction",
  ]);
  details.validate(
    !authorization.flags
      .and(AppAuthorizationRequestDetails.FLAG_REQUIRES_SHARED_STORAGE)
      .isZero()
  );
  const requestHash = request.getRawDataSha256();

  if (
    !response.hasRequestHash() ||
    !response.requestHashType?.eqn(EHashTypes.HASH_SHA256) ||
    !response.requestHash?.equals(requestHash) ||
    response.appOrDelegatorID!.address !== request.appOrDelegatorID!.address ||
    response.signature!.identityID.address !== user.identityID ||
    response.signature!.systemID.address !== user.systemID ||
    response.isTestnet() !== request.isTestnet() ||
    details.delegateID !== request.signature!.identityID.address ||
    details.requestSigningSystemID !== request.signature!.systemID.address
  ) {
    throw new Error(
      "Authorization response does not match the outstanding request and selected user."
    );
  }

  if (
    response.hasRequestID() &&
    response.requestID?.address !== request.requestID!.address
  ) {
    throw new Error("Authorization response request ID does not match.");
  }

  if (details.outcome === AppAuthorizationOutcome.SUCCESS) {
    const expectedGrantID = deriveAppAuthorizationGrantID(
      user,
      {
        systemID: details.requestSigningSystemID,
        identityID: details.delegateID,
      },
      request.appOrDelegatorID!.address,
      requestHash.toString("hex")
    );

    if (details.grantID !== expectedGrantID)
      throw new Error("Authorization response grant ID does not match.");
  }

  validateSize(
    response.toBuffer().length,
    maxResponseBytes,
    "Authorization response"
  );

  return details;
}

/**
 * Correlate against the retained request and selected/resolved user; verify the
 * envelope signature separately. An acknowledgment never authorizes later work.
 */
export function validateAppAuthorizationResponse(
  response: GenericResponse,
  request: GenericRequest,
  user: AppAuthorizationResponseUser,
  maxResponseBytes?: number
): AppAuthorizationResponseDetails {
  return validateResponse(response, request, user, true, maxResponseBytes);
}

/** Build a response only after the wallet has resolved the final outcome and selected U. */
export function createAppAuthorizationResponse(
  request: GenericRequest,
  params: CreateAppAuthorizationResponseParams
): GenericResponse {
  rejectUnknownFields(params, [
    "user",
    "createdAt",
    "outcome",
    "storageBindings",
    "grantTransaction",
  ]);

  // validateResponse below admits both the original request and this template.
  const requestHash = request.getRawDataSha256();
  const delegate = {
    systemID: request.signature!.systemID.address,
    identityID: request.signature!.identityID.address,
  };
  const response = new GenericResponse({
    flags: request.isTestnet()
      ? GenericResponse.FLAG_IS_TESTNET
      : GenericResponse.BASE_FLAGS,
    signature: new VerifiableSignatureData({
      version: VerifiableSignatureData.DEFAULT_VERSION,
      systemID: CompactIAddressObject.fromAddress(params.user.systemID),
      identityID: CompactIAddressObject.fromAddress(params.user.identityID),
      isTestnet: request.isTestnet(),
    }),
    appOrDelegatorID: request.appOrDelegatorID,
    requestID: request.requestID,
    requestHash,
    createdAt: params.createdAt ?? new BN(getUnixTime()),
    details: [
      new AppAuthorizationResponseOrdinalVDXFObject({
        data: new AppAuthorizationResponseDetails({
          outcome: params.outcome,
          requestSigningSystemID: delegate.systemID,
          delegateID: delegate.identityID,
          grantID:
            params.outcome === AppAuthorizationOutcome.SUCCESS
              ? deriveAppAuthorizationGrantID(
                  params.user,
                  delegate,
                  request.appOrDelegatorID!.address,
                  requestHash.toString("hex")
                )
              : undefined,
          storageBindings: params.storageBindings,
          grantTransaction: params.grantTransaction,
        }),
      }),
    ],
  });

  validateResponse(response, request, params.user, false);

  return response;
}
