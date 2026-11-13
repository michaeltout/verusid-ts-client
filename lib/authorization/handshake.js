"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_APP_AUTHORIZATION_GIFT_EXPIRY_SECONDS = exports.APP_AUTHORIZATION_SALT_BYTES = void 0;
exports.normalizeAppAuthorizationOffers = normalizeAppAuthorizationOffers;
exports.hasAppAuthorizationRequest = hasAppAuthorizationRequest;
exports.validateAppAuthorizationEnvelope = validateAppAuthorizationEnvelope;
exports.validateAppAuthorizationRequest = validateAppAuthorizationRequest;
exports.createAppAuthorizationRequest = createAppAuthorizationRequest;
exports.getAppAuthorizationOperationID = getAppAuthorizationOperationID;
exports.validateAppAuthorizationResponse = validateAppAuthorizationResponse;
exports.createAppAuthorizationResponse = createAppAuthorizationResponse;
const bn_js_1 = __importDefault(require("bn.js"));
const crypto_1 = require("crypto");
const verus_typescript_primitives_1 = require("verus-typescript-primitives");
const validation_1 = require("../requests/validation");
const time_1 = require("../constants/time");
const time_2 = require("../utils/time");
exports.APP_AUTHORIZATION_SALT_BYTES = 32;
exports.DEFAULT_APP_AUTHORIZATION_GIFT_EXPIRY_SECONDS = time_1.SECONDS_PER_DAY;
const OPERATION_ID_DOMAIN = "VerusAppAuthorizationOperation/v1\0";
/** Normalize only the address representation; role validation and deduplication belong to the codec. */
function normalizeAppAuthorizationOffers(offers) {
    if (offers === undefined)
        return undefined;
    const normalized = offers.map((offer) => {
        // In particular, do not silently discard per-offer system selectors.
        (0, verus_typescript_primitives_1.rejectUnknownFields)(offer, ["role", "identity"]);
        const identity = typeof offer.identity === "string"
            ? verus_typescript_primitives_1.CompactIAddressObject.fromAddress(offer.identity)
            : offer.identity;
        return { role: offer.role, identity };
    });
    new verus_typescript_primitives_1.AppAuthorizationRequestDetails({ offeredIdentities: normalized });
    return normalized;
}
/** Detect the wire ordinal as well as its class so malformed payloads cannot bypass admission. */
function hasAppAuthorizationRequest(request) {
    return (Array.isArray(request.details) &&
        request.details.some((detail) => detail instanceof verus_typescript_primitives_1.AppAuthorizationRequestOrdinalVDXFObject ||
            (bn_js_1.default.isBN(detail === null || detail === void 0 ? void 0 : detail.type) &&
                detail.type.eq(verus_typescript_primitives_1.APP_AUTHORIZATION_REQUEST_VDXF_ORDINAL))));
}
function validateSize(size, limit, description) {
    if (limit !== undefined &&
        (!Number.isSafeInteger(limit) || limit < 1 || size > limit)) {
        throw new Error(`${description} exceeds its configured admission limit.`);
    }
}
/** Validate signed envelope fields shared by bootstrap, delegated requests and completions. */
function validateAppAuthorizationEnvelope(envelope, requireSignature = true, allowEncryptedDetails = false) {
    (0, validation_1.validateSignedGenericEnvelope)(envelope, requireSignature, allowEncryptedDetails);
    if (!envelope.hasCreatedAt() || !envelope.hasAppOrDelegatorID()) {
        throw new Error("Authorization requires a creation time and app identity.");
    }
}
function validateRequest(request, options, requireSignature) {
    if (!Array.isArray(request.details) ||
        request.details.length !== 2 ||
        !(request.details[0] instanceof verus_typescript_primitives_1.AuthenticationRequestOrdinalVDXFObject) ||
        !(request.details[1] instanceof verus_typescript_primitives_1.AppAuthorizationRequestOrdinalVDXFObject) ||
        !request.details[0].type.eq(verus_typescript_primitives_1.AUTHENTICATION_REQUEST_VDXF_ORDINAL) ||
        !request.details[1].type.eq(verus_typescript_primitives_1.APP_AUTHORIZATION_REQUEST_VDXF_ORDINAL)) {
        throw new Error("Authorization requires exactly authentication then authorization details.");
    }
    validateAppAuthorizationEnvelope(request, requireSignature);
    const authentication = request.details[0].data;
    const authorization = request.details[1].data;
    if (options.checkExpiry === false) {
        if (options.now != null &&
            (!Number.isSafeInteger(options.now) || options.now < 0)) {
            throw new Error("Invalid admission time.");
        }
        (0, validation_1.validateAuthenticationRequestDetails)(authentication);
    }
    else {
        (0, validation_1.validateAuthenticationExpiry)(authentication, options.now);
    }
    if (!authentication.hasRequestID() || !authentication.hasExpiryTime()) {
        throw new Error("Authorization requires valid authentication, request correlation, and expiry.");
    }
    if (!request.hasRequestID() ||
        request.requestID.address !== authentication.requestID.address) {
        throw new Error("Authorization request IDs do not match.");
    }
    if (authentication.expiryTime.lte(request.createdAt)) {
        throw new Error("Authorization expiry must follow its creation time.");
    }
    if (!request.hasSalt() ||
        request.salt.length !== exports.APP_AUTHORIZATION_SALT_BYTES) {
        throw new Error(`Authorization requires a ${exports.APP_AUTHORIZATION_SALT_BYTES}-byte request salt.`);
    }
    if (!(authorization instanceof verus_typescript_primitives_1.AppAuthorizationRequestDetails)) {
        throw new Error("Invalid authorization details.");
    }
    (0, verus_typescript_primitives_1.rejectUnknownFields)(authorization, [
        "version",
        "flags",
        "gift",
        "offeredIdentities",
    ]);
    authorization.validate();
    if (authorization.gift)
        validateSize(authorization.gift.toBuffer().length, options.maxGiftBytes, "Authorization gift");
    validateSize(request.toBuffer().length, options.maxRequestBytes, "Authorization request");
    return { authentication, authorization };
}
/** Structural admission only; callers must also verify the actual signature and current authority. */
function validateAppAuthorizationRequest(request, options = {}) {
    return validateRequest(request, options, true);
}
/** Construct a signing template; use the existing signGenericRequest method to sign it. */
function createAppAuthorizationRequest(params) {
    var _a, _b, _c;
    (0, verus_typescript_primitives_1.rejectUnknownFields)(params, [
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
    const createdAt = (_a = params.createdAt) !== null && _a !== void 0 ? _a : new bn_js_1.default((0, time_2.getUnixTime)());
    const expiryTime = (_b = params.expiryTime) !== null && _b !== void 0 ? _b : (params.gift
        ? createdAt.addn(exports.DEFAULT_APP_AUTHORIZATION_GIFT_EXPIRY_SECONDS)
        : undefined);
    if (expiryTime === undefined)
        throw new Error("An authorization request without a gift requires an explicit expiry.");
    const authorization = new verus_typescript_primitives_1.AppAuthorizationRequestDetails({
        gift: params.gift,
        offeredIdentities: normalizeAppAuthorizationOffers(params.offeredIdentities),
    });
    if (params.requiresSharedStorage) {
        authorization.flags = authorization.flags.or(verus_typescript_primitives_1.AppAuthorizationRequestDetails.FLAG_REQUIRES_SHARED_STORAGE);
    }
    const requestID = verus_typescript_primitives_1.CompactIAddressObject.fromAddress(params.requestID);
    const request = new verus_typescript_primitives_1.GenericRequest({
        flags: params.isTestnet
            ? verus_typescript_primitives_1.GenericRequest.FLAG_IS_TESTNET
            : verus_typescript_primitives_1.GenericRequest.BASE_FLAGS,
        signature: new verus_typescript_primitives_1.VerifiableSignatureData({
            version: verus_typescript_primitives_1.VerifiableSignatureData.DEFAULT_VERSION,
            systemID: verus_typescript_primitives_1.CompactIAddressObject.fromAddress(params.delegate.systemID),
            identityID: verus_typescript_primitives_1.CompactIAddressObject.fromAddress(params.delegate.identityID),
            isTestnet: params.isTestnet,
        }),
        appOrDelegatorID: verus_typescript_primitives_1.CompactIAddressObject.fromAddress(params.appID),
        requestID,
        createdAt,
        salt: (_c = params.salt) !== null && _c !== void 0 ? _c : (0, crypto_1.randomBytes)(exports.APP_AUTHORIZATION_SALT_BYTES),
        responseURIs: params.responseURIs,
        encryptResponseToAddress: params.encryptResponseToAddress,
        preferredHandler: params.preferredHandler,
        details: [
            new verus_typescript_primitives_1.AuthenticationRequestOrdinalVDXFObject({
                data: new verus_typescript_primitives_1.AuthenticationRequestDetails({
                    requestID,
                    expiryTime,
                    recipientConstraints: params.recipientConstraints,
                }),
            }),
            new verus_typescript_primitives_1.AppAuthorizationRequestOrdinalVDXFObject({ data: authorization }),
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
function getAppAuthorizationOperationID(request) {
    validateAppAuthorizationRequest(request, { checkExpiry: false });
    return (0, verus_typescript_primitives_1.hashData)(Buffer.concat([
        Buffer.from(OPERATION_ID_DOMAIN, "utf8"),
        (0, verus_typescript_primitives_1.decodeDestination)(request.signature.systemID.address, verus_typescript_primitives_1.I_ADDR_VERSION),
        (0, verus_typescript_primitives_1.decodeDestination)(request.signature.identityID.address, verus_typescript_primitives_1.I_ADDR_VERSION),
        request.getRawDataSha256(),
    ]), verus_typescript_primitives_1.EHashTypes.HASH_SHA256).toString("hex");
}
function validateResponse(response, request, user, requireSignature, maxResponseBytes) {
    var _a, _b, _c;
    // Timely submission may confirm after expiry; correlation must remain possible.
    const { authentication, authorization } = validateAppAuthorizationRequest(request, { checkExpiry: false });
    (0, validation_1.validateAuthenticationRecipient)(authentication, user);
    if (!Array.isArray(response.details) ||
        response.details.length !== 1 ||
        !(response.details[0] instanceof verus_typescript_primitives_1.AppAuthorizationResponseOrdinalVDXFObject) ||
        !response.details[0].type.eq(verus_typescript_primitives_1.APP_AUTHORIZATION_RESPONSE_VDXF_ORDINAL)) {
        throw new Error("Expected exactly one authorization response detail.");
    }
    validateAppAuthorizationEnvelope(response, requireSignature);
    const details = response.details[0].data;
    if (!(details instanceof verus_typescript_primitives_1.AppAuthorizationResponseDetails)) {
        throw new Error("Invalid authorization response details.");
    }
    (0, verus_typescript_primitives_1.rejectUnknownFields)(details, [
        "version",
        "flags",
        "outcome",
        "requestSigningSystemID",
        "delegateID",
        "grantID",
        "storageBindings",
        "grantTransaction",
    ]);
    details.validate(!authorization.flags
        .and(verus_typescript_primitives_1.AppAuthorizationRequestDetails.FLAG_REQUIRES_SHARED_STORAGE)
        .isZero());
    const requestHash = request.getRawDataSha256();
    if (!response.hasRequestHash() ||
        !((_a = response.requestHashType) === null || _a === void 0 ? void 0 : _a.eqn(verus_typescript_primitives_1.EHashTypes.HASH_SHA256)) ||
        !((_b = response.requestHash) === null || _b === void 0 ? void 0 : _b.equals(requestHash)) ||
        response.appOrDelegatorID.address !== request.appOrDelegatorID.address ||
        response.signature.identityID.address !== user.identityID ||
        response.signature.systemID.address !== user.systemID ||
        response.isTestnet() !== request.isTestnet() ||
        details.delegateID !== request.signature.identityID.address ||
        details.requestSigningSystemID !== request.signature.systemID.address) {
        throw new Error("Authorization response does not match the outstanding request and selected user.");
    }
    if (response.hasRequestID() &&
        ((_c = response.requestID) === null || _c === void 0 ? void 0 : _c.address) !== request.requestID.address) {
        throw new Error("Authorization response request ID does not match.");
    }
    if (details.outcome === verus_typescript_primitives_1.AppAuthorizationOutcome.SUCCESS) {
        const expectedGrantID = (0, verus_typescript_primitives_1.deriveAppAuthorizationGrantID)(user, {
            systemID: details.requestSigningSystemID,
            identityID: details.delegateID,
        }, request.appOrDelegatorID.address, requestHash.toString("hex"));
        if (details.grantID !== expectedGrantID)
            throw new Error("Authorization response grant ID does not match.");
    }
    validateSize(response.toBuffer().length, maxResponseBytes, "Authorization response");
    return details;
}
/**
 * Correlate against the retained request and selected/resolved user; verify the
 * envelope signature separately. An acknowledgment never authorizes later work.
 */
function validateAppAuthorizationResponse(response, request, user, maxResponseBytes) {
    return validateResponse(response, request, user, true, maxResponseBytes);
}
/** Build a response only after the wallet has resolved the final outcome and selected U. */
function createAppAuthorizationResponse(request, params) {
    var _a;
    (0, verus_typescript_primitives_1.rejectUnknownFields)(params, [
        "user",
        "createdAt",
        "outcome",
        "storageBindings",
        "grantTransaction",
    ]);
    // validateResponse below admits both the original request and this template.
    const requestHash = request.getRawDataSha256();
    const delegate = {
        systemID: request.signature.systemID.address,
        identityID: request.signature.identityID.address,
    };
    const response = new verus_typescript_primitives_1.GenericResponse({
        flags: request.isTestnet()
            ? verus_typescript_primitives_1.GenericResponse.FLAG_IS_TESTNET
            : verus_typescript_primitives_1.GenericResponse.BASE_FLAGS,
        signature: new verus_typescript_primitives_1.VerifiableSignatureData({
            version: verus_typescript_primitives_1.VerifiableSignatureData.DEFAULT_VERSION,
            systemID: verus_typescript_primitives_1.CompactIAddressObject.fromAddress(params.user.systemID),
            identityID: verus_typescript_primitives_1.CompactIAddressObject.fromAddress(params.user.identityID),
            isTestnet: request.isTestnet(),
        }),
        appOrDelegatorID: request.appOrDelegatorID,
        requestID: request.requestID,
        requestHash,
        createdAt: (_a = params.createdAt) !== null && _a !== void 0 ? _a : new bn_js_1.default((0, time_2.getUnixTime)()),
        details: [
            new verus_typescript_primitives_1.AppAuthorizationResponseOrdinalVDXFObject({
                data: new verus_typescript_primitives_1.AppAuthorizationResponseDetails({
                    outcome: params.outcome,
                    requestSigningSystemID: delegate.systemID,
                    delegateID: delegate.identityID,
                    grantID: params.outcome === verus_typescript_primitives_1.AppAuthorizationOutcome.SUCCESS
                        ? (0, verus_typescript_primitives_1.deriveAppAuthorizationGrantID)(params.user, delegate, request.appOrDelegatorID.address, requestHash.toString("hex"))
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
