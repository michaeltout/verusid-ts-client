"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateAuthenticationRequestDetails = validateAuthenticationRequestDetails;
exports.validateAuthenticationExpiry = validateAuthenticationExpiry;
exports.validateAuthenticationRecipient = validateAuthenticationRecipient;
exports.validateSignedGenericEnvelope = validateSignedGenericEnvelope;
const bn_js_1 = __importDefault(require("bn.js"));
const verus_typescript_primitives_1 = require("verus-typescript-primitives");
const GenericEnvelope_1 = require("verus-typescript-primitives/dist/vdxf/classes/envelope/GenericEnvelope");
const numbers_1 = require("../constants/numbers");
const time_1 = require("../utils/time");
const RECIPIENT_CONSTRAINT_FIELDS = new Map([
    [verus_typescript_primitives_1.RecipientConstraint.REQUIRED_ID, "identityID"],
    [verus_typescript_primitives_1.RecipientConstraint.REQUIRED_SYSTEM, "systemID"],
    [verus_typescript_primitives_1.RecipientConstraint.REQUIRED_PARENT, "parentID"],
]);
const SUPPORTED_ENVELOPE_FLAGS = GenericEnvelope_1.GenericEnvelope.FLAG_SIGNED.or(GenericEnvelope_1.GenericEnvelope.FLAG_HAS_REQUEST_ID)
    .or(GenericEnvelope_1.GenericEnvelope.FLAG_HAS_CREATED_AT)
    .or(GenericEnvelope_1.GenericEnvelope.FLAG_MULTI_DETAILS)
    .or(GenericEnvelope_1.GenericEnvelope.FLAG_IS_TESTNET)
    .or(GenericEnvelope_1.GenericEnvelope.FLAG_HAS_SALT)
    .or(GenericEnvelope_1.GenericEnvelope.FLAG_HAS_APP_OR_DELEGATOR_ID);
const SUPPORTED_REQUEST_FLAGS = SUPPORTED_ENVELOPE_FLAGS.or(verus_typescript_primitives_1.GenericRequest.FLAG_HAS_RESPONSE_URIS)
    .or(verus_typescript_primitives_1.GenericRequest.FLAG_HAS_ENCRYPT_RESPONSE_TO_ADDRESS)
    .or(verus_typescript_primitives_1.GenericRequest.FLAG_HAS_PREFERRED_HANDLER);
const SUPPORTED_RESPONSE_FLAGS = SUPPORTED_ENVELOPE_FLAGS.or(verus_typescript_primitives_1.GenericResponse.FLAG_HAS_REQUEST_HASH).or(verus_typescript_primitives_1.GenericResponse.FLAG_HAS_HANDLED_BY);
function validateTimestamp(timestamp, description) {
    if (!bn_js_1.default.isBN(timestamp) ||
        timestamp.isNeg() ||
        timestamp.gt(numbers_1.MAX_SAFE_INTEGER_BN)) {
        throw new Error(`Invalid ${description}.`);
    }
}
function validateRecipientConstraints(constraints) {
    if (constraints == null)
        return;
    if (!Array.isArray(constraints))
        throw new Error("Invalid authentication recipient constraints.");
    for (const constraint of constraints) {
        if (!constraint || !RECIPIENT_CONSTRAINT_FIELDS.has(constraint.type)) {
            throw new Error("Unsupported authentication recipient constraint.");
        }
        const identity = constraint.identity;
        // Address conversion does not check the compact encoding's version.
        if (!bn_js_1.default.isBN(identity === null || identity === void 0 ? void 0 : identity.version) ||
            identity.version.lt(verus_typescript_primitives_1.CompactIAddressObject.FIRST_VERSION) ||
            identity.version.gt(verus_typescript_primitives_1.CompactIAddressObject.LAST_VERSION)) {
            throw new Error("Unsupported authentication recipient identity version.");
        }
        // Existing recipient constraints may use FQNs. Resolve through their compact
        // address representation before comparing the canonical identity address.
        (0, verus_typescript_primitives_1.decodeDestination)(identity.toIAddress(), verus_typescript_primitives_1.I_ADDR_VERSION);
    }
}
/** Validate authentication fields without requiring optional correlation or expiry fields. */
function validateAuthenticationRequestDetails(authentication) {
    if (!(authentication instanceof verus_typescript_primitives_1.AuthenticationRequestDetails) ||
        !bn_js_1.default.isBN(authentication.flags) ||
        !authentication.flags.eq(authentication.calcFlags(new bn_js_1.default(0))) ||
        !authentication.isValid()) {
        throw new Error("Invalid authentication fields or presence flags.");
    }
    // calcFlags uses truthiness. Validate present values directly so malformed
    // falsy fields cannot disappear from the reconstructed presence flags.
    if (authentication.requestID != null) {
        verus_typescript_primitives_1.CompactIAddressObject.validateCompactIdentityAddress(authentication.requestID);
    }
    if (authentication.expiryTime != null) {
        validateTimestamp(authentication.expiryTime, "authentication expiry");
    }
    validateRecipientConstraints(authentication.recipientConstraints);
}
/** Require a signed authentication deadline that has not reached the current time. */
function validateAuthenticationExpiry(authentication, now = (0, time_1.getUnixTime)()) {
    validateAuthenticationRequestDetails(authentication);
    if (!Number.isSafeInteger(now) || now < 0)
        throw new Error("Invalid admission time.");
    if (!authentication.hasExpiryTime())
        throw new Error("Authentication requires an expiry.");
    if (authentication.expiryTime.lte(new bn_js_1.default(now)))
        throw new Error("Authentication request has expired.");
}
/** Match alternatives within each constraint type, requiring every requested type. */
function validateAuthenticationRecipient(authentication, recipient) {
    validateAuthenticationRequestDetails(authentication);
    (0, verus_typescript_primitives_1.decodeDestination)(recipient.systemID, verus_typescript_primitives_1.I_ADDR_VERSION);
    (0, verus_typescript_primitives_1.decodeDestination)(recipient.identityID, verus_typescript_primitives_1.I_ADDR_VERSION);
    for (const [type, field] of RECIPIENT_CONSTRAINT_FIELDS) {
        const value = recipient[field];
        const constraints = (authentication.recipientConstraints || []).filter((constraint) => constraint.type === type);
        if (constraints.length &&
            (!value ||
                !constraints.some((constraint) => constraint.identity.toIAddress() === value))) {
            throw new Error("Selected response signer does not satisfy the request's recipient constraints.");
        }
    }
}
/**
 * Check a signed envelope's version and field consistency. Encrypted details
 * require an explicit opt-in and subsequent authenticated decryption. This does
 * not verify cryptographic signatures or impose a request-specific app scope,
 * correlation identifier, creation time, expiry, or salt requirement.
 */
function validateSignedGenericEnvelope(envelope, requireSignature = true, allowEncryptedDetails = false) {
    var _a;
    let supportedFlags = envelope instanceof verus_typescript_primitives_1.GenericRequest
        ? SUPPORTED_REQUEST_FLAGS
        : envelope instanceof verus_typescript_primitives_1.GenericResponse
            ? SUPPORTED_RESPONSE_FLAGS
            : SUPPORTED_ENVELOPE_FLAGS;
    if (allowEncryptedDetails) {
        supportedFlags = supportedFlags.or(GenericEnvelope_1.GenericEnvelope.FLAG_DETAILS_ARE_ENCRYPTED);
    }
    if (!Array.isArray(envelope.details) ||
        !bn_js_1.default.isBN(envelope.flags) ||
        envelope.flags.isNeg() ||
        !envelope.flags.and(supportedFlags).eq(envelope.flags) ||
        (!envelope.detailsAreEncrypted() &&
            envelope.hasMultiDetails() !== (envelope.details.length > 1)) ||
        !envelope.isValidVersion() ||
        !envelope.isSigned() ||
        !envelope.signature ||
        (requireSignature && !((_a = envelope.signature.signatureAsVch) === null || _a === void 0 ? void 0 : _a.length))) {
        throw new Error("Expected a supported signed envelope with permitted details encoding.");
    }
    if (envelope.detailsAreEncrypted()) {
        const detail = envelope.details[0];
        // Ciphertext always occupies one descriptor. MULTI_DETAILS describes the
        // plaintext framing and is checked against its count after decryption.
        // Check descriptor flags before serialization, which would normalize them.
        if (envelope.details.length !== 1 ||
            !(detail instanceof verus_typescript_primitives_1.DataDescriptorOrdinalVDXFObject) ||
            !bn_js_1.default.isBN(detail.type) ||
            !detail.type.eq(verus_typescript_primitives_1.DATA_DESCRIPTOR_VDXF_ORDINAL) ||
            !(detail.data instanceof verus_typescript_primitives_1.DataDescriptor) ||
            !bn_js_1.default.isBN(detail.data.version) ||
            !bn_js_1.default.isBN(detail.data.flags) ||
            !detail.data.isValid() ||
            !detail.data.flags.eq(detail.data.calcFlags()) ||
            !detail.data.hasEncryptedData() ||
            !Buffer.isBuffer(detail.data.objectdata) ||
            !detail.data.objectdata.length) {
            throw new Error("Expected one valid encrypted details descriptor.");
        }
    }
    // Only flagged fields are serialized and signed. Reject fields that consumers
    // could otherwise use for correlation or delivery without signature coverage.
    if (envelope.hasRequestID() !== (envelope.requestID != null) ||
        envelope.hasCreatedAt() !== (envelope.createdAt != null) ||
        envelope.hasSalt() !== (envelope.salt != null) ||
        envelope.hasAppOrDelegatorID() !== (envelope.appOrDelegatorID != null)) {
        throw new Error("Inconsistent envelope presence flags.");
    }
    if (envelope instanceof verus_typescript_primitives_1.GenericRequest &&
        (envelope.hasResponseURIs() !== (envelope.responseURIs != null) ||
            envelope.hasEncryptResponseToAddress() !==
                (envelope.encryptResponseToAddress != null) ||
            envelope.hasPreferredHandler() !== (envelope.preferredHandler != null))) {
        throw new Error("Inconsistent response-delivery flags.");
    }
    if (envelope instanceof verus_typescript_primitives_1.GenericResponse &&
        (envelope.hasRequestHash() !== (envelope.requestHash != null) ||
            envelope.hasRequestHash() !== (envelope.requestHashType != null) ||
            envelope.hasHandledBy() !== (envelope.handledBy != null))) {
        throw new Error("Inconsistent response presence flags.");
    }
    if (envelope.hasRequestID()) {
        verus_typescript_primitives_1.CompactIAddressObject.validateCompactIdentityAddress(envelope.requestID);
    }
    if (envelope.hasSalt() && !Buffer.isBuffer(envelope.salt)) {
        throw new Error("Invalid envelope salt.");
    }
    if (envelope.hasCreatedAt())
        validateTimestamp(envelope.createdAt, "envelope creation time");
    if (envelope.hasAppOrDelegatorID()) {
        verus_typescript_primitives_1.CompactIAddressObject.validateCompactIdentityAddress(envelope.appOrDelegatorID);
    }
    verus_typescript_primitives_1.CompactIAddressObject.validateCompactIdentityAddress(envelope.signature.identityID);
    verus_typescript_primitives_1.CompactIAddressObject.validateCompactIdentityAddress(envelope.signature.systemID);
    for (const detail of envelope.details) {
        if (!bn_js_1.default.isBN(detail === null || detail === void 0 ? void 0 : detail.version) ||
            detail.version.lt(verus_typescript_primitives_1.OrdinalVDXFObject.VERSION_FIRST) ||
            detail.version.gt(verus_typescript_primitives_1.OrdinalVDXFObject.VERSION_LAST)) {
            throw new Error("Unsupported envelope detail version.");
        }
    }
}
