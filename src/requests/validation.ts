import BN from "bn.js";
import {
  AuthenticationRequestDetails,
  CompactIAddressObject,
  DATA_DESCRIPTOR_VDXF_ORDINAL,
  DataDescriptor,
  DataDescriptorOrdinalVDXFObject,
  GenericRequest,
  GenericResponse,
  I_ADDR_VERSION,
  OrdinalVDXFObject,
  RecipientConstraint,
  decodeDestination,
} from "verus-typescript-primitives";
import { GenericEnvelope } from "verus-typescript-primitives/dist/vdxf/classes/envelope/GenericEnvelope";
import { MAX_SAFE_INTEGER_BN } from "../constants/numbers";
import { getUnixTime } from "../utils/time";

/** Identity chosen to answer an authentication request, including its resolved parent. */
export interface AuthenticationRecipient {
  identityID: string;
  systemID: string;
  parentID?: string;
}

const RECIPIENT_CONSTRAINT_FIELDS = new Map<
  number,
  keyof AuthenticationRecipient
>([
  [RecipientConstraint.REQUIRED_ID, "identityID"],
  [RecipientConstraint.REQUIRED_SYSTEM, "systemID"],
  [RecipientConstraint.REQUIRED_PARENT, "parentID"],
]);

const SUPPORTED_ENVELOPE_FLAGS = GenericEnvelope.FLAG_SIGNED.or(
  GenericEnvelope.FLAG_HAS_REQUEST_ID
)
  .or(GenericEnvelope.FLAG_HAS_CREATED_AT)
  .or(GenericEnvelope.FLAG_MULTI_DETAILS)
  .or(GenericEnvelope.FLAG_IS_TESTNET)
  .or(GenericEnvelope.FLAG_HAS_SALT)
  .or(GenericEnvelope.FLAG_HAS_APP_OR_DELEGATOR_ID);
const SUPPORTED_REQUEST_FLAGS = SUPPORTED_ENVELOPE_FLAGS.or(
  GenericRequest.FLAG_HAS_RESPONSE_URIS
)
  .or(GenericRequest.FLAG_HAS_ENCRYPT_RESPONSE_TO_ADDRESS)
  .or(GenericRequest.FLAG_HAS_PREFERRED_HANDLER);
const SUPPORTED_RESPONSE_FLAGS = SUPPORTED_ENVELOPE_FLAGS.or(
  GenericResponse.FLAG_HAS_REQUEST_HASH
).or(GenericResponse.FLAG_HAS_HANDLED_BY);

function validateTimestamp(
  timestamp: BN | undefined,
  description: string
): void {
  if (
    !BN.isBN(timestamp) ||
    timestamp!.isNeg() ||
    timestamp!.gt(MAX_SAFE_INTEGER_BN)
  ) {
    throw new Error(`Invalid ${description}.`);
  }
}

function validateRecipientConstraints(
  constraints: RecipientConstraint[] | undefined
): void {
  if (constraints == null) return;
  if (!Array.isArray(constraints))
    throw new Error("Invalid authentication recipient constraints.");

  for (const constraint of constraints) {
    if (!constraint || !RECIPIENT_CONSTRAINT_FIELDS.has(constraint.type)) {
      throw new Error("Unsupported authentication recipient constraint.");
    }

    const identity = constraint.identity;

    // Address conversion does not check the compact encoding's version.
    if (
      !BN.isBN(identity?.version) ||
      identity.version.lt(CompactIAddressObject.FIRST_VERSION) ||
      identity.version.gt(CompactIAddressObject.LAST_VERSION)
    ) {
      throw new Error("Unsupported authentication recipient identity version.");
    }

    // Existing recipient constraints may use FQNs. Resolve through their compact
    // address representation before comparing the canonical identity address.
    decodeDestination(identity.toIAddress(), I_ADDR_VERSION);
  }
}

/** Validate authentication fields without requiring optional correlation or expiry fields. */
export function validateAuthenticationRequestDetails(
  authentication: AuthenticationRequestDetails
): void {
  if (
    !(authentication instanceof AuthenticationRequestDetails) ||
    !BN.isBN(authentication.flags) ||
    !authentication.flags!.eq(authentication.calcFlags(new BN(0))) ||
    !authentication.isValid()
  ) {
    throw new Error("Invalid authentication fields or presence flags.");
  }

  // calcFlags uses truthiness. Validate present values directly so malformed
  // falsy fields cannot disappear from the reconstructed presence flags.
  if (authentication.requestID != null) {
    CompactIAddressObject.validateCompactIdentityAddress(
      authentication.requestID
    );
  }

  if (authentication.expiryTime != null) {
    validateTimestamp(authentication.expiryTime, "authentication expiry");
  }

  validateRecipientConstraints(authentication.recipientConstraints);
}

/** Require a signed authentication deadline that has not reached the current time. */
export function validateAuthenticationExpiry(
  authentication: AuthenticationRequestDetails,
  now = getUnixTime()
): void {
  validateAuthenticationRequestDetails(authentication);

  if (!Number.isSafeInteger(now) || now < 0)
    throw new Error("Invalid admission time.");
  if (!authentication.hasExpiryTime())
    throw new Error("Authentication requires an expiry.");
  if (authentication.expiryTime!.lte(new BN(now)))
    throw new Error("Authentication request has expired.");
}

/** Match alternatives within each constraint type, requiring every requested type. */
export function validateAuthenticationRecipient(
  authentication: AuthenticationRequestDetails,
  recipient: AuthenticationRecipient
): void {
  validateAuthenticationRequestDetails(authentication);
  decodeDestination(recipient.systemID, I_ADDR_VERSION);
  decodeDestination(recipient.identityID, I_ADDR_VERSION);

  for (const [type, field] of RECIPIENT_CONSTRAINT_FIELDS) {
    const value = recipient[field];
    const constraints = (authentication.recipientConstraints || []).filter(
      (constraint) => constraint.type === type
    );

    if (
      constraints.length &&
      (!value ||
        !constraints.some(
          (constraint) => constraint.identity.toIAddress() === value
        ))
    ) {
      throw new Error(
        "Selected response signer does not satisfy the request's recipient constraints."
      );
    }
  }
}

/**
 * Check a signed envelope's version and field consistency. Encrypted details
 * require an explicit opt-in and subsequent authenticated decryption. This does
 * not verify cryptographic signatures or impose a request-specific app scope,
 * correlation identifier, creation time, expiry, or salt requirement.
 */
export function validateSignedGenericEnvelope(
  envelope: GenericEnvelope,
  requireSignature = true,
  allowEncryptedDetails = false
): void {
  let supportedFlags =
    envelope instanceof GenericRequest
      ? SUPPORTED_REQUEST_FLAGS
      : envelope instanceof GenericResponse
      ? SUPPORTED_RESPONSE_FLAGS
      : SUPPORTED_ENVELOPE_FLAGS;

  if (allowEncryptedDetails) {
    supportedFlags = supportedFlags.or(GenericEnvelope.FLAG_DETAILS_ARE_ENCRYPTED);
  }

  if (
    !Array.isArray(envelope.details) ||
    !BN.isBN(envelope.flags) ||
    envelope.flags.isNeg() ||
    !envelope.flags.and(supportedFlags).eq(envelope.flags) ||
    (!envelope.detailsAreEncrypted() &&
      envelope.hasMultiDetails() !== (envelope.details.length > 1)) ||
    !envelope.isValidVersion() ||
    !envelope.isSigned() ||
    !envelope.signature ||
    (requireSignature && !envelope.signature.signatureAsVch?.length)
  ) {
    throw new Error(
      "Expected a supported signed envelope with permitted details encoding."
    );
  }

  if (envelope.detailsAreEncrypted()) {
    const detail = envelope.details[0];

    // Ciphertext always occupies one descriptor. MULTI_DETAILS describes the
    // plaintext framing and is checked against its count after decryption.
    // Check descriptor flags before serialization, which would normalize them.
    if (
      envelope.details.length !== 1 ||
      !(detail instanceof DataDescriptorOrdinalVDXFObject) ||
      !BN.isBN(detail.type) ||
      !detail.type.eq(DATA_DESCRIPTOR_VDXF_ORDINAL) ||
      !(detail.data instanceof DataDescriptor) ||
      !BN.isBN(detail.data.version) ||
      !BN.isBN(detail.data.flags) ||
      !detail.data.isValid() ||
      !detail.data.flags.eq(detail.data.calcFlags()) ||
      !detail.data.hasEncryptedData() ||
      !Buffer.isBuffer(detail.data.objectdata) ||
      !detail.data.objectdata.length
    ) {
      throw new Error("Expected one valid encrypted details descriptor.");
    }
  }

  // Only flagged fields are serialized and signed. Reject fields that consumers
  // could otherwise use for correlation or delivery without signature coverage.
  if (
    envelope.hasRequestID() !== (envelope.requestID != null) ||
    envelope.hasCreatedAt() !== (envelope.createdAt != null) ||
    envelope.hasSalt() !== (envelope.salt != null) ||
    envelope.hasAppOrDelegatorID() !== (envelope.appOrDelegatorID != null)
  ) {
    throw new Error("Inconsistent envelope presence flags.");
  }

  if (
    envelope instanceof GenericRequest &&
    (envelope.hasResponseURIs() !== (envelope.responseURIs != null) ||
      envelope.hasEncryptResponseToAddress() !==
        (envelope.encryptResponseToAddress != null) ||
      envelope.hasPreferredHandler() !== (envelope.preferredHandler != null))
  ) {
    throw new Error("Inconsistent response-delivery flags.");
  }

  if (
    envelope instanceof GenericResponse &&
    (envelope.hasRequestHash() !== (envelope.requestHash != null) ||
      envelope.hasRequestHash() !== (envelope.requestHashType != null) ||
      envelope.hasHandledBy() !== (envelope.handledBy != null))
  ) {
    throw new Error("Inconsistent response presence flags.");
  }

  if (envelope.hasRequestID()) {
    CompactIAddressObject.validateCompactIdentityAddress(envelope.requestID!);
  }

  if (envelope.hasSalt() && !Buffer.isBuffer(envelope.salt)) {
    throw new Error("Invalid envelope salt.");
  }

  if (envelope.hasCreatedAt())
    validateTimestamp(envelope.createdAt, "envelope creation time");
  if (envelope.hasAppOrDelegatorID()) {
    CompactIAddressObject.validateCompactIdentityAddress(
      envelope.appOrDelegatorID!
    );
  }

  CompactIAddressObject.validateCompactIdentityAddress(
    envelope.signature.identityID
  );
  CompactIAddressObject.validateCompactIdentityAddress(
    envelope.signature.systemID
  );

  for (const detail of envelope.details) {
    if (
      !BN.isBN(detail?.version) ||
      detail.version.lt(OrdinalVDXFObject.VERSION_FIRST) ||
      detail.version.gt(OrdinalVDXFObject.VERSION_LAST)
    ) {
      throw new Error("Unsupported envelope detail version.");
    }
  }
}
