import BN from "bn.js";
import {
  AuthenticationRequestDetails,
  AuthenticationRequestOrdinalVDXFObject,
  CompactIAddressObject,
  DataDescriptor,
  DataDescriptorOrdinalVDXFObject,
  GenericRequest,
  I_ADDR_VERSION,
  RecipientConstraint,
  ResponseURI,
  VerifiableSignatureData,
  toBase58Check,
} from "verus-typescript-primitives";
import {
  validateAuthenticationExpiry,
  validateAuthenticationRecipient,
  validateAuthenticationRequestDetails,
  validateSignedGenericEnvelope,
} from "../requests/validation";

const address = (value: number) =>
  toBase58Check(Buffer.alloc(20, value), I_ADDR_VERSION);
const RECIPIENT = {
  identityID: address(1),
  systemID: address(2),
  parentID: address(3),
};
const NOW = 1_800_000_000;

function signedAuthentication(): GenericRequest {
  return new GenericRequest({
    createdAt: new BN(NOW),
    signature: new VerifiableSignatureData({
      version: VerifiableSignatureData.DEFAULT_VERSION,
      identityID: CompactIAddressObject.fromAddress(RECIPIENT.identityID),
      systemID: CompactIAddressObject.fromAddress(RECIPIENT.systemID),
      signatureAsVch: Buffer.from("structural signature fixture"),
    }),
    details: [
      new AuthenticationRequestOrdinalVDXFObject({
        data: new AuthenticationRequestDetails(),
      }),
    ],
  });
}

function signedEncryptedEnvelope(): GenericRequest {
  const request = signedAuthentication();
  request.details = [
    new DataDescriptorOrdinalVDXFObject({
      data: new DataDescriptor({
        flags: DataDescriptor.FLAG_ENCRYPTED_DATA,
        objectdata: Buffer.from("encrypted details fixture"),
        epk: Buffer.alloc(32, 1),
      }),
    }),
  ];
  request.setDetailsAreEncrypted();

  return request;
}

describe("shared authentication validation", () => {
  test("optional app-authorization fields are not required for ordinary authentication", () => {
    const authentication = new AuthenticationRequestDetails();
    expect(() =>
      validateAuthenticationRequestDetails(authentication)
    ).not.toThrow();
    expect(() =>
      validateAuthenticationRecipient(authentication, RECIPIENT)
    ).not.toThrow();
    expect(() => validateAuthenticationExpiry(authentication, NOW)).toThrow(
      /requires an expiry/
    );
  });

  test("matches any identity within a type while requiring every constrained type", () => {
    const authentication = new AuthenticationRequestDetails({
      recipientConstraints: [
        RecipientConstraint.requiredIDFromAddress(address(9)),
        RecipientConstraint.requiredIDFromAddress(RECIPIENT.identityID),
        RecipientConstraint.requiredSystemFromAddress(RECIPIENT.systemID),
        RecipientConstraint.requiredParentFromAddress(RECIPIENT.parentID),
      ],
    });

    expect(() =>
      validateAuthenticationRecipient(authentication, RECIPIENT)
    ).not.toThrow();
    expect(() =>
      validateAuthenticationRecipient(authentication, {
        ...RECIPIENT,
        systemID: address(9),
      })
    ).toThrow(/recipient constraints/);
    expect(() =>
      validateAuthenticationRecipient(authentication, {
        ...RECIPIENT,
        parentID: undefined,
      })
    ).toThrow(/recipient constraints/);
  });

  test("a standalone recipient check rejects unknown constraints and invalid recipients", () => {
    const authentication = new AuthenticationRequestDetails({
      recipientConstraints: [
        {
          type: 99,
          identity: CompactIAddressObject.fromAddress(RECIPIENT.identityID),
        },
      ],
    });

    expect(() =>
      validateAuthenticationRecipient(authentication, RECIPIENT)
    ).toThrow(/Unsupported authentication/);
    expect(() =>
      validateAuthenticationRecipient(new AuthenticationRequestDetails(), {
        ...RECIPIENT,
        identityID: "unresolved@",
      })
    ).toThrow();
  });

  test.each([0, 2, 255])(
    "rejects unsupported compact recipient version %s after binary decoding",
    (version) => {
      const constraint = RecipientConstraint.requiredIDFromAddress(
        RECIPIENT.identityID
      );
      constraint.identity.version = new BN(version);

      const authentication = new AuthenticationRequestDetails({
        recipientConstraints: [constraint],
      });
      const decoded = new AuthenticationRequestDetails();
      const bytes = authentication.toBuffer();

      expect(decoded.fromBuffer(bytes)).toBe(bytes.length);
      expect(decoded.recipientConstraints![0].identity.version.toNumber()).toBe(
        version
      );
      expect(() => validateAuthenticationRequestDetails(decoded)).toThrow(
        /recipient identity version/
      );
      expect(() => validateAuthenticationRecipient(decoded, RECIPIENT)).toThrow(
        /recipient identity version/
      );
    }
  );

  test("preserves supported canonical and FQN recipient constraints after binary decoding", () => {
    const parent = RecipientConstraint.requiredParentFromFQN("example.vrsc@");
    const authentication = new AuthenticationRequestDetails({
      recipientConstraints: [
        RecipientConstraint.requiredIDFromAddress(RECIPIENT.identityID),
        parent,
      ],
    });
    const decoded = new AuthenticationRequestDetails();
    const bytes = authentication.toBuffer();

    expect(decoded.fromBuffer(bytes)).toBe(bytes.length);
    expect(() =>
      validateAuthenticationRecipient(decoded, {
        ...RECIPIENT,
        parentID: parent.identity.toIAddress(),
      })
    ).not.toThrow();
    expect(() => validateAuthenticationRecipient(decoded, RECIPIENT)).toThrow(
      /recipient constraints/
    );
  });

  test("rejects optional authentication fields omitted from the signed flags", () => {
    const authentication = new AuthenticationRequestDetails();
    authentication.expiryTime = new BN(NOW + 1);
    expect(() => validateAuthenticationRequestDetails(authentication)).toThrow(
      /presence flags/
    );
    authentication.setFlags();
    expect(() =>
      validateAuthenticationRequestDetails(authentication)
    ).not.toThrow();

    authentication.requestID = CompactIAddressObject.fromAddress(
      RECIPIENT.identityID
    );
    expect(() => validateAuthenticationRequestDetails(authentication)).toThrow(
      /presence flags/
    );
  });

  test.each([new BN(-1), new BN(8)])(
    "rejects unsupported authentication flags %s",
    (flags) => {
      const authentication = new AuthenticationRequestDetails({ flags });
      expect(() =>
        validateAuthenticationRequestDetails(authentication)
      ).toThrow(/presence flags/);
    }
  );

  test.each([
    AuthenticationRequestDetails.FLAG_HAS_REQUEST_ID,
    AuthenticationRequestDetails.FLAG_HAS_EXPIRY_TIME,
    AuthenticationRequestDetails.FLAG_HAS_RECIPIENT_CONSTRAINTS,
  ])("rejects missing fields declared by flag %s", (flags) => {
    const authentication = new AuthenticationRequestDetails({ flags });
    expect(() => validateAuthenticationRequestDetails(authentication)).toThrow(
      /presence flags/
    );
  });

  test.each(["requestID", "expiryTime", "recipientConstraints"])(
    "rejects malformed falsy %s values even when reconstructed flags are clear",
    (field) => {
      for (const value of [0, false, ""]) {
        const authentication = new AuthenticationRequestDetails();
        (authentication as any)[field] = value;
        expect(authentication.flags!.isZero()).toBe(true);
        expect(() =>
          validateAuthenticationRequestDetails(authentication)
        ).toThrow();
      }
    }
  );

  test("expiry uses the current deadline including equality and safe integer boundaries", () => {
    const authentication = new AuthenticationRequestDetails({
      expiryTime: new BN(NOW),
    });
    expect(() =>
      validateAuthenticationExpiry(authentication, NOW - 1)
    ).not.toThrow();
    expect(() => validateAuthenticationExpiry(authentication, NOW)).toThrow(
      /expired/
    );
    expect(() => validateAuthenticationExpiry(authentication, NOW + 1)).toThrow(
      /expired/
    );
    expect(() => validateAuthenticationExpiry(authentication, NaN)).toThrow(
      /admission time/
    );
    authentication.expiryTime = new BN(1).shln(53);
    expect(() => validateAuthenticationExpiry(authentication, NOW)).toThrow(
      /expiry/
    );
  });

  test("accepts the largest safe expiry and rejects the immediately larger value", () => {
    const authentication = new AuthenticationRequestDetails({
      expiryTime: new BN(Number.MAX_SAFE_INTEGER),
    });
    expect(() =>
      validateAuthenticationExpiry(authentication, Number.MAX_SAFE_INTEGER - 1)
    ).not.toThrow();
    authentication.expiryTime = authentication.expiryTime!.addn(1);
    expect(() => validateAuthenticationRequestDetails(authentication)).toThrow(
      /expiry/
    );
  });
});

describe("shared signed-envelope validation", () => {
  test("ordinary signed authentication does not acquire app scope or salt requirements", () => {
    const request = signedAuthentication();
    expect(request.hasAppOrDelegatorID()).toBe(false);
    expect(request.hasSalt()).toBe(false);
    expect(() => validateSignedGenericEnvelope(request)).not.toThrow();
  });

  test("rejects unsigned delivery fields for an ordinary signed request", () => {
    const request = signedAuthentication();
    request.responseURIs = [
      ResponseURI.fromUriString("https://example.com/response"),
    ];
    expect(() => validateSignedGenericEnvelope(request)).toThrow(
      /response-delivery flags/
    );
    request.setFlags();
    expect(() => validateSignedGenericEnvelope(request)).not.toThrow();
  });

  test("signing templates must opt out of signature-byte presence explicitly", () => {
    const request = signedAuthentication();
    request.signature!.signatureAsVch = Buffer.alloc(0);
    expect(() => validateSignedGenericEnvelope(request)).toThrow(
      /signed envelope/
    );
    expect(() => validateSignedGenericEnvelope(request, false)).not.toThrow();
  });

  test("encrypted details require opt-in without relaxing the signature requirement", () => {
    const request = signedEncryptedEnvelope();
    expect(() => validateSignedGenericEnvelope(request)).toThrow();
    expect(() =>
      validateSignedGenericEnvelope(request, true, true)
    ).not.toThrow();

    request.signature!.signatureAsVch = Buffer.alloc(0);
    expect(() => validateSignedGenericEnvelope(request, true, true)).toThrow();
    expect(() =>
      validateSignedGenericEnvelope(request, false, true)
    ).not.toThrow();
  });

  test("encrypted multi-details framing allows one ciphertext descriptor without relaxing plaintext counts", () => {
    const request = signedEncryptedEnvelope();
    request.flags = request.flags.or(GenericRequest.FLAG_MULTI_DETAILS);

    expect(request.details).toHaveLength(1);
    expect(() =>
      validateSignedGenericEnvelope(request, true, true)
    ).not.toThrow();

    request.flags = request.flags.xor(
      GenericRequest.FLAG_DETAILS_ARE_ENCRYPTED
    );
    expect(() => validateSignedGenericEnvelope(request, true, true)).toThrow();
  });

  test("encrypted details require exactly one descriptor with its registered ordinal", () => {
    const request = signedEncryptedEnvelope();
    const descriptor = request.details[0];
    const authentication = signedAuthentication().details[0];

    for (const details of [[], [descriptor, descriptor], [authentication]]) {
      request.details = details;
      expect(() =>
        validateSignedGenericEnvelope(request, true, true)
      ).toThrow();
    }

    request.details = [descriptor];
    descriptor.type = authentication.type;
    expect(() => validateSignedGenericEnvelope(request, true, true)).toThrow();
  });

  test.each([
    {
      description: "unknown descriptor flags",
      mutate: (descriptor: DataDescriptor) => {
        descriptor.flags = descriptor.flags.or(
          DataDescriptor.FLAG_MASK.addn(1)
        );
      },
    },
    {
      description: "unflagged encryption public key",
      mutate: (descriptor: DataDescriptor) => {
        descriptor.flags = descriptor.flags.xor(
          DataDescriptor.FLAG_ENCRYPTION_PUBLIC_KEY_PRESENT
        );
      },
    },
    {
      description: "unsupported descriptor version",
      mutate: (descriptor: DataDescriptor) => {
        descriptor.version = DataDescriptor.LAST_VERSION.addn(1);
      },
    },
    {
      description: "descriptor without encrypted data",
      mutate: (descriptor: DataDescriptor) => {
        descriptor.flags = descriptor.flags.xor(
          DataDescriptor.FLAG_ENCRYPTED_DATA
        );
      },
    },
  ])(
    "rejects $description before serialization can normalize it",
    ({ mutate }) => {
      const request = signedEncryptedEnvelope();
      const descriptor = (request.details[0] as DataDescriptorOrdinalVDXFObject)
        .data;
      mutate(descriptor);
      const originalFlags = descriptor.flags.clone();
      const originalVersion = descriptor.version.clone();

      expect(() =>
        validateSignedGenericEnvelope(request, true, true)
      ).toThrow();
      expect(descriptor.flags.eq(originalFlags)).toBe(true);
      expect(descriptor.version.eq(originalVersion)).toBe(true);
    }
  );
});
