"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const verus_typescript_primitives_1 = require("verus-typescript-primitives");
const verusd_rpc_ts_client_1 = require("verusd-rpc-ts-client");
const utxo_lib_1 = require("@bitgo/utxo-lib");
const vdxf_1 = require("verus-typescript-primitives/dist/constants/vdxf");
const bignumber_js_1 = __importDefault(require("bignumber.js"));
const bn_js_1 = __importDefault(require("bn.js"));
const registration_1 = require("./identity/registration");
const registrationSigning_1 = require("./identity/registrationSigning");
const registrationFundingVerification_1 = require("./identity/registrationFundingVerification");
const registrationPolicy_1 = require("./identity/registrationPolicy");
const updateFundingVerification_1 = require("./identity/updateFundingVerification");
const fundingPrimitives_1 = require("./identity/fundingPrimitives");
const fundingVerification_1 = require("./identity/fundingVerification");
const updateDataVerification_1 = require("./identity/updateDataVerification");
const localUpdateData_1 = require("./identity/localUpdateData");
const localIdentityUpdate_1 = require("./identity/localIdentityUpdate");
const fullIdentityUpdateValidation_1 = require("./identity/fullIdentityUpdateValidation");
const updateLimits_1 = require("./identity/updateLimits");
const requestSnapshot_1 = require("./utils/requestSnapshot");
const identityValidation_1 = require("./identity/identityValidation");
const handshake_1 = require("./authorization/handshake");
const authority_1 = require("./authorization/authority");
const identityAuthority_1 = require("./identity/identityAuthority");
const signatures_1 = require("./identity/signatures");
const grants_1 = require("./authorization/grants");
const profile_1 = require("./authorization/profile");
const validation_1 = require("./requests/validation");
const time_1 = require("./constants/time");
const { createUnfundedIdentityUpdate, validateFundedCurrencyTransfer, completeFundedIdentityUpdate } = utxo_lib_1.smarttxs;
const ID_SIG_VERSION = 2;
const IDENTITY_SIGNATURE_TIME_TOLERANCE_SECONDS = time_1.SECONDS_PER_HOUR;
const RESERVE_TRANSFER_DEFAULT_PER_STEP_FEE = new bn_js_1.default(10000, 10);
const RESERVE_TRANSFER_DESTINATION_BYTE_DIVISOR = 128;
function getUtxos(result) {
    return Array.isArray(result) ? result : result.utxos;
}
class VerusIdInterface {
    constructor(chain, baseURL, config, rpcRequestOverride, APIAuth) {
        // Keep the legacy chainIAddr arguments at the public API boundary.
        this.createGenericRequest = (params, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) => this.createGenericEnvelope(verus_typescript_primitives_1.GenericRequest, params, primaryAddrWif, getIdentityResult, currentHeight);
        this.createGenericResponse = (params, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) => this.createGenericEnvelope(verus_typescript_primitives_1.GenericResponse, params, primaryAddrWif, getIdentityResult, currentHeight);
        this.signGenericRequest = (this.signGenericEnvelope);
        this.signGenericResponse = (this.signGenericEnvelope);
        /**
         * Verify request admission; authorization bootstrap also checks current app
         * policy and throws UnsupportedDelegatorProfileError for a reserved profile.
         */
        this.verifyGenericRequest = (envelope_1, getIdentityResult_1, chainIAddr_1, sigBlockTime_1, ...args_1) => __awaiter(this, [envelope_1, getIdentityResult_1, chainIAddr_1, sigBlockTime_1, ...args_1], void 0, function* (envelope, getIdentityResult, chainIAddr, sigBlockTime, acceptUnsigned = false) {
            if (!VerusIdInterface.validateUnsignedGenericRequest(envelope))
                return false;
            if ((0, handshake_1.hasAppAuthorizationRequest)(envelope)) {
                const request = (0, requestSnapshot_1.snapshotRequestValue)(envelope);
                const rpc = this.interface;
                const configuredChain = rpc.chain;
                try {
                    const context = yield this.loadAuthorizationSignatureContext(request, sigBlockTime);
                    if (!context || (chainIAddr != null && chainIAddr !== context.delegate.systemID))
                        return false;
                    // A future profile must not be bypassed by an older authorization flow.
                    // Inspect effective current content, not the request's signing-height CMM.
                    yield (0, profile_1.assertAppDelegatorProfileSupportedV1)(context.source, {
                        systemID: context.delegate.systemID,
                        identityID: request.appOrDelegatorID.toIAddress(),
                    });
                    (0, handshake_1.validateAppAuthorizationRequest)(request);
                    return this.interface === rpc && rpc.chain === configuredChain &&
                        envelope.toBuffer().equals(request.toBuffer());
                }
                catch (error) {
                    if (error instanceof verus_typescript_primitives_1.UnsupportedDelegatorProfileError)
                        throw error;
                    return false;
                }
            }
            if (acceptUnsigned && !envelope.isSigned()) {
                return true;
            }
            return this.verifyGenericEnvelope(envelope, getIdentityResult, chainIAddr, sigBlockTime);
        });
        this.verifyGenericResponse = (this.verifyGenericEnvelope);
        this.interface = new verusd_rpc_ts_client_1.VerusdRpcInterface(chain, baseURL, config, rpcRequestOverride, APIAuth);
    }
    getCurrentHeight() {
        return __awaiter(this, void 0, void 0, function* () {
            const _infores = yield this.interface.getInfo();
            if (_infores.error)
                throw new Error(_infores.error.message);
            const info = _infores.result;
            return info.longestchain;
        });
    }
    /** Resolve and quote a modern commit/reveal registration without broadcasting. */
    resolveIdentityRegistration(request) {
        return (0, registration_1.resolveIdentityRegistration)(this.interface, request);
    }
    /** Builds the commitment transaction and returns private reservation recovery data. */
    createNameReservationTransaction(request) {
        return (0, registration_1.createNameReservationTransaction)(this.interface, request);
    }
    /** Spends an explicitly identified, confirmed commitment to create an identity. */
    createIdentityRegistrationTransaction(request) {
        return (0, registration_1.createIdentityRegistrationTransaction)(this.interface, request);
    }
    signIdentityRegistrationTransaction(request) {
        const prepared = request.transaction;
        (0, registration_1.validatePreparedIdentityRegistrationTransaction)(prepared, request.txHex);
        for (const partial of request.partialTransactions || [])
            (0, registration_1.validatePreparedIdentityRegistrationTransaction)(prepared, partial);
        return (0, registrationSigning_1.signIdentityRegistrationTransaction)({
            txHex: request.txHex == null ? prepared.txHex : request.txHex,
            prevouts: prepared.prevouts,
            identityAuthorities: prepared.identityAuthorities,
            keys: request.keys,
            partialTransactions: request.partialTransactions
        });
    }
    mergeIdentityRegistrationTransactions(request) {
        return this.signIdentityRegistrationTransaction(request);
    }
    inspectIdentityRegistrationSignatures(request) {
        return (0, registrationSigning_1.inspectIdentityRegistrationSignatures)(request);
    }
    /** Verify the approved economic intent and every supplied signature; inspect signingStatus before broadcast. */
    validateIdentityRegistrationTransaction(prepared, candidateHex = prepared.txHex, expectedChangeAddress = prepared.changeAddress) {
        (0, registration_1.validatePreparedIdentityRegistrationTransaction)(prepared, candidateHex, expectedChangeAddress);
        return Object.assign({ valid: true }, (0, registrationSigning_1.inspectIdentityRegistrationSignatures)({
            txHex: candidateHex,
            prevouts: prepared.prevouts,
            identityAuthorities: prepared.identityAuthorities
        }));
    }
    /** Independently account for raw input/output currencies against retained approval. No RPC or signature cache. */
    verifyIdentityRegistrationFunding(prepared, candidateHex = prepared.txHex, expectedChangeAddress = prepared.changeAddress) {
        return (0, registrationFundingVerification_1.verifyIdentityRegistrationFunding)(prepared, candidateHex, expectedChangeAddress);
    }
    /** Validate funding, approved intent, and complete signatures on every send, including retries. */
    sendIdentityRegistrationTransaction(prepared_1, signedHex_1) {
        return __awaiter(this, arguments, void 0, function* (prepared, signedHex, expectedChangeAddress = prepared.changeAddress) {
            (0, registration_1.validatePreparedIdentityRegistrationTransaction)(prepared, signedHex, expectedChangeAddress);
            const checked = (0, registrationSigning_1.inspectIdentityRegistrationSignatures)({
                txHex: signedHex,
                prevouts: prepared.prevouts,
                identityAuthorities: prepared.identityAuthorities
            });
            if (checked.signingStatus !== "complete") {
                throw new registrationPolicy_1.RegistrationError("INCOMPLETE_SIGNATURES", "Registration must be fully signed before broadcast.");
            }
            // Once submission starts, an RPC error or lost response cannot prove that
            // the transaction was not accepted. Retain the ID of the exact bytes sent.
            const txid = (0, fundingPrimitives_1.transaction)(signedHex).getId();
            let response;
            try {
                response = yield this.interface.sendRawTransaction(signedHex);
            }
            catch (cause) {
                throw new registrationPolicy_1.RegistrationError("BROADCAST_UNKNOWN", `Registration broadcast outcome is unknown; transaction ${txid} may have been submitted. Check its status before retrying.`, { txid, cause });
            }
            if (response == null || response.error != null || response.result !== txid) {
                throw new registrationPolicy_1.RegistrationError("BROADCAST_UNKNOWN", `Registration broadcast outcome is unknown; transaction ${txid} may have been submitted. Check its status before retrying.`, { txid, response });
            }
            return response;
        });
    }
    getChainId() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.interface.chain === verus_typescript_primitives_1.DEFAULT_VERUS_CHAINNAME || this.interface.chain === verus_typescript_primitives_1.DEFAULT_VERUS_CHAINID) {
                return verus_typescript_primitives_1.DEFAULT_VERUS_CHAINID;
            }
            else {
                // An explicitly configured i-address must not be replaced by an RPC response.
                try {
                    if (verus_typescript_primitives_1.IdentityID.fromAddress(this.interface.chain).toAddress() === this.interface.chain) {
                        return this.interface.chain;
                    }
                }
                catch (_) {
                    // Chain names still require RPC resolution.
                }
                const _currres = yield this.interface.getCurrency(this.interface.chain);
                if (_currres.error)
                    throw new Error(_currres.error.message);
                return _currres.result.currencyid;
            }
        });
    }
    signMessage(iAddrOrIdentity, message, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.signHashOrMessage(iAddrOrIdentity, message, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr);
        });
    }
    signHash(iAddrOrIdentity, hash, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.signHashOrMessage(iAddrOrIdentity, hash, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr);
        });
    }
    signHashOrMessage(iAddrOrIdentity, hashOrMessage, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            let identity;
            let height;
            let chainId;
            if (getIdentityResult != null) {
                identity = getIdentityResult;
            }
            else {
                const _idres = yield this.interface.getIdentity(iAddrOrIdentity);
                if (_idres.error)
                    throw new Error(_idres.error.message);
                identity = _idres.result;
            }
            if (identity.status !== "active") {
                throw new Error("Cannot create a valid signature for a revoked identity");
            }
            if (currentHeight != null) {
                height = currentHeight;
            }
            else {
                height = yield this.getCurrentHeight();
            }
            if (chainIAddr != null) {
                chainId = chainIAddr;
            }
            else {
                chainId = yield this.getChainId();
            }
            const keyPair = utxo_lib_1.ECPair.fromWIF(primaryAddrWif, utxo_lib_1.networks.verus);
            const sig = new utxo_lib_1.IdentitySignature(utxo_lib_1.networks.verus, ID_SIG_VERSION, verus_typescript_primitives_1.EHashTypes.HASH_SHA256, height, null, chainId, identity.identity.identityaddress);
            if (Buffer.isBuffer(hashOrMessage)) {
                sig.signHashOffline(hashOrMessage, keyPair);
            }
            else {
                sig.signMessageOffline(hashOrMessage, keyPair);
            }
            return sig.toBuffer().toString("base64");
        });
    }
    verifyMessage(iAddrOrIdentity, base64Sig, message, getIdentityResult, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.verifyHashOrMessage(iAddrOrIdentity, yield this.readIdentitySignature(iAddrOrIdentity, base64Sig, chainIAddr), message, getIdentityResult);
        });
    }
    verifyHash(iAddrOrIdentity, base64Sig, hash, getIdentityResult, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.verifyHashOrMessage(iAddrOrIdentity, yield this.readIdentitySignature(iAddrOrIdentity, base64Sig, chainIAddr), hash, getIdentityResult);
        });
    }
    /** Resolve names once and parse the same compact signature for every verifier. */
    readIdentitySignature(iAddrOrIdentity, base64Sig, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            let identityAddress = iAddrOrIdentity;
            try {
                utxo_lib_1.address.fromBase58Check(identityAddress);
            }
            catch (_a) {
                const response = yield this.interface.getIdentity(iAddrOrIdentity);
                if (response.error)
                    throw new Error(response.error.message);
                identityAddress = response.result.identity.identityaddress;
            }
            const chainID = chainIAddr !== null && chainIAddr !== void 0 ? chainIAddr : yield this.getChainId();
            const signature = new utxo_lib_1.IdentitySignature(utxo_lib_1.networks.verus);
            signature.fromBuffer(Buffer.from(base64Sig, "base64"), 0, chainID, identityAddress);
            return signature;
        });
    }
    verifyHashOrMessage(iAddrOrIdentity, sig, hashOrMessage, getIdentityResult) {
        return __awaiter(this, void 0, void 0, function* () {
            let identityAtHeight;
            if (getIdentityResult != null) {
                identityAtHeight = getIdentityResult;
            }
            else {
                const _idresatheight = yield this.interface.getIdentity(iAddrOrIdentity, sig.blockHeight);
                if (_idresatheight.error)
                    throw new Error(_idresatheight.error.message);
                identityAtHeight = _idresatheight.result;
            }
            if (identityAtHeight.status !== "active") {
                return false;
            }
            try {
                const minimumSignatures = identityAtHeight.identity.minimumsignatures;
                const primaryKeys = (0, identityAuthority_1.getIdentityPrimaryKeyIDs)(identityAtHeight.identity.primaryaddresses, minimumSignatures);
                const digest = Buffer.isBuffer(hashOrMessage) ? hashOrMessage : sig.hashMessage(hashOrMessage);
                const signers = (0, signatures_1.recoverIdentitySignatureSigners)(digest, sig.signatures);
                // Preserve Core's ordinary key-ID counting, including distinct compressed
                // and uncompressed addresses. Repeated signatures still count only once.
                const signedKeys = new Set();
                for (const signer of signers) {
                    for (const keyID of signer.keyIDs) {
                        if (primaryKeys.has(keyID))
                            signedKeys.add(keyID);
                    }
                }
                return signedKeys.size >= minimumSignatures;
            }
            catch (_a) {
                return false;
            }
        });
    }
    getSignatureInfo(iAddrOrIdentity, base64Sig, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            const sig = yield this.readIdentitySignature(iAddrOrIdentity, base64Sig, chainIAddr);
            return {
                version: sig.version,
                hashtype: sig.hashType,
                height: sig.blockHeight,
            };
        });
    }
    /**
     * @deprecated Legacy VerusID login, use GenericRequest class with login objects in details array
     */
    signLoginConsentRequest(request, primaryAddrWif, getIdentityResult, currentHeight) {
        return __awaiter(this, void 0, void 0, function* () {
            let height = currentHeight;
            if (height == null) {
                height = yield this.getCurrentHeight();
            }
            const sig = yield this.signHash(request.signing_id, request.getChallengeHash(height), primaryAddrWif, getIdentityResult, height, request.system_id);
            request.signature = new verus_typescript_primitives_1.VerusIDSignature({ signature: sig }, verus_typescript_primitives_1.IDENTITY_AUTH_SIG_VDXF_KEY);
            return request;
        });
    }
    /**
     * @deprecated Legacy VerusID login, use GenericRequest class with login objects in details array
     */
    createLoginConsentRequest(signingId, challenge, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            let chainId;
            if (chainIAddr != null)
                chainId = chainIAddr;
            else
                chainId = yield this.getChainId();
            const req = new verus_typescript_primitives_1.LoginConsentRequest({
                system_id: chainId,
                signing_id: signingId,
                challenge,
            });
            if (primaryAddrWif) {
                return this.signLoginConsentRequest(req, primaryAddrWif, getIdentityResult, currentHeight);
            }
            else
                return req;
        });
    }
    /**
     * @deprecated Legacy VerusID login, use GenericRequest class with login objects in details array
     */
    verifyLoginConsentRequest(request, getIdentityResult, chainIAddr, sigBlockTime) {
        return __awaiter(this, void 0, void 0, function* () {
            const signature = yield this.readIdentitySignature(request.signing_id, request.signature.signature, chainIAddr);
            if (!(yield this.verifySignatureCreationTime(request.challenge.created_at, signature.blockHeight, sigBlockTime)))
                return false;
            return this.verifyHashOrMessage(request.signing_id, signature, request.getChallengeHash(signature.blockHeight), getIdentityResult);
        });
    }
    /**
     * @deprecated Legacy VerusID login, use GenericRequest class with login objects in details array
     */
    signLoginResponse(response, primaryAddrWif, getIdentityResult, currentHeight) {
        return __awaiter(this, void 0, void 0, function* () {
            let height = currentHeight;
            if (height == null) {
                height = yield this.getCurrentHeight();
            }
            const sig = yield this.signHash(response.signing_id, response.getDecisionHash(height), primaryAddrWif, getIdentityResult, height, response.system_id);
            response.signature = new verus_typescript_primitives_1.VerusIDSignature({ signature: sig }, verus_typescript_primitives_1.LOGIN_CONSENT_RESPONSE_SIG_VDXF_KEY);
            return response;
        });
    }
    /**
     * @deprecated Legacy VerusID login, use GenericRequest class with login objects in details array
     */
    createLoginResponse(signingId, decision, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            let chainId;
            if (chainIAddr != null)
                chainId = chainIAddr;
            else
                chainId = yield this.getChainId();
            const req = decision instanceof verus_typescript_primitives_1.LoginConsentProvisioningDecision
                ? new verus_typescript_primitives_1.LoginConsentProvisioningResponse({
                    system_id: chainId,
                    signing_id: signingId,
                    decision: decision,
                })
                : new verus_typescript_primitives_1.LoginConsentResponse({
                    system_id: chainId,
                    signing_id: signingId,
                    decision: decision,
                });
            if (primaryAddrWif) {
                return this.signLoginConsentResponse(req, primaryAddrWif, getIdentityResult, currentHeight);
            }
            else
                return req;
        });
    }
    /**
     * @deprecated Legacy VerusID login, use GenericRequest class with login objects in details array
     */
    verifyResponse(response, getIdentityResult, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            const sigInfo = yield this.getSignatureInfo(response.signing_id, response.signature.signature, chainIAddr);
            return this.verifyHash(response.signing_id, response.signature.signature, response.getDecisionHash(sigInfo.height), getIdentityResult, chainIAddr);
        });
    }
    /**
     * @deprecated SignedSessionObject construction is disabled in primitives.
     * No compatible replacement HTTP session API is available.
     */
    verifySignedSessionObject(object, getIdentityResult, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            const sigInfo = yield this.getSignatureInfo(object.signing_id, object.signature.signature, chainIAddr);
            return this.verifyHash(object.signing_id, object.signature.signature, object.getDataHash(sigInfo.height), getIdentityResult, chainIAddr);
        });
    }
    /**
     * @deprecated SignedSessionObject construction is disabled in primitives.
     * No compatible replacement HTTP session API is available.
     */
    signSessionObject(object, primaryAddrWif, getIdentityResult, currentHeight) {
        return __awaiter(this, void 0, void 0, function* () {
            let height = currentHeight;
            if (height == null) {
                height = yield this.getCurrentHeight();
            }
            const sig = yield this.signHash(object.signing_id, object.getDataHash(height), primaryAddrWif, getIdentityResult, height, object.system_id);
            object.signature = new verus_typescript_primitives_1.VerusIDSignature({ signature: sig }, verus_typescript_primitives_1.LOGIN_CONSENT_RESPONSE_SIG_VDXF_KEY);
            return object;
        });
    }
    /**
     * @deprecated Disabled because SignedSessionObject construction is unsupported in primitives.
     * Always rejects; no compatible replacement HTTP session API is available.
     */
    createSignedSessionObject(signingId, data, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error("SignedSessionObject is deprecated and disabled; no compatible replacement HTTP session API is available.");
        });
    }
    /**
     * @deprecated Legacy VerusID login, use GenericRequest class with login objects in details array
     */
    signLoginConsentResponse(response, primaryAddrWif, getIdentityResult, currentHeight) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.signLoginResponse(response, primaryAddrWif, getIdentityResult, currentHeight);
        });
    }
    /**
     * @deprecated Legacy VerusID login, use GenericRequest class with login objects in details array
     */
    createLoginConsentResponse(signingId, decision, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.createLoginResponse(signingId, decision, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr);
        });
    }
    /**
     * @deprecated Legacy VerusID login, use GenericRequest class with login objects in details array
     */
    verifyLoginConsentResponse(response, getIdentityResult, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.verifyResponse(response, getIdentityResult, chainIAddr);
        });
    }
    /**
     * @deprecated Legacy VerusPay implementation, use GenericRequest class with invoice objects in details array
     */
    createVerusPayInvoice(details, signingIdIAddr, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            let chainId;
            if (chainIAddr != null)
                chainId = chainIAddr;
            else
                chainId = yield this.getChainId();
            const inv = new verus_typescript_primitives_1.VerusPayInvoice({
                details: details,
                version: details.isTagged() ? verus_typescript_primitives_1.VERUSPAY_VERSION_4 : verus_typescript_primitives_1.VERUSPAY_VERSION_3
            });
            if (signingIdIAddr && primaryAddrWif) {
                return this.signVerusPayInvoice(inv, signingIdIAddr, chainId, primaryAddrWif, getIdentityResult, currentHeight);
            }
            else
                return inv;
        });
    }
    /**
     * @deprecated Legacy VerusPay implementation, use GenericRequest class with invoice objects in details array
     */
    signVerusPayInvoice(invoice, signingIdIAddr, systemIdIAddr, primaryAddrWif, getIdentityResult, currentHeight) {
        return __awaiter(this, void 0, void 0, function* () {
            let height = currentHeight;
            if (height == null) {
                height = yield this.getCurrentHeight();
            }
            invoice.setSigned();
            invoice.signing_id = signingIdIAddr;
            invoice.system_id = systemIdIAddr;
            const sig = yield this.signHash(signingIdIAddr, invoice.getDetailsHash(height), primaryAddrWif, getIdentityResult, height, systemIdIAddr);
            invoice.signature = new verus_typescript_primitives_1.VerusIDSignature({ signature: sig }, verus_typescript_primitives_1.IDENTITY_AUTH_SIG_VDXF_KEY, false);
            return invoice;
        });
    }
    /**
     * @deprecated Legacy VerusPay implementation, use GenericRequest class with invoice objects in details array
     */
    verifySignedVerusPayInvoice(invoice, getIdentityResult, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            const sigInfo = yield this.getSignatureInfo(invoice.signing_id, invoice.signature.signature, chainIAddr);
            return this.verifyHash(invoice.signing_id, invoice.signature.signature, invoice.getDetailsHash(sigInfo.height, sigInfo.version), getIdentityResult, chainIAddr);
        });
    }
    signVerusIdProvisioningResponse(response, primaryAddrWif, getIdentityResult, currentHeight) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.signLoginResponse(response, primaryAddrWif, getIdentityResult, currentHeight);
        });
    }
    createVerusIdProvisioningResponse(signingId, decision, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.createLoginResponse(signingId, decision, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr);
        });
    }
    verifyVerusIdProvisioningResponse(response, getIdentityResult, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.verifyResponse(response, getIdentityResult, chainIAddr);
        });
    }
    static signHashWithAddress(hash, wif) {
        const keyPair = utxo_lib_1.ECPair.fromWIF(wif, utxo_lib_1.networks.verus);
        const sig = new utxo_lib_1.IdentitySignature(utxo_lib_1.networks.verus);
        return sig.signHashOffline(hash, keyPair).toString("base64");
    }
    static signVerusIdProvisioningRequest(request, addrWif) {
        return __awaiter(this, void 0, void 0, function* () {
            const sig = VerusIdInterface.signHashWithAddress(request.getChallengeHash(), addrWif);
            request.signature = new verus_typescript_primitives_1.VerusIDSignature({ signature: sig }, verus_typescript_primitives_1.IDENTITY_AUTH_SIG_VDXF_KEY);
            return request;
        });
    }
    static createVerusIdProvisioningRequest(signingAddress, challenge, addrWif) {
        return __awaiter(this, void 0, void 0, function* () {
            const req = new verus_typescript_primitives_1.LoginConsentProvisioningRequest({
                signing_address: signingAddress,
                challenge,
            });
            if (addrWif) {
                return VerusIdInterface.signVerusIdProvisioningRequest(req, addrWif);
            }
            else
                return req;
        });
    }
    static verifyVerusIdProvisioningRequest(request, address) {
        return __awaiter(this, void 0, void 0, function* () {
            const sig = new utxo_lib_1.IdentitySignature(utxo_lib_1.networks.verus, ID_SIG_VERSION, verus_typescript_primitives_1.EHashTypes.HASH_SHA256, null, [Buffer.from(request.signature.signature, "base64")]);
            return sig.verifyHashOffline(request.getChallengeHash(), address)[0];
        });
    }
    static getIdentityFromIdTx(transaction, idAddr, parseVdxfObjects, strict = false) {
        let index = -1;
        let id = null;
        for (let i = 0; i < transaction.outs.length; i++) {
            const decomp = (0, verus_typescript_primitives_1.decompile)(transaction.outs[i].script);
            if (decomp.length !== 4 || decomp[1] !== verus_typescript_primitives_1.OPS.OP_CHECKCRYPTOCONDITION || decomp[3] !== verus_typescript_primitives_1.OPS.OP_DROP) {
                if (strict)
                    throw new Error("Unknown script format output found in transaction");
                continue;
            }
            const outMaster = verus_typescript_primitives_1.OptCCParams.fromChunk(decomp[0]);
            const outParams = verus_typescript_primitives_1.OptCCParams.fromChunk(decomp[2]);
            if (!outMaster.evalCode.eq(new bn_js_1.default(verus_typescript_primitives_1.EVALS.EVAL_NONE))) {
                if (strict)
                    throw new Error("Unsupported master eval code " + outMaster.evalCode.toNumber() + " found in transaction output");
                continue;
            }
            // Data uploads also contain notary evidence outputs. This helper extracts
            // the identity; update builders verify the upload evidence separately.
            if (!outParams.evalCode.eq(new bn_js_1.default(verus_typescript_primitives_1.EVALS.EVAL_IDENTITY_PRIMARY))) {
                if (strict && !outParams.evalCode.eq(new bn_js_1.default(verus_typescript_primitives_1.EVALS.EVAL_NOTARY_EVIDENCE))) {
                    throw new Error("Unsupported params eval code " + outParams.evalCode.toNumber() + " found in transaction output");
                }
                continue;
            }
            if (strict && id != null)
                throw new Error("Multiple identity outputs found in transaction");
            id = new verus_typescript_primitives_1.Identity();
            id.fromBuffer(outParams.getParamObject(), 0, parseVdxfObjects);
            if (id.getIdentityAddress() === idAddr) {
                index = i;
                if (!strict)
                    break;
            }
            else if (strict) {
                throw new Error("Identity output does not match identity address");
            }
        }
        if (index < 0) {
            throw new Error("Identity output not found");
        }
        else {
            return { vout: index, identity: id };
        }
    }
    static addNegativeDelta(deltas, key, value) {
        if (deltas.has(key))
            deltas.set(key, deltas.get(key).minus(value));
        else
            deltas.set(key, value.multipliedBy((0, bignumber_js_1.default)(-1)));
    }
    static addValidationFeesToDeltas(validation, deltas) {
        for (const key in validation.fees) {
            VerusIdInterface.addNegativeDelta(deltas, key, (0, bignumber_js_1.default)(validation.fees[key]));
        }
    }
    static addValidationSentToDeltas(validation, deltas) {
        for (const key in validation.sent) {
            VerusIdInterface.addNegativeDelta(deltas, key, (0, bignumber_js_1.default)(validation.sent[key]));
        }
    }
    static validateNoUnexpectedCurrencySent(validation) {
        for (const key in validation.sent) {
            if ((0, bignumber_js_1.default)(validation.sent[key]).isGreaterThan((0, bignumber_js_1.default)(0))) {
                throw new Error("Cannot send currency and update ID.");
            }
        }
    }
    static getSatoshis(value, label) {
        const satoshis = (0, bignumber_js_1.default)(value);
        if (!satoshis.isFinite() || satoshis.isNegative() || !satoshis.isInteger()) {
            throw new Error(label + " must be a non-negative integer satoshi value.");
        }
        return new bn_js_1.default(satoshis.toFixed(0), 10);
    }
    static getCurrencyValueMap(output) {
        const valueMap = new Map();
        for (const currency of Object.keys(output.currencies || {})) {
            valueMap.set(currency, VerusIdInterface.getSatoshis(output.currencies[currency], "Currency transfer output currency value for " + currency));
        }
        if (valueMap.size === 0)
            throw new Error("Currency transfer output must include at least one currency value.");
        return valueMap;
    }
    static isReserveTransferOutput(output) {
        return output.convertto != null ||
            output.exportto != null ||
            output.via != null ||
            output.preconvert === true ||
            output.burn === true ||
            output.burnweight === true ||
            output.mintnew === true ||
            output.importtosource === true;
    }
    static getTxDestination(destination) {
        const destinationType = destination.typeNoFlags();
        if (destinationType.eq(verus_typescript_primitives_1.DEST_PKH)) {
            return new verus_typescript_primitives_1.TxDestination(new verus_typescript_primitives_1.KeyID(destination.destinationBytes));
        }
        else if (destinationType.eq(verus_typescript_primitives_1.DEST_ID)) {
            return new verus_typescript_primitives_1.TxDestination(new verus_typescript_primitives_1.IdentityID(destination.destinationBytes));
        }
        else
            throw new Error("Unsupported transfer destination type.");
    }
    static getTokenOutputVersion(valueMap) {
        const version = new bn_js_1.default(1, 10);
        return valueMap.size > 1 ? version.xor(verus_typescript_primitives_1.TOKEN_OUTPUT_VERSION_MULTIVALUE) : version;
    }
    static createSmartTransactionOutputScript(master, params) {
        return new verus_typescript_primitives_1.SmartTransactionScript(master, params).toBuffer();
    }
    static usesRefundDestination(output) {
        return output.exportto != null ||
            output.preconvert === true ||
            (output.convertto != null &&
                output.mintnew !== true &&
                output.burn !== true &&
                output.burnweight !== true);
    }
    static getReserveTransferDestination(output) {
        const destination = (0, requestSnapshot_1.snapshotRequestValue)(output.address);
        if (output.refundto != null && VerusIdInterface.usesRefundDestination(output)) {
            destination.type = destination.type.or(verus_typescript_primitives_1.FLAG_DEST_AUX);
            destination.auxDests = [
                ...(destination.auxDests || []),
                (0, requestSnapshot_1.snapshotRequestValue)(output.refundto)
            ];
        }
        return destination;
    }
    static validateCurrencyTransferOutput(output, chainId, isReserveTransfer) {
        if (!isReserveTransfer) {
            if (output.feecurrency != null)
                throw new Error("Fee currency is only valid for reserve transfer outputs.");
            if (output.feesatoshis != null)
                throw new Error("Reserve transfer fee is only valid for reserve transfer outputs.");
            if (output.refundto != null)
                throw new Error("Refund destination is only valid for reserve transfer outputs.");
            if (output.destsystem != null)
                throw new Error("Destination system is only valid for reserve transfer outputs.");
            return;
        }
        if (output.refundto != null && !VerusIdInterface.usesRefundDestination(output)) {
            throw new Error("Refund destination is only valid for export, preconvert, or conversion reserve transfer outputs.");
        }
        if (output.via != null && output.convertto == null) {
            throw new Error("Reserve-to-reserve currency transfers with via must also specify convertto.");
        }
        if (output.exportto != null && output.feesatoshis == null) {
            throw new Error("Cross-system currency transfers require explicit reserve transfer feesatoshis.");
        }
        if (output.feecurrency != null && output.feecurrency !== chainId && output.feesatoshis == null) {
            throw new Error("Non-native reserve transfer fee currency requires explicit feesatoshis.");
        }
        if ((output.preconvert || output.mintnew || output.burn || output.burnweight) &&
            output.feecurrency != null &&
            output.feecurrency !== chainId) {
            throw new Error("Preconvert, mint, and burn reserve transfer fees must use the native chain currency.");
        }
        if (output.preconvert && output.convertto == null) {
            throw new Error("Preconvert currency transfers require convertto.");
        }
        if (output.mintnew && output.convertto == null) {
            throw new Error("Mint currency transfers require convertto.");
        }
    }
    static getReserveTransferDestinationCurrency(output, currencies) {
        const primaryCurrency = currencies[0];
        const convertTo = output.convertto ? output.convertto : (output.exportto ? output.exportto : primaryCurrency);
        const destCurrencyID = output.via ? output.via : convertTo;
        const secondReserveID = output.via ? output.convertto : undefined;
        return {
            destCurrencyID,
            secondReserveID,
            destSystemID: output.destsystem ? output.destsystem : output.exportto
        };
    }
    static getReserveTransferFlags(output, currencies) {
        let flags = new bn_js_1.default(1, 10);
        const isConversion = output.convertto != null && (currencies.length !== 1 || output.convertto !== currencies[0]);
        if (output.importtosource)
            flags = flags.or(verus_typescript_primitives_1.RESERVE_TRANSFER_IMPORT_TO_SOURCE);
        if (output.via != null && output.convertto != null)
            flags = flags.or(verus_typescript_primitives_1.RESERVE_TRANSFER_RESERVE_TO_RESERVE);
        if (output.exportto != null)
            flags = flags.or(verus_typescript_primitives_1.RESERVE_TRANSFER_CROSS_SYSTEM);
        if (isConversion)
            flags = flags.or(verus_typescript_primitives_1.RESERVE_TRANSFER_CONVERT);
        if (output.preconvert)
            flags = flags.or(verus_typescript_primitives_1.RESERVE_TRANSFER_PRECONVERT);
        if (output.mintnew)
            flags = flags.or(verus_typescript_primitives_1.RESERVE_TRANSFER_MINT_CURRENCY);
        if (output.burn)
            flags = flags.or(verus_typescript_primitives_1.RESERVE_TRANSFER_BURN_CHANGE_PRICE);
        if (output.burnweight)
            flags = flags.or(verus_typescript_primitives_1.RESERVE_TRANSFER_BURN_CHANGE_WEIGHT);
        return flags;
    }
    static calculateReserveTransferFee(destination, flags) {
        if (flags.and(verus_typescript_primitives_1.RESERVE_TRANSFER_FEE_OUTPUT).gt(new bn_js_1.default(0, 10)))
            return new bn_js_1.default(0, 10);
        const baseFee = RESERVE_TRANSFER_DEFAULT_PER_STEP_FEE.shln(1);
        const destinationSizeSteps = Math.floor(destination.destinationBytes.length / RESERVE_TRANSFER_DESTINATION_BYTE_DIVISOR);
        return baseFee.add(baseFee.mul(new bn_js_1.default(destinationSizeSteps, 10)));
    }
    static getReserveTransferFeeSatoshis(output, flags) {
        return output.feesatoshis != null ?
            VerusIdInterface.getSatoshis(output.feesatoshis, "Reserve transfer fee") :
            VerusIdInterface.calculateReserveTransferFee(output.address, flags);
    }
    static getReserveTransferFeeCurrency(output, chainId) {
        if (output.preconvert || output.mintnew || output.burn || output.burnweight)
            return chainId;
        return output.feecurrency ? output.feecurrency : chainId;
    }
    static hasGatewayLeg(destination) {
        return destination.isGateway() && destination.gatewayID != null;
    }
    static getGatewayLegFees(destination) {
        return VerusIdInterface.hasGatewayLeg(destination) ?
            VerusIdInterface.getSatoshis(destination.fees ? destination.fees.toString() : 0, "Reserve transfer gateway fee") :
            new bn_js_1.default(0, 10);
    }
    static createUnfundedCurrencyTransferTransaction(chainId, currencyTransferOutputs, expiryHeight) {
        const txb = new utxo_lib_1.TransactionBuilder(utxo_lib_1.networks.verus);
        txb.setVersion(4);
        txb.setExpiryHeight(expiryHeight);
        txb.setVersionGroupId(0x892f2085);
        for (const output of currencyTransferOutputs) {
            const tagDestination = output.vdxftag == null ? undefined : new verus_typescript_primitives_1.TxDestination(new verus_typescript_primitives_1.UnknownID((0, verus_typescript_primitives_1.decodeDestination)(output.vdxftag, vdxf_1.X_ADDR_VERSION)), verus_typescript_primitives_1.TxDestination.TYPE_INDEX);
            if (output.address == null)
                throw new Error("Must specify address for all outputs");
            const valueMap = VerusIdInterface.getCurrencyValueMap(output);
            const valueCurrencies = Array.from(valueMap.keys());
            const isReserveTransfer = VerusIdInterface.isReserveTransferOutput(output);
            VerusIdInterface.validateCurrencyTransferOutput(output, chainId, isReserveTransfer);
            const nativeValue = valueMap.get(chainId) || new bn_js_1.default(0, 10);
            const feeCurrency = isReserveTransfer ?
                VerusIdInterface.getReserveTransferFeeCurrency(output, chainId) :
                chainId;
            const flags = isReserveTransfer ?
                VerusIdInterface.getReserveTransferFlags(output, valueCurrencies) :
                new bn_js_1.default(1, 10);
            const feeSatoshis = isReserveTransfer ?
                VerusIdInterface.getReserveTransferFeeSatoshis(output, flags) :
                new bn_js_1.default(0, 10);
            const reserveTransferDestination = isReserveTransfer ?
                VerusIdInterface.getReserveTransferDestination(output) :
                output.address;
            const gatewayLegFees = isReserveTransfer ?
                VerusIdInterface.getGatewayLegFees(reserveTransferDestination) :
                new bn_js_1.default(0, 10);
            const nativeFeeValue = isReserveTransfer && feeCurrency === chainId ? feeSatoshis.add(gatewayLegFees) : new bn_js_1.default(0, 10);
            const outputNativeValue = nativeValue.add(nativeFeeValue);
            if (isReserveTransfer) {
                if (valueMap.size !== 1)
                    throw new Error("Reserve transfers require exactly one currency in their value map.");
                const reserveDestination = VerusIdInterface.getTxDestination(verus_typescript_primitives_1.RESERVE_TRANSFER_DESTINATION);
                const { destCurrencyID, secondReserveID, destSystemID } = VerusIdInterface.getReserveTransferDestinationCurrency(output, valueCurrencies);
                const values = new verus_typescript_primitives_1.CurrencyValueMap({
                    valueMap,
                    multivalue: valueMap.size > 1
                });
                const reserveTransfer = new verus_typescript_primitives_1.ReserveTransfer({
                    values,
                    version: VerusIdInterface.getTokenOutputVersion(valueMap),
                    flags,
                    feeCurrencyID: feeCurrency,
                    feeAmount: feeSatoshis,
                    transferDestination: reserveTransferDestination,
                    destCurrencyID,
                    secondReserveID,
                    destSystemID
                });
                const outMaster = new verus_typescript_primitives_1.OptCCParams({
                    version: new bn_js_1.default(3, 10),
                    evalCode: new bn_js_1.default(verus_typescript_primitives_1.EVALS.EVAL_NONE),
                    m: new bn_js_1.default(1, 10),
                    n: new bn_js_1.default(1, 10),
                    destinations: [tagDestination || reserveDestination]
                });
                const outParams = new verus_typescript_primitives_1.OptCCParams({
                    version: new bn_js_1.default(3, 10),
                    evalCode: new bn_js_1.default(verus_typescript_primitives_1.EVALS.EVAL_RESERVE_TRANSFER),
                    m: new bn_js_1.default(1, 10),
                    n: new bn_js_1.default(1, 10),
                    destinations: [reserveDestination],
                    vData: [reserveTransfer.toBuffer()]
                });
                txb.addOutput(VerusIdInterface.createSmartTransactionOutputScript(outMaster, outParams), outputNativeValue.toNumber());
            }
            else {
                const tokenValueMap = new Map(valueMap);
                tokenValueMap.delete(chainId);
                if (!tagDestination && tokenValueMap.size === 0 && output.address.typeNoFlags().eq(verus_typescript_primitives_1.DEST_PKH)) {
                    txb.addOutput(output.address.getAddressString(), outputNativeValue.toNumber());
                }
                else {
                    const destination = VerusIdInterface.getTxDestination(output.address);
                    const masterDestinations = tagDestination ? [tagDestination] : tokenValueMap.size === 0 ? [] : [destination];
                    const outMaster = new verus_typescript_primitives_1.OptCCParams({
                        version: new bn_js_1.default(3, 10),
                        evalCode: new bn_js_1.default(verus_typescript_primitives_1.EVALS.EVAL_NONE),
                        m: new bn_js_1.default(masterDestinations.length),
                        n: new bn_js_1.default(masterDestinations.length),
                        destinations: masterDestinations
                    });
                    const outParams = tokenValueMap.size === 0 ?
                        new verus_typescript_primitives_1.OptCCParams({
                            version: new bn_js_1.default(3, 10),
                            evalCode: new bn_js_1.default(verus_typescript_primitives_1.EVALS.EVAL_NONE),
                            m: new bn_js_1.default(1, 10),
                            n: new bn_js_1.default(1, 10),
                            destinations: [destination]
                        }) :
                        new verus_typescript_primitives_1.OptCCParams({
                            version: new bn_js_1.default(3, 10),
                            evalCode: new bn_js_1.default(verus_typescript_primitives_1.EVALS.EVAL_RESERVE_OUTPUT),
                            m: new bn_js_1.default(1, 10),
                            n: new bn_js_1.default(1, 10),
                            destinations: [destination],
                            vData: [new verus_typescript_primitives_1.TokenOutput({
                                    values: new verus_typescript_primitives_1.CurrencyValueMap({
                                        valueMap: tokenValueMap,
                                        multivalue: tokenValueMap.size > 1
                                    }),
                                    version: VerusIdInterface.getTokenOutputVersion(tokenValueMap)
                                }).toBuffer()]
                        });
                    txb.addOutput(VerusIdInterface.createSmartTransactionOutputScript(outMaster, outParams), outputNativeValue.toNumber());
                }
            }
        }
        return txb.buildIncomplete().toHex();
    }
    static getExpectedSentFromCurrencyTransferOutputs(currencyTransferOutputs) {
        const expectedSent = new Map();
        for (const output of currencyTransferOutputs) {
            const valueMap = VerusIdInterface.getCurrencyValueMap(output);
            valueMap.forEach((value, currency) => {
                const satoshis = (0, bignumber_js_1.default)(value.toString());
                if (expectedSent.has(currency))
                    expectedSent.set(currency, expectedSent.get(currency).plus(satoshis));
                else
                    expectedSent.set(currency, satoshis);
            });
        }
        return expectedSent;
    }
    static getDestinationFees(destination) {
        return (0, bignumber_js_1.default)(VerusIdInterface.getGatewayLegFees(destination).toString());
    }
    static getExpectedFeesFromCurrencyTransferOutputs(currencyTransferOutputs, chainId) {
        const expectedFees = new Map();
        for (const output of currencyTransferOutputs) {
            const isReserveTransfer = VerusIdInterface.isReserveTransferOutput(output);
            if (!isReserveTransfer)
                continue;
            const valueCurrencies = Array.from(VerusIdInterface.getCurrencyValueMap(output).keys());
            VerusIdInterface.validateCurrencyTransferOutput(output, chainId, isReserveTransfer);
            const flags = VerusIdInterface.getReserveTransferFlags(output, valueCurrencies);
            const feeCurrency = VerusIdInterface.getReserveTransferFeeCurrency(output, chainId);
            const reserveTransferDestination = VerusIdInterface.getReserveTransferDestination(output);
            const outputFees = (0, bignumber_js_1.default)(VerusIdInterface.getReserveTransferFeeSatoshis(output, flags).toString())
                .plus(VerusIdInterface.getDestinationFees(reserveTransferDestination));
            if (expectedFees.has(feeCurrency))
                expectedFees.set(feeCurrency, expectedFees.get(feeCurrency).plus(outputFees));
            else
                expectedFees.set(feeCurrency, outputFees);
        }
        return expectedFees;
    }
    static validateCurrencyTransferSent(validation, expectedSent) {
        const keys = new Set([
            ...Object.keys(validation.sent ? validation.sent : {}),
            ...Array.from(expectedSent.keys())
        ]);
        keys.forEach(key => {
            const actual = (0, bignumber_js_1.default)(validation.sent && validation.sent[key] != null ? validation.sent[key] : 0);
            const expected = expectedSent.get(key) || (0, bignumber_js_1.default)(0);
            if (!actual.isEqualTo(expected)) {
                throw new Error("Sent currency delta does not match explicit currency transfer output for " + key + ".");
            }
        });
    }
    static validateFees(validation, expectedExplicitFees, chainId, maxFee) {
        const maxNativeFeeSatoshis = (0, bignumber_js_1.default)((0, updateFundingVerification_1.identityUpdateFeeCap)(maxFee));
        if (!maxNativeFeeSatoshis.isFinite() || maxNativeFeeSatoshis.isNegative()) {
            throw new Error("Maximum fee must be a non-negative finite number.");
        }
        const keys = new Set([
            chainId,
            ...Object.keys(validation.fees ? validation.fees : {}),
            ...Array.from(expectedExplicitFees.keys())
        ]);
        keys.forEach(key => {
            const actual = (0, bignumber_js_1.default)(validation.fees && validation.fees[key] != null ? validation.fees[key] : 0);
            const expectedExplicitFee = expectedExplicitFees.get(key) || (0, bignumber_js_1.default)(0);
            if (actual.isLessThan(expectedExplicitFee)) {
                throw new Error("Fee is lower than explicit fee output for " + key + ".");
            }
            if (key === chainId) {
                if (actual.isGreaterThan(maxNativeFeeSatoshis)) {
                    throw new Error("Fee exceeds maximum permissable fee value.");
                }
            }
            else if (!actual.isEqualTo(expectedExplicitFee)) {
                throw new Error("Unexpected fee currency delta for " + key + ".");
            }
        });
    }
    static getFundingUtxosFromTransaction(fundedTxHex, utxoList) {
        const fundedTx = utxo_lib_1.Transaction.fromHex(fundedTxHex, utxo_lib_1.networks.verus);
        const utxosUsed = [];
        fundedTx.ins.forEach((input) => {
            const inputFromList = utxoList.find(utxo => {
                const inputHash = Buffer.from(input.hash).reverse().toString('hex');
                return utxo.txid === inputHash && utxo.outputIndex === input.index;
            });
            if (inputFromList) {
                utxosUsed.push(inputFromList);
            }
            else
                throw new Error("Input not found in UTXO list");
        });
        return utxosUsed;
    }
    getVerifiedFundingUtxosFromTransaction(fundedTxHex_1, utxoList_1) {
        return __awaiter(this, arguments, void 0, function* (fundedTxHex, utxoList, allowUnverifiedPrevouts = false) {
            (0, fundingVerification_1.assertUnverifiedPrevoutsAllowed)(allowUnverifiedPrevouts);
            if (allowUnverifiedPrevouts)
                return VerusIdInterface.getFundingUtxosFromTransaction(fundedTxHex, utxoList);
            const fundedTx = (0, fundingPrimitives_1.transaction)(fundedTxHex);
            const seen = new Set();
            const txCache = new Map();
            const utxosUsed = [];
            for (const input of fundedTx.ins) {
                const inputHash = Buffer.from(input.hash).reverse().toString('hex');
                const outpoint = `${inputHash}:${input.index}`;
                if (seen.has(outpoint))
                    throw new Error("Duplicate funding outpoint.");
                seen.add(outpoint);
                const inputFromList = utxoList.find(utxo => utxo.txid === inputHash && utxo.outputIndex === input.index);
                if (!inputFromList)
                    throw new Error("Input not found in UTXO list");
                let prevTx = txCache.get(inputHash);
                if (prevTx == null) {
                    const rawTxRes = yield this.interface.getRawTransaction(inputHash, 0);
                    if (rawTxRes.error)
                        throw new Error("Couldn't verify prevout " + inputHash + ": " + rawTxRes.error.message);
                    const rawTx = rawTxRes.result;
                    const rawTxHex = typeof rawTx === "string" ? rawTx : rawTx.hex;
                    if (typeof rawTxHex !== "string")
                        throw new Error("Couldn't verify prevout " + inputHash + ": missing raw transaction hex.");
                    prevTx = (0, fundingPrimitives_1.transaction)(rawTxHex);
                    if (prevTx.getId() !== inputHash) {
                        throw new Error("Prevout transaction hash mismatch for " + inputHash + ".");
                    }
                    txCache.set(inputHash, prevTx);
                }
                const prevOut = prevTx.outs[input.index];
                if (prevOut == null)
                    throw new Error("Prevout " + inputHash + " index " + input.index + " not found.");
                utxosUsed.push(Object.assign(Object.assign({}, inputFromList), { script: prevOut.script.toString('hex'), satoshis: prevOut.value, rawTransaction: prevTx.toHex() }));
            }
            return utxosUsed;
        });
    }
    static combineUnfundedTransactions(baseTxHex, outputsTxHex) {
        const baseTx = utxo_lib_1.Transaction.fromHex(baseTxHex, utxo_lib_1.networks.verus);
        const outputsTx = utxo_lib_1.Transaction.fromHex(outputsTxHex, utxo_lib_1.networks.verus);
        if (baseTx.ins.length !== 0)
            throw new Error("Identity update transaction must be unfunded before combining currency transfer outputs.");
        if (outputsTx.ins.length !== 0)
            throw new Error("Currency transfer transaction must be unfunded before combining.");
        outputsTx.outs.forEach((output) => {
            baseTx.outs.push(output);
        });
        return baseTx.toHex();
    }
    static validateCompletedIdentityUpdateTransaction(fundedTxHex, completedTxHex, identityTransaction, identityVout) {
        const fundedTx = utxo_lib_1.Transaction.fromHex(fundedTxHex, utxo_lib_1.networks.verus);
        const completedTx = utxo_lib_1.Transaction.fromHex(completedTxHex, utxo_lib_1.networks.verus);
        if (completedTx.outs.length !== fundedTx.outs.length) {
            throw new Error("Completed identity update output count does not match funded transaction.");
        }
        for (let i = 0; i < fundedTx.outs.length; i++) {
            if (completedTx.outs[i].value !== fundedTx.outs[i].value ||
                Buffer.from(completedTx.outs[i].script).toString('hex') !== Buffer.from(fundedTx.outs[i].script).toString('hex')) {
                throw new Error("Completed identity update outputs do not match funded transaction.");
            }
        }
        if (completedTx.ins.length !== fundedTx.ins.length + 1) {
            throw new Error("Completed identity update input count does not match funded transaction plus identity input.");
        }
        for (let i = 0; i < fundedTx.ins.length; i++) {
            if (Buffer.from(completedTx.ins[i].hash).toString('hex') !== Buffer.from(fundedTx.ins[i].hash).toString('hex') ||
                completedTx.ins[i].index !== fundedTx.ins[i].index ||
                completedTx.ins[i].sequence !== fundedTx.ins[i].sequence) {
                throw new Error("Completed identity update funding inputs do not match funded transaction.");
            }
        }
        const identityInput = completedTx.ins[fundedTx.ins.length];
        const expectedIdentityInputHash = Buffer.from(identityTransaction.getId(), 'hex').reverse();
        if (Buffer.from(identityInput.hash).toString('hex') !== expectedIdentityInputHash.toString('hex') || identityInput.index !== identityVout) {
            throw new Error("Completed identity update does not spend the expected identity output.");
        }
    }
    static completeIdentityUpdateTransaction(fundedTxHex, utxoList, identityTransaction, identityVout) {
        const completeIdentityUpdate = completeFundedIdentityUpdate(fundedTxHex, utxo_lib_1.networks.verus, utxoList.map(x => Buffer.from(x.script, 'hex')), {
            hash: Buffer.from(identityTransaction.getId(), 'hex').reverse(),
            index: identityVout,
            script: identityTransaction.outs[identityVout].script,
            sequence: 4294967295
        });
        VerusIdInterface.validateCompletedIdentityUpdateTransaction(fundedTxHex, completeIdentityUpdate, identityTransaction, identityVout);
        return completeIdentityUpdate;
    }
    static getIdentityDefinitionUtxo(identityAddress, identityTransaction, identityVout, identityTransactionHeight) {
        return {
            address: identityAddress,
            txid: identityTransaction.getId(),
            outputIndex: identityVout,
            script: identityTransaction.outs[identityVout].script.toString('hex'),
            satoshis: identityTransaction.outs[identityVout].value,
            rawTransaction: identityTransaction.toHex(),
            height: identityTransactionHeight,
            isspendable: false,
            blocktime: 0 // Filled in to avoid getblock call because blocktime is not currently checked for the ID definition utxo
        };
    }
    static validateIdentityPrimaryAddress(identity, expectedPrimaryAddress) {
        if (expectedPrimaryAddress == null)
            return;
        // Binary content need not have a lossless daemon JSON representation.
        const primaryAddresses = (identity.primaryAddresses || []).map(address => address.toAddress());
        if (primaryAddresses.length !== 1 || primaryAddresses[0] !== expectedPrimaryAddress) {
            throw new Error("Identity primary address must be exactly " + expectedPrimaryAddress + ".");
        }
    }
    /** Validate definitions returned for required revocation/recovery authorities. */
    validateIdentityUpdateAuthorities(authorities) {
        return __awaiter(this, void 0, void 0, function* () {
            for (const authority of authorities) {
                const response = yield this.interface.getIdentity(authority.address);
                try {
                    if (response.error || !response.result) {
                        throw new Error("Missing authority");
                    }
                    // Check the RPC value before parsing can normalize a malformed version.
                    const rawVersion = response.result.identity.version;
                    if (!Number.isInteger(rawVersion) ||
                        rawVersion < 1 ||
                        rawVersion > 3) {
                        throw new Error("Invalid authority version");
                    }
                    const definition = verus_typescript_primitives_1.Identity.fromJson(response.result.identity);
                    (0, identityValidation_1.validateIdentityVersion)(definition.version);
                    // Validate the signing threshold and version-specific authority fields.
                    if (!bn_js_1.default.isBN(definition.minSigs)) {
                        throw new Error("Missing authority threshold");
                    }
                    (0, identityValidation_1.validateIdentityPrimaryAddresses)(definition.primaryAddresses, definition.minSigs);
                    if (definition.version.gten(2)) {
                        (0, fundingPrimitives_1.validAddress)(definition.revocationAuthority.toAddress(), true);
                        (0, fundingPrimitives_1.validAddress)(definition.recoveryAuthority.toAddress(), true);
                    }
                    // Bind the returned definition to the requested authority address.
                    if (definition.getIdentityAddress() !== authority.address) {
                        throw new Error("Wrong authority");
                    }
                }
                catch (_) {
                    throw new Error(`Identity ${authority.role} authority does not exist on the configured chain.`);
                }
            }
        });
    }
    /**
     * Build or verify an unfunded update against the raw identity being spent.
     * Use one height/expiry context for identity edits, evidence, and verification.
     */
    prepareIdentityUpdateTransaction(identity_1, rawIdentityTransaction_1, currentHeight_1, updateIdentityTransactionHex_1) {
        return __awaiter(this, arguments, void 0, function* (identity, rawIdentityTransaction, currentHeight, updateIdentityTransactionHex, parseVdxfObjects = true, isTestnet = false, decryptData, localUploadCrypto, chainIAddr) {
            var _a;
            // Detach caller-owned state before invoking RPC or wallet callbacks.
            identity = (0, requestSnapshot_1.snapshotRequestValue)(identity);
            localUploadCrypto = (0, localUpdateData_1.captureLocalIdentityUploadCrypto)(localUploadCrypto);
            decryptData = decryptData || (localUploadCrypto === null || localUploadCrypto === void 0 ? void 0 : localUploadCrypto.decryptData);
            // Reject unsupported request fields and uploads before any external work.
            if (identity instanceof verus_typescript_primitives_1.IdentityUpdateRequestDetails) {
                if (!bn_js_1.default.isBN(identity.flags) ||
                    identity.flags.isNeg() ||
                    identity.flags.gtn(31)) {
                    throw new Error("Unsupported identity update request flags.");
                }
                if (identity.expires() || identity.expiryHeight !== undefined) {
                    if (!bn_js_1.default.isBN(identity.expiryHeight) ||
                        identity.expiryHeight.isNeg() ||
                        identity.expiryHeight.bitLength() > 32) {
                        throw new Error("Invalid identity update request expiry height.");
                    }
                }
                if (identity.containsSystem() || identity.systemID !== undefined) {
                    if (!(identity.systemID instanceof verus_typescript_primitives_1.IdentityID)) {
                        throw new Error("Invalid identity update request system.");
                    }
                    (0, fundingPrimitives_1.validAddress)(identity.systemID.toAddress(), true);
                }
                if ((identity.containsTxid() || identity.txid !== undefined) &&
                    (!Buffer.isBuffer(identity.txid) || identity.txid.length !== 32)) {
                    throw new Error("Invalid identity update request txid.");
                }
                const partial = identity.identity;
                if (!(partial instanceof verus_typescript_primitives_1.PartialIdentity)) {
                    throw new Error("Identity update request requires a partial identity.");
                }
                (0, identityValidation_1.dropEmptyIdentityContent)(partial);
                (0, identityValidation_1.validatePartialIdentityDefinition)(partial);
                (0, localUpdateData_1.validateLocalIdentityUploadRequest)(identity, isTestnet);
                // Uploads need decryption; local construction also needs encryption.
                if (identity.containsSignData() &&
                    !updateIdentityTransactionHex &&
                    !localUploadCrypto) {
                    throw new Error("Local identity data uploads require wallet crypto callbacks.");
                }
                if (identity.containsSignData() && typeof decryptData !== "function") {
                    throw new Error("Identity data uploads require a decryption callback.");
                }
            }
            // Select the chain context once so lock normalization and tx expiry agree.
            let height = currentHeight;
            if (height == null) {
                // Lock consensus uses the active chain's next block. A peer-reported
                // longest chain can be ahead while this endpoint is still synchronizing.
                const response = yield this.interface.getInfo();
                if (response.error) {
                    throw new Error(response.error.message);
                }
                height = (_a = response.result) === null || _a === void 0 ? void 0 : _a.blocks;
            }
            if (!Number.isSafeInteger(height) ||
                height < 0 ||
                height + 20 >= 500000000) {
                throw new Error("Invalid identity update preparation height.");
            }
            let expiryHeight = height + 20;
            if (identity instanceof verus_typescript_primitives_1.IdentityUpdateRequestDetails &&
                identity.expiryHeight !== undefined) {
                if (identity.expiryHeight.lte(new bn_js_1.default(height))) {
                    throw new Error("Identity update request has expired.");
                }
                expiryHeight = Math.min(expiryHeight, identity.expiryHeight.toNumber());
            }
            // A supplied template fixes the expiry used for every subsequent lock check.
            if (identity instanceof verus_typescript_primitives_1.IdentityUpdateRequestDetails &&
                updateIdentityTransactionHex) {
                (0, updateLimits_1.validateIdentityUpdateTransactionSize)(updateIdentityTransactionHex);
                const supplied = (0, fundingPrimitives_1.transaction)(updateIdentityTransactionHex);
                (0, fundingVerification_1.verifyTransparentTransaction)(supplied);
                if (!Number.isInteger(supplied.expiryHeight) ||
                    supplied.expiryHeight < height + updateLimits_1.MIN_IDENTITY_UPDATE_EXPIRY_DELTA ||
                    supplied.expiryHeight >= 500000000 ||
                    supplied.expiryHeight > height + updateLimits_1.MAX_IDENTITY_UPDATE_EXPIRY_DELTA ||
                    (identity.expiryHeight !== undefined &&
                        identity.expiryHeight.lt(new bn_js_1.default(supplied.expiryHeight)))) {
                    throw new Error("Supplied identity update expiry must be 4 to 40 blocks ahead and within the request expiry.");
                }
                expiryHeight = supplied.expiryHeight;
            }
            if (expiryHeight < height + updateLimits_1.MIN_IDENTITY_UPDATE_EXPIRY_DELTA) {
                throw new Error("Identity update expiry must be at least 4 blocks ahead to satisfy daemon relay policy.");
            }
            const chainId = chainIAddr || (yield this.getChainId());
            (0, fundingPrimitives_1.validAddress)(chainId, true);
            if (identity instanceof verus_typescript_primitives_1.IdentityUpdateRequestDetails &&
                identity.systemID !== undefined &&
                identity.systemID.toAddress() !== chainId) {
                throw new Error("Identity update request system does not match the configured chain.");
            }
            const identityTransaction = (0, fundingPrimitives_1.transaction)(rawIdentityTransaction);
            let unfundedTxHex;
            let identityAddress;
            let vout = -1;
            let identityOnOutput;
            if (identity instanceof verus_typescript_primitives_1.Identity) {
                // Full identities describe final state: validate the transition without
                // applying the partial-request normalization rules.
                (0, localIdentityUpdate_1.validateSupportedIdentityUpdateState)(identity);
                identityAddress = identity.getIdentityAddress();
                const identityFromIdTx = VerusIdInterface.getIdentityFromIdTx(identityTransaction, identityAddress, false);
                (0, localIdentityUpdate_1.validateSupportedIdentityUpdateState)(identityFromIdTx.identity);
                (0, identityValidation_1.dropEmptyIdentityContent)(identity);
                const requiredAuthorities = (0, fullIdentityUpdateValidation_1.validateFullIdentityUpdate)(identityFromIdTx.identity, identity, {
                    chainId,
                    nextBlockHeight: height + 1,
                    expiryHeight,
                });
                yield this.validateIdentityUpdateAuthorities(requiredAuthorities);
                unfundedTxHex = createUnfundedIdentityUpdate(identity.toBuffer().toString("hex"), utxo_lib_1.networks.verus, expiryHeight);
                vout = identityFromIdTx.vout;
                identityOnOutput = identity;
            }
            else if (identity instanceof verus_typescript_primitives_1.IdentityUpdateRequestDetails) {
                if ((identity.containsTxid() || identity.txid !== undefined) &&
                    identity.getTxidString() !== identityTransaction.getId()) {
                    throw new Error("Identity update request txid does not match the txid of the identity transaction");
                }
                identityAddress = identity.getIdentityAddress(isTestnet);
                // Raw source bytes, rather than aggregated RPC JSON, are the merge base.
                const source = VerusIdInterface.getIdentityFromIdTx(identityTransaction, identityAddress, false);
                vout = source.vout;
                (0, updateFundingVerification_1.verifyIdentityDefinitionOutput)(identityTransaction.outs[vout], identityAddress);
                const merged = (0, localIdentityUpdate_1.applyLocalIdentityUpdate)(source.identity, identity.identity, {
                    chainId,
                    nextBlockHeight: height + 1,
                    expiryHeight,
                    hasDataUploads: identity.containsSignData(),
                });
                yield this.validateIdentityUpdateAuthorities(merged.requiredAuthorities);
                const expectedIdentity = merged.identity;
                // Keep the expected ordinary edit separate from generated upload references.
                // Both supplied and local templates are checked against it below.
                if (updateIdentityTransactionHex) {
                    unfundedTxHex = updateIdentityTransactionHex;
                }
                else {
                    const constructedIdentity = (0, requestSnapshot_1.snapshotRequestValue)(expectedIdentity);
                    const evidence = identity.containsSignData()
                        ? yield (0, localUpdateData_1.buildLocalIdentityUpdateData)({
                            request: identity,
                            chainId,
                            crypto: localUploadCrypto,
                        })
                        : { outputs: [], contentMultiMap: new Map() };
                    for (const [key, values] of evidence.contentMultiMap) {
                        constructedIdentity.contentMultiMap.kvContent.set(key, values);
                    }
                    (0, identityValidation_1.validateIdentityDefinition)(constructedIdentity);
                    const local = (0, fundingPrimitives_1.transaction)(createUnfundedIdentityUpdate(constructedIdentity.toBuffer().toString("hex"), utxo_lib_1.networks.verus, expiryHeight));
                    // References were built for evidence starting at output zero.
                    local.outs = [...evidence.outputs, ...local.outs];
                    unfundedTxHex = local.toHex();
                }
                (0, updateLimits_1.validateIdentityUpdateTransactionSize)(unfundedTxHex);
                const template = (0, fundingPrimitives_1.transaction)(unfundedTxHex);
                (0, fundingVerification_1.verifyTransparentTransaction)(template);
                // Supplied daemon templates can include the old identity input. Funding
                // adds that verified input itself after validating the output plan.
                template.ins = [];
                unfundedTxHex = template.toHex();
                const output = VerusIdInterface.getIdentityFromIdTx(template, identityAddress, false, true);
                identityOnOutput = output.identity;
                // Remove upload entries from this comparison copy so ordinary fields can
                // be checked separately. Verify uploads against the original request below.
                const ordinary = (0, requestSnapshot_1.snapshotRequestValue)(identityOnOutput);
                if (identity.containsSignData()) {
                    for (const [key] of identity.signDataMap.entries()) {
                        ordinary.contentMultiMap.kvContent.deleteByAddress(key.toAddress());
                    }
                }
                const actualPrivate = ordinary.privateAddresses || [];
                const expectedPrivate = expectedIdentity.privateAddresses || [];
                if (actualPrivate.length !== expectedPrivate.length ||
                    actualPrivate.some((value, index) => !value.toBuffer().equals(expectedPrivate[index].toBuffer()))) {
                    throw new Error("Private addresses in identity transaction do not match the requested update.");
                }
                if (!ordinary.contentMultiMap
                    .toBuffer()
                    .equals(expectedIdentity.contentMultiMap.toBuffer())) {
                    throw new Error("Unexpected contentmultimap entries in identity transaction");
                }
                if (!ordinary.toBuffer().equals(expectedIdentity.toBuffer())) {
                    throw new Error("Identity update request changes or unchanged identity properties do not match the identity transaction.");
                }
                if (!identity.containsSignData() && template.outs.length !== 1) {
                    throw new Error("Expected only one output in identity update request");
                }
                // Authenticate and decrypt every requested upload before funding.
                if (identity.containsSignData()) {
                    yield (0, updateDataVerification_1.verifyIdentityUpdateData)(identity, unfundedTxHex, decryptData, chainId);
                }
            }
            else {
                throw new Error("Invalid identity type");
            }
            // Even unfunded results must contain a canonical, zero-value definition.
            // Return the decoded output so later policy checks use the actual bytes.
            (0, updateLimits_1.validateIdentityUpdateTransactionSize)(unfundedTxHex);
            const outputTransaction = (0, fundingPrimitives_1.transaction)(unfundedTxHex);
            (0, fundingVerification_1.verifyTransparentTransaction)(outputTransaction);
            const outputDefinition = VerusIdInterface.getIdentityFromIdTx(outputTransaction, identityAddress, parseVdxfObjects, true);
            (0, updateFundingVerification_1.verifyIdentityDefinitionOutput)(outputTransaction.outs[outputDefinition.vout], identityAddress, true);
            identityOnOutput = outputDefinition.identity;
            (0, updateFundingVerification_1.verifyIdentityDefinitionOutput)(identityTransaction.outs[vout], identityAddress);
            return {
                height,
                expiryHeight,
                chainId,
                identityTransaction,
                identityAddress,
                identityOnOutput,
                unfundedTxHex,
                vout,
            };
        });
    }
    // When using this function with a remote RPC server, PLEASE USE THE VERUSID DECODED FROM rawIdentityTransaction
    // AS YOUR BASE FOR PASSING IN THE IDENTITY PARAMETER (what you want to update). Otherwise if you're using an
    // untrusted server to get your identity base and then editing, you could be updating an ID with data you don't
    // want to update.
    createUpdateIdentityTransaction(identity_1, changeAddress_1, rawIdentityTransaction_1, identityTransactionHeight_1, utxoList_1, chainIAddr_1, maxFee_1, fundRawTransactionResult_1, currentHeight_1, updateIdentityTransactionHex_1) {
        return __awaiter(this, arguments, void 0, function* (identity, changeAddress, rawIdentityTransaction, identityTransactionHeight, utxoList, chainIAddr, maxFee, fundRawTransactionResult, currentHeight, updateIdentityTransactionHex, parseVdxfObjects = true, isTestnet = false, // This parameter is only necessary if you pass in an IdentityUpdateRequestDetails
        allowUnverifiedPrevouts = false, decryptData, localUploadCrypto) {
            var _a;
            (0, fundingVerification_1.assertUnverifiedPrevoutsAllowed)(allowUnverifiedPrevouts);
            if (maxFee !== undefined)
                (0, updateFundingVerification_1.identityUpdateFeeCap)(maxFee);
            const utxos = utxoList == null ? undefined : (0, requestSnapshot_1.snapshotRequestValue)(getUtxos(utxoList));
            fundRawTransactionResult = (0, requestSnapshot_1.snapshotRequestValue)(fundRawTransactionResult);
            const preparedIdentityUpdate = yield this.prepareIdentityUpdateTransaction(identity, rawIdentityTransaction, currentHeight, updateIdentityTransactionHex, parseVdxfObjects, isTestnet, decryptData, localUploadCrypto, chainIAddr);
            const feeLimit = maxFee === undefined ? (0, updateFundingVerification_1.defaultIdentityUpdateFeeCap)(preparedIdentityUpdate.unfundedTxHex) : maxFee;
            let fundedTxHex;
            if (utxos == null) {
                fundedTxHex = preparedIdentityUpdate.unfundedTxHex;
            }
            else if (fundRawTransactionResult == null) {
                const _fundRawTxRes = yield this.interface.fundRawTransaction(preparedIdentityUpdate.unfundedTxHex, utxos.map(utxo => {
                    return {
                        voutnum: utxo.outputIndex,
                        txid: utxo.txid,
                    };
                }), changeAddress);
                if (_fundRawTxRes.error)
                    throw new Error("Couldn't fund raw transaction");
                else
                    fundedTxHex = _fundRawTxRes.result.hex;
            }
            else
                fundedTxHex = fundRawTransactionResult.hex;
            (0, updateLimits_1.validateIdentityUpdateTransactionSize)(fundedTxHex);
            const chainId = preparedIdentityUpdate.chainId;
            const deltas = new Map();
            if (utxos) {
                const verifiedFundingUtxos = yield this.getVerifiedFundingUtxosFromTransaction(fundedTxHex, utxos, allowUnverifiedPrevouts);
                const validation = validateFundedCurrencyTransfer(chainId, fundedTxHex, preparedIdentityUpdate.unfundedTxHex, changeAddress, utxo_lib_1.networks.verus, verifiedFundingUtxos);
                if (!validation.valid)
                    throw new Error(validation.message);
                VerusIdInterface.validateNoUnexpectedCurrencySent(validation);
                VerusIdInterface.validateFees(validation, new Map(), chainId, feeLimit);
                VerusIdInterface.addValidationFeesToDeltas(validation, deltas);
                const completeIdentityUpdate = VerusIdInterface.completeIdentityUpdateTransaction(fundedTxHex, verifiedFundingUtxos, preparedIdentityUpdate.identityTransaction, preparedIdentityUpdate.vout);
                verifiedFundingUtxos.push(VerusIdInterface.getIdentityDefinitionUtxo(preparedIdentityUpdate.identityAddress, preparedIdentityUpdate.identityTransaction, preparedIdentityUpdate.vout, identityTransactionHeight));
                const fundingApproval = (0, updateFundingVerification_1.createIdentityUpdateFundingApproval)({
                    txHex: completeIdentityUpdate, unfundedTxHex: preparedIdentityUpdate.unfundedTxHex,
                    systemId: chainId, changeAddress, nativeFee: ((_a = validation.fees) === null || _a === void 0 ? void 0 : _a[chainId]) || "0",
                    fees: Object.assign({}, validation.fees), explicitFees: {}, maxFee: (0, updateFundingVerification_1.identityUpdateFeeCap)(feeLimit),
                    identity: { txid: preparedIdentityUpdate.identityTransaction.getId(), outputIndex: preparedIdentityUpdate.vout,
                        identityAddress: preparedIdentityUpdate.identityAddress },
                }, verifiedFundingUtxos, allowUnverifiedPrevouts, {
                    chainId, nextBlockHeight: preparedIdentityUpdate.height + 1,
                });
                return {
                    hex: completeIdentityUpdate,
                    utxos: verifiedFundingUtxos,
                    identity: preparedIdentityUpdate.identityOnOutput,
                    deltas,
                    fundingApproval
                };
            }
            else {
                return {
                    hex: fundedTxHex,
                    utxos: [],
                    identity: preparedIdentityUpdate.identityOnOutput,
                    deltas
                };
            }
        });
    }
    createUpdateIdentityWithCurrencyTransferTransaction(identity_1, changeAddress_1, rawIdentityTransaction_1, identityTransactionHeight_1, currencyTransferOutputs_1, utxoList_1) {
        return __awaiter(this, arguments, void 0, function* (identity, changeAddress, rawIdentityTransaction, identityTransactionHeight, currencyTransferOutputs, utxoList, options = {}) {
            var _a, _b, _c;
            const localUploadCrypto = (0, localUpdateData_1.captureLocalIdentityUploadCrypto)(options.localUploadCrypto);
            options = Object.assign(Object.assign({}, (0, requestSnapshot_1.snapshotRequestValue)(Object.assign(Object.assign({}, options), { localUploadCrypto: undefined }))), { localUploadCrypto });
            currencyTransferOutputs = (0, requestSnapshot_1.snapshotRequestValue)(currencyTransferOutputs);
            (0, fundingVerification_1.assertUnverifiedPrevoutsAllowed)((_a = options.allowUnverifiedPrevouts) !== null && _a !== void 0 ? _a : false);
            if (options.maxFee !== undefined)
                (0, updateFundingVerification_1.identityUpdateFeeCap)(options.maxFee);
            const utxos = (0, requestSnapshot_1.snapshotRequestValue)(getUtxos(utxoList));
            if (!currencyTransferOutputs.length)
                throw new Error("Must provide at least one explicit currency transfer output.");
            // Retain the caller's approved ownership policy before any RPC await. A
            // copied address list prevents later form changes from relaxing this check.
            const expectedPrimaryAddress = options.expectedIdentityPrimaryAddress == null ? changeAddress : options.expectedIdentityPrimaryAddress;
            const suppliedPrimaryAddresses = options.expectedIdentityPrimaryAddresses;
            const expectedMinimumSignatures = options.expectedIdentityMinimumSignatures;
            const hasExpectedPolicy = suppliedPrimaryAddresses !== undefined || expectedMinimumSignatures !== undefined;
            let expectedPrimaryAddresses;
            if (hasExpectedPolicy) {
                if (options.expectedIdentityPrimaryAddress !== undefined) {
                    throw new Error("Choose either an expected primary address or a complete expected identity signing policy.");
                }
                if (!Array.isArray(suppliedPrimaryAddresses) || suppliedPrimaryAddresses.length === 0 || suppliedPrimaryAddresses.length > 25 ||
                    !Number.isInteger(expectedMinimumSignatures) || expectedMinimumSignatures < 1 ||
                    expectedMinimumSignatures > suppliedPrimaryAddresses.length || expectedMinimumSignatures > 13) {
                    throw new Error("Expected identity signing policy requires primary addresses and a valid minimum signature count.");
                }
                expectedPrimaryAddresses = [...suppliedPrimaryAddresses];
                try {
                    if (new Set(expectedPrimaryAddresses).size !== expectedPrimaryAddresses.length ||
                        expectedPrimaryAddresses.some(primary => typeof primary !== "string" || verus_typescript_primitives_1.KeyID.fromAddress(primary).toAddress() !== primary)) {
                        throw new Error("Invalid primary address.");
                    }
                }
                catch (_) {
                    throw new Error("Expected identity primary addresses must be distinct transparent R-addresses.");
                }
            }
            const preparedIdentityUpdate = yield this.prepareIdentityUpdateTransaction(identity, rawIdentityTransaction, options.currentHeight, options.updateIdentityTransactionHex, options.parseVdxfObjects == null ? true : options.parseVdxfObjects, options.isTestnet == null ? false : options.isTestnet, options.decryptData, options.localUploadCrypto, options.chainIAddr);
            if (expectedPrimaryAddresses) {
                const outputIdentity = preparedIdentityUpdate.identityOnOutput;
                const outputPrimaryAddresses = (outputIdentity.primaryAddresses || []).map(address => address.toAddress());
                if (outputPrimaryAddresses.length !== expectedPrimaryAddresses.length ||
                    outputPrimaryAddresses.some((primary, index) => primary !== expectedPrimaryAddresses[index]) ||
                    !((_b = outputIdentity.minSigs) === null || _b === void 0 ? void 0 : _b.eqn(expectedMinimumSignatures))) {
                    throw new Error("Identity signing policy does not match the expected primary addresses and minimum signatures.");
                }
            }
            else {
                VerusIdInterface.validateIdentityPrimaryAddress(preparedIdentityUpdate.identityOnOutput, expectedPrimaryAddress);
            }
            const chainId = preparedIdentityUpdate.chainId;
            const currencyTransferTxHex = VerusIdInterface.createUnfundedCurrencyTransferTransaction(chainId, currencyTransferOutputs, preparedIdentityUpdate.expiryHeight);
            const combinedUnfundedTxHex = VerusIdInterface.combineUnfundedTransactions(preparedIdentityUpdate.unfundedTxHex, currencyTransferTxHex);
            (0, updateLimits_1.validateIdentityUpdateTransactionSize)(combinedUnfundedTxHex);
            const expectedExplicitFees = VerusIdInterface.getExpectedFeesFromCurrencyTransferOutputs(currencyTransferOutputs, chainId);
            const feeLimit = options.maxFee === undefined ? (0, updateFundingVerification_1.defaultIdentityUpdateFeeCap)(combinedUnfundedTxHex, (expectedExplicitFees.get(chainId) || new bignumber_js_1.default(0)).toFixed(0)) : options.maxFee;
            let fundedTxHex;
            if (options.fundRawTransactionResult == null) {
                const _fundRawTxRes = yield this.interface.fundRawTransaction(combinedUnfundedTxHex, utxos.map(utxo => {
                    return {
                        voutnum: utxo.outputIndex,
                        txid: utxo.txid,
                    };
                }), changeAddress);
                if (_fundRawTxRes.error)
                    throw new Error("Couldn't fund raw transaction");
                else
                    fundedTxHex = _fundRawTxRes.result.hex;
            }
            else
                fundedTxHex = options.fundRawTransactionResult.hex;
            (0, updateLimits_1.validateIdentityUpdateTransactionSize)(fundedTxHex);
            const verifiedFundingUtxos = yield this.getVerifiedFundingUtxosFromTransaction(fundedTxHex, utxos, options.allowUnverifiedPrevouts == null ? false : options.allowUnverifiedPrevouts);
            const validation = validateFundedCurrencyTransfer(chainId, fundedTxHex, combinedUnfundedTxHex, changeAddress, utxo_lib_1.networks.verus, verifiedFundingUtxos);
            if (!validation.valid)
                throw new Error(validation.message);
            const expectedSent = VerusIdInterface.getExpectedSentFromCurrencyTransferOutputs(currencyTransferOutputs);
            const deltas = new Map();
            VerusIdInterface.validateCurrencyTransferSent(validation, expectedSent);
            VerusIdInterface.validateFees(validation, expectedExplicitFees, chainId, feeLimit);
            VerusIdInterface.addValidationFeesToDeltas(validation, deltas);
            VerusIdInterface.addValidationSentToDeltas(validation, deltas);
            const completeIdentityUpdate = VerusIdInterface.completeIdentityUpdateTransaction(fundedTxHex, verifiedFundingUtxos, preparedIdentityUpdate.identityTransaction, preparedIdentityUpdate.vout);
            verifiedFundingUtxos.push(VerusIdInterface.getIdentityDefinitionUtxo(preparedIdentityUpdate.identityAddress, preparedIdentityUpdate.identityTransaction, preparedIdentityUpdate.vout, identityTransactionHeight));
            const fundingApproval = (0, updateFundingVerification_1.createIdentityUpdateFundingApproval)({
                txHex: completeIdentityUpdate, unfundedTxHex: combinedUnfundedTxHex,
                systemId: chainId, changeAddress, nativeFee: ((_c = validation.fees) === null || _c === void 0 ? void 0 : _c[chainId]) || "0",
                fees: Object.assign({}, validation.fees), explicitFees: Object.fromEntries([...expectedExplicitFees].map(([id, value]) => [id, value.toFixed(0)])),
                maxFee: (0, updateFundingVerification_1.identityUpdateFeeCap)(feeLimit),
                identity: { txid: preparedIdentityUpdate.identityTransaction.getId(), outputIndex: preparedIdentityUpdate.vout,
                    identityAddress: preparedIdentityUpdate.identityAddress },
            }, verifiedFundingUtxos, options.allowUnverifiedPrevouts === true, {
                chainId, nextBlockHeight: preparedIdentityUpdate.height + 1,
            });
            return {
                hex: completeIdentityUpdate,
                utxos: verifiedFundingUtxos,
                identity: preparedIdentityUpdate.identityOnOutput,
                deltas,
                fundingApproval
            };
        });
    }
    createRevokeIdentityTransaction(_identity_1, changeAddress_1, rawIdentityTransaction_1, identityTransactionHeight_1, utxoList_1, chainIAddr_1) {
        return __awaiter(this, arguments, void 0, function* (_identity, changeAddress, rawIdentityTransaction, identityTransactionHeight, utxoList, chainIAddr, fee = 0.0001, fundRawTransactionResult, currentHeight, allowUnverifiedPrevouts = false) {
            (0, fundingVerification_1.assertUnverifiedPrevoutsAllowed)(allowUnverifiedPrevouts);
            const identity = (0, requestSnapshot_1.snapshotRequestValue)(_identity);
            identity.clearContentMultiMap();
            identity.revoke();
            return this.createUpdateIdentityTransaction(identity, changeAddress, rawIdentityTransaction, identityTransactionHeight, utxoList, chainIAddr, fee, fundRawTransactionResult, currentHeight, undefined, true, false, allowUnverifiedPrevouts);
        });
    }
    createRecoverIdentityTransaction(_identity_1, changeAddress_1, rawIdentityTransaction_1, identityTransactionHeight_1, utxoList_1, chainIAddr_1) {
        return __awaiter(this, arguments, void 0, function* (_identity, changeAddress, rawIdentityTransaction, identityTransactionHeight, utxoList, chainIAddr, fee = 0.0001, fundRawTransactionResult, currentHeight, allowUnverifiedPrevouts = false) {
            (0, fundingVerification_1.assertUnverifiedPrevoutsAllowed)(allowUnverifiedPrevouts);
            const identity = (0, requestSnapshot_1.snapshotRequestValue)(_identity);
            identity.clearContentMultiMap();
            identity.unrevoke();
            return this.createUpdateIdentityTransaction(identity, changeAddress, rawIdentityTransaction, identityTransactionHeight, utxoList, chainIAddr, fee, fundRawTransactionResult, currentHeight, undefined, true, false, allowUnverifiedPrevouts);
        });
    }
    /**
     *
     * @param unsignedTxHex The unsigned transaction hex
     * @param inputs A list of UTXOs that are being used as inputs for the transaction, in the order they appear in the unsigned tx
     * @param keys A list of WIF keys that correspond to the UTXOs in the inputs list, each utxo will be signed with each key in the list at the position of the utxo in the inputs list
     */
    signUpdateIdentityTransaction(unsignedTxHex, inputs, keys, fundingApproval, lockContext) {
        (0, updateLimits_1.validateIdentityUpdateTransactionSize)(unsignedTxHex);
        const utxos = getUtxos(inputs);
        if (fundingApproval)
            (0, updateFundingVerification_1.verifyIdentityUpdateFunding)(fundingApproval, unsignedTxHex, utxos, lockContext);
        const txb = utxo_lib_1.smarttxs.getFundedTxBuilder(unsignedTxHex, utxo_lib_1.networks.verus, utxos.map(x => Buffer.from(x.script, 'hex')));
        for (let i = 0; i < keys.length; i++) {
            if (utxos[i] && keys[i] && Array.isArray(keys[i]) && keys[i].length > 0) {
                const keysForInput = keys[i];
                for (let j = 0; j < keysForInput.length; j++) {
                    if (keysForInput[j]) {
                        const keyPair = utxo_lib_1.ECPair.fromWIF(keysForInput[j], utxo_lib_1.networks.verus);
                        txb.sign(i, keyPair, null, utxo_lib_1.Transaction.SIGHASH_ALL, utxos[i].satoshis);
                    }
                }
            }
        }
        const signedHex = txb.build().toHex();
        (0, updateLimits_1.validateIdentityUpdateTransactionSize)(signedHex);
        if (fundingApproval)
            (0, updateFundingVerification_1.verifyIdentityUpdateFunding)(fundingApproval, signedHex, utxos, lockContext);
        return signedHex;
    }
    createGenericEnvelope(EnvelopeClass, params, primaryAddrWif, getIdentityResult, currentHeight) {
        return __awaiter(this, void 0, void 0, function* () {
            // Signing uses the system carried in the envelope.
            const req = new EnvelopeClass(params);
            if (primaryAddrWif) {
                return this.signGenericEnvelope(req, primaryAddrWif, getIdentityResult, currentHeight);
            }
            else
                return req;
        });
    }
    signGenericEnvelope(request, primaryAddrWif, getIdentityResult, currentHeight) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a, _b, _c, _d, _e, _f;
            request.setSigned();
            let height = currentHeight;
            if (height == null) {
                height = yield this.getCurrentHeight();
            }
            if (request.signature == null) {
                throw new Error("Require VerifiableSignatureData to be filled in, without signatureAsVch to sign.");
            }
            if (((_a = request.signature) === null || _a === void 0 ? void 0 : _a.hasBoundHashes()) || ((_b = request.signature) === null || _b === void 0 ? void 0 : _b.hasStatements()) || ((_c = request.signature) === null || _c === void 0 ? void 0 : _c.hasVdxfKeys()) || ((_d = request.signature) === null || _d === void 0 ? void 0 : _d.hasVdxfKeyNames())) {
                throw new Error("Bound hashes, statements, and vdxfkeys in signature not yet supported.");
            }
            const sig = yield this.signHash((_e = request.signature) === null || _e === void 0 ? void 0 : _e.identityID.toIAddress(), request.getDetailsIdentitySignatureHash(height), primaryAddrWif, getIdentityResult, height, (_f = request.signature) === null || _f === void 0 ? void 0 : _f.systemID.toIAddress());
            request.signature.signatureAsVch = Buffer.from(sig, 'base64');
            return request;
        });
    }
    verifyGenericEnvelope(envelope, getIdentityResult, chainIAddr, sigBlockTime) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!envelope.isSigned())
                return false;
            const verifiableSig = envelope.signature;
            const signature = yield this.readIdentitySignature(verifiableSig.identityID.toIAddress(), verifiableSig.signatureAsVch.toString('base64'), chainIAddr);
            if (!(yield this.verifySignatureCreationTime(envelope.hasCreatedAt() ? envelope.createdAt : undefined, signature.blockHeight, sigBlockTime))) {
                return false;
            }
            return this.verifyHashOrMessage(verifiableSig.identityID.toIAddress(), signature, envelope.getDetailsIdentitySignatureHash(signature.blockHeight), getIdentityResult);
        });
    }
    /** A shared signed-block time check; current request expiry is a separate policy. */
    verifySignatureCreationTime(createdAt, signedHeight, sigBlockTime) {
        return __awaiter(this, void 0, void 0, function* () {
            var _a;
            const timestamp = new bignumber_js_1.default((_a = createdAt === null || createdAt === void 0 ? void 0 : createdAt.toString()) !== null && _a !== void 0 ? _a : NaN);
            if (!timestamp.isInteger() || timestamp.isNegative() || timestamp.gt(Number.MAX_SAFE_INTEGER))
                return false;
            let blocktime = sigBlockTime;
            if (blocktime == null) {
                const response = yield this.interface.getBlock(signedHeight.toString());
                if (response.error)
                    throw new Error(response.error.message);
                blocktime = response.result.time;
            }
            return Number.isSafeInteger(blocktime) && blocktime >= 0 &&
                timestamp.minus(blocktime).abs().lte(IDENTITY_SIGNATURE_TIME_TOLERANCE_SECONDS);
        });
    }
    /** Fresh RPC authority evidence, scoped to this connection's signing system. */
    loadAuthorizationSignatureContext(envelope_1, sigBlockTime_1) {
        return __awaiter(this, arguments, void 0, function* (envelope, sigBlockTime, allowEncryptedDetails = false) {
            (0, handshake_1.validateAppAuthorizationEnvelope)(envelope, true, allowEncryptedDetails);
            const metadata = envelope.signature;
            const source = { rpc: this.interface, systemID: yield this.getChainId() };
            const delegate = {
                identityID: metadata.identityID.toIAddress(),
                systemID: metadata.systemID.toIAddress(),
            };
            if (delegate.systemID !== source.systemID)
                return undefined;
            const signature = yield this.getSignatureInfo(delegate.identityID, metadata.signatureAsVch.toString("base64"), delegate.systemID);
            const [signedIdentity, currentIdentity] = yield Promise.all([
                (0, identityAuthority_1.loadIdentityRevision)(source, delegate, signature.height),
                (0, identityAuthority_1.loadIdentityRevision)(source, delegate),
            ]);
            if (!(yield this.verifySignatureCreationTime(envelope.createdAt, signature.height, sigBlockTime)) ||
                !(0, authority_1.inspectAuthorizationSigners)(envelope, signedIdentity, currentIdentity).valid) {
                return undefined;
            }
            return { source, delegate, signedIdentity, currentIdentity };
        });
    }
    static validateUnsignedGenericRequest(request) {
        const details = request.details;
        if (!Array.isArray(details))
            return false;
        // Authorization is a distinct bootstrap operation. The legacy method name
        // must not let acceptUnsigned or unrelated detail types bypass admission.
        if ((0, handshake_1.hasAppAuthorizationRequest)(request)) {
            try {
                (0, handshake_1.validateAppAuthorizationRequest)(request);
                return true;
            }
            catch (_a) {
                return false;
            }
        }
        let authIndex = -1;
        let specialIndex = -1;
        let provisioningIndex = -1;
        let appEncryptIndex = -1;
        let walletBackupIndex = -1;
        for (let i = 0; i < details.length; i++) {
            const detail = details[i];
            if (detail instanceof verus_typescript_primitives_1.AuthenticationRequestOrdinalVDXFObject) {
                if (authIndex !== -1)
                    return false;
                authIndex = i;
            }
            if (detail instanceof verus_typescript_primitives_1.ProvisionIdentityDetailsOrdinalVDXFObject) {
                if (provisioningIndex !== -1)
                    return false;
                provisioningIndex = i;
            }
            if (detail instanceof verus_typescript_primitives_1.AppEncryptionRequestOrdinalVDXFObject) {
                if (appEncryptIndex !== -1)
                    return false;
                appEncryptIndex = i;
            }
            if (detail instanceof verus_typescript_primitives_1.CreateWalletBackupDetailsOrdinalVDXFObject) {
                if (walletBackupIndex !== -1)
                    return false;
                walletBackupIndex = i;
            }
            if (detail instanceof verus_typescript_primitives_1.VerusPayInvoiceDetailsOrdinalVDXFObject || detail instanceof verus_typescript_primitives_1.IdentityUpdateRequestOrdinalVDXFObject) {
                if (specialIndex !== -1)
                    return false;
                specialIndex = i;
            }
        }
        if (walletBackupIndex !== -1 && walletBackupIndex !== 0)
            return false;
        if (authIndex !== -1 && authIndex !== (walletBackupIndex === 0 ? 1 : 0))
            return false;
        if (specialIndex !== -1 && specialIndex !== details.length - 1)
            return false;
        if (provisioningIndex !== -1 && (authIndex === -1 || provisioningIndex < authIndex))
            return false;
        if (appEncryptIndex !== -1 && (authIndex === -1 || appEncryptIndex < authIndex))
            return false;
        return true;
    }
    /**
     * Shared admission for any delegated handler. Supply a complete effective
     * credential view and current wallet-control checks, then retain the handler's
     * own approval and response-encryption requirements. No failed grant falls
     * back to self-controlled or unscoped processing. A present delegator profile
     * throws UnsupportedDelegatorProfileError so the wallet can explain rejection.
     */
    verifyDelegatedGenericRequest(envelope, options) {
        return __awaiter(this, void 0, void 0, function* () {
            const request = (0, requestSnapshot_1.snapshotRequestValue)(envelope);
            const retained = (0, requestSnapshot_1.snapshotRequestValue)(options);
            const rpc = this.interface;
            const configuredChain = rpc.chain;
            try {
                if ((0, handshake_1.hasAppAuthorizationRequest)(request) || !request.hasAppOrDelegatorID() ||
                    !VerusIdInterface.validateUnsignedGenericRequest(request))
                    return false;
                const authentication = request.details.find(detail => detail instanceof verus_typescript_primitives_1.AuthenticationRequestOrdinalVDXFObject);
                // A historical signing block alone says nothing about freshness today.
                // Other request types must supply their own signed freshness contract.
                const isUnexpired = () => {
                    if (!authentication)
                        return typeof retained.verifyFreshness === "function";
                    (0, validation_1.validateAuthenticationExpiry)(authentication.data);
                    return true;
                };
                if (!isUnexpired())
                    return false;
                const context = yield this.loadAuthorizationSignatureContext(request, retained.sigBlockTime);
                if (!context)
                    return false;
                const grant = yield (0, grants_1.verifyDelegatedAppAuthorization)(Object.assign(Object.assign({}, retained), { delegate: context.delegate, appID: request.appOrDelegatorID.toIAddress(), verifyDelegatorProfile: (delegator) => __awaiter(this, void 0, void 0, function* () {
                        // The profile read follows every asynchronous handler freshness check,
                        // so a profile introduced during that check cannot be overlooked.
                        if (retained.verifyFreshness &&
                            (yield retained.verifyFreshness((0, requestSnapshot_1.snapshotRequestValue)(request))) !== true) {
                            throw new Error("Delegated request freshness check failed.");
                        }
                        yield (0, profile_1.assertAppDelegatorProfileSupportedV1)(context.source, delegator);
                    }), verifyAuthority: (credential) => __awaiter(this, void 0, void 0, function* () {
                        const original = yield (0, identityAuthority_1.loadIdentityRevisionAtOutpoint)(context.source, context.delegate, credential.data.originalRevision);
                        return (0, authority_1.inspectAuthorizationSigners)(request, context.signedIdentity, context.currentIdentity, original).valid;
                    }) }));
                if (grant == null)
                    return false;
                return isUnexpired() && this.interface === rpc &&
                    rpc.chain === configuredChain && envelope.toBuffer().equals(request.toBuffer()) &&
                    options.user.identityID === retained.user.identityID &&
                    options.user.systemID === retained.user.systemID;
            }
            catch (error) {
                if (error instanceof verus_typescript_primitives_1.UnsupportedDelegatorProfileError)
                    throw error;
                return false;
            }
        });
    }
    /**
     * Verify a completion against the retained request and the resolved final user.
     * For encrypted details, decryptDetails authenticates a detached descriptor and
     * returns raw plaintext: the single VDXF-tagged DataDescriptor used by the
     * wallet's response encryption. Its objectdata contains the original details
     * bytes. Private keys stay in the callback; the SDK unwraps and validates data.
     */
    verifyAppAuthorizationResponse(response, request, user, sigBlockTime, decryptDetails) {
        return __awaiter(this, void 0, void 0, function* () {
            const retainedResponse = (0, requestSnapshot_1.snapshotRequestValue)(response);
            const retainedRequest = (0, requestSnapshot_1.snapshotRequestValue)(request);
            const retainedUser = (0, requestSnapshot_1.snapshotRequestValue)(user);
            const rpc = this.interface;
            const configuredChain = rpc.chain;
            try {
                const encrypted = retainedResponse.detailsAreEncrypted();
                if (encrypted && typeof decryptDetails !== "function")
                    return false;
                const context = yield this.loadAuthorizationSignatureContext(retainedResponse, sigBlockTime, encrypted);
                if (!context)
                    return false;
                // Do not invoke private decryption for a response from an unexpected user.
                if (context.delegate.identityID !== retainedUser.identityID ||
                    context.delegate.systemID !== retainedUser.systemID)
                    return false;
                let readableResponse = retainedResponse;
                let currentIdentity = context.currentIdentity;
                if (encrypted) {
                    const descriptor = retainedResponse.details[0].data;
                    const decryptedBytes = yield decryptDetails((0, requestSnapshot_1.snapshotRequestValue)(descriptor));
                    // Authenticated encryption adds overhead. Bound parsing by the original
                    // ciphertext rather than trusting an arbitrarily large callback result.
                    if (!Buffer.isBuffer(decryptedBytes) || !decryptedBytes.length ||
                        decryptedBytes.length > descriptor.objectdata.length)
                        return false;
                    // Parsed buffers may share slices; detach before the later authority RPC.
                    const plaintext = Buffer.from(decryptedBytes);
                    // Reuse the wallet's existing single-descriptor VDXF framing. Consume
                    // all bytes and reject flags/encodings that serialization would repair.
                    const decoded = new verus_typescript_primitives_1.VDXFDataDescriptor();
                    if (decoded.fromBuffer(plaintext) !== plaintext.length ||
                        decoded.vdxfkey !== verus_typescript_primitives_1.DataDescriptorKey.vdxfid ||
                        !decoded.version.eq(vdxf_1.VDXF_OBJECT_DEFAULT_VERSION) ||
                        !decoded.dataDescriptor.isValid() ||
                        !decoded.dataDescriptor.flags.eq(decoded.dataDescriptor.calcFlags()) ||
                        decoded.dataDescriptor.hasEncryptedData() ||
                        !decoded.toBuffer().equals(plaintext))
                        return false;
                    const details = decoded.dataDescriptor.objectdata;
                    readableResponse = (0, requestSnapshot_1.snapshotRequestValue)(retainedResponse);
                    readableResponse.flags = readableResponse.flags.xor(verus_typescript_primitives_1.GenericResponse.FLAG_DETAILS_ARE_ENCRYPTED);
                    // Keep the authenticated metadata and MULTI_DETAILS flag. The signature
                    // belongs to retainedResponse; never verify it against this plaintext view.
                    if (readableResponse.setDetailsFromBuffer(details) !== details.length ||
                        !readableResponse.getDetailsBuffer().equals(details))
                        return false;
                    // Decryption may await wallet work. Refresh U's authority and parent
                    // before accepting, still checking signers against the signed ciphertext.
                    currentIdentity = yield (0, identityAuthority_1.loadIdentityRevision)(context.source, context.delegate);
                    if (!(0, authority_1.inspectAuthorizationSigners)(retainedResponse, context.signedIdentity, currentIdentity).valid)
                        return false;
                }
                // Parent constraints use RPC state rather than a caller-supplied label.
                (0, handshake_1.validateAppAuthorizationResponse)(readableResponse, retainedRequest, Object.assign(Object.assign({}, retainedUser), { parentID: currentIdentity.identity.parent }));
                // Revalidate before serialization so callback-time descriptor mutations
                // cannot disappear through the descriptor codec's flag normalization.
                (0, handshake_1.validateAppAuthorizationEnvelope)(response, true, encrypted);
                return this.interface === rpc && rpc.chain === configuredChain &&
                    response.toBuffer().equals(retainedResponse.toBuffer()) &&
                    request.toBuffer().equals(retainedRequest.toBuffer()) &&
                    user.identityID === retainedUser.identityID && user.systemID === retainedUser.systemID;
            }
            catch (_a) {
                return false;
            }
        });
    }
}
exports.default = VerusIdInterface;
