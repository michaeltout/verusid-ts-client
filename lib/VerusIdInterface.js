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
const bignumber_js_1 = __importDefault(require("bignumber.js"));
const bn_js_1 = require("bn.js");
const { createUnfundedIdentityUpdate, validateFundedCurrencyTransfer, completeFundedIdentityUpdate } = utxo_lib_1.smarttxs;
const VRSC_I_ADDRESS = "i5w5MuNik5NtLcYmNzcvaoixooEebB6MGV";
const ID_SIG_VERSION = 2;
const ID_SIG_TYPE = 5;
const LOGIN_CONSENT_SIG_TIME_DIFF_THRESHOLD = 3600;
class VerusIdInterface {
    constructor(chain, baseURL, config) {
        this.interface = new verusd_rpc_ts_client_1.VerusdRpcInterface(chain, baseURL, config);
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
    getChainId() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.interface.chain === "VRSC" || this.interface.chain === VRSC_I_ADDRESS) {
                return VRSC_I_ADDRESS;
            }
            else {
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
            const sig = new utxo_lib_1.IdentitySignature(utxo_lib_1.networks.verus, ID_SIG_VERSION, ID_SIG_TYPE, height, null, chainId, identity.identity.identityaddress);
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
            return this.verifyHashOrMessage(iAddrOrIdentity, base64Sig, message, getIdentityResult, chainIAddr);
        });
    }
    verifyHash(iAddrOrIdentity, base64Sig, hash, getIdentityResult, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.verifyHashOrMessage(iAddrOrIdentity, base64Sig, hash, getIdentityResult, chainIAddr);
        });
    }
    verifyHashOrMessage(iAddrOrIdentity, base64Sig, hashOrMessage, getIdentityResult, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            let iAddress;
            let identityAtHeight;
            let chainId;
            try {
                utxo_lib_1.address.fromBase58Check(iAddrOrIdentity);
                iAddress = iAddrOrIdentity;
            }
            catch (e) {
                const _idres = yield this.interface.getIdentity(iAddrOrIdentity);
                if (_idres.error)
                    throw new Error(_idres.error.message);
                const identity = _idres.result;
                iAddress = identity.identity.identityaddress;
            }
            const sig = new utxo_lib_1.IdentitySignature(utxo_lib_1.networks.verus);
            if (chainIAddr != null)
                chainId = chainIAddr;
            else
                chainId = yield this.getChainId();
            sig.fromBuffer(Buffer.from(base64Sig, "base64"), 0, chainId, iAddress);
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
            const primaryAddresses = identityAtHeight.identity.primaryaddresses;
            const minsigs = identityAtHeight.identity.minimumsignatures;
            let sigs = 0;
            let signedBy = {};
            for (let j = 0; j < primaryAddresses.length; j++) {
                const signingAddress = primaryAddresses[j];
                if (signedBy[signingAddress])
                    continue;
                const sigRes = Buffer.isBuffer(hashOrMessage)
                    ? sig.verifyHashOffline(hashOrMessage, signingAddress)
                    : sig.verifyMessageOffline(hashOrMessage, signingAddress);
                if (sigRes.some((x) => x === true)) {
                    signedBy[signingAddress] = true;
                }
            }
            for (const key of Object.keys(signedBy)) {
                if (signedBy[key]) {
                    sigs += 1;
                }
                if (sigs == minsigs)
                    return true;
            }
            return false;
        });
    }
    getSignatureInfo(iAddrOrIdentity, base64Sig, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            let iAddress;
            let chainId;
            try {
                utxo_lib_1.address.fromBase58Check(iAddrOrIdentity);
                iAddress = iAddrOrIdentity;
            }
            catch (e) {
                const _idres = yield this.interface.getIdentity(iAddrOrIdentity);
                if (_idres.error)
                    throw new Error(_idres.error.message);
                const identity = _idres.result;
                iAddress = identity.identity.identityaddress;
            }
            if (chainIAddr != null)
                chainId = chainIAddr;
            else
                chainId = yield this.getChainId();
            const sig = new utxo_lib_1.IdentitySignature(utxo_lib_1.networks.verus);
            sig.fromBuffer(Buffer.from(base64Sig, "base64"), 0, chainId, iAddress);
            return {
                version: sig.version,
                hashtype: sig.hashType,
                height: sig.blockHeight,
            };
        });
    }
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
    signIdentityUpdateRequest(request, primaryAddrWif, getIdentityResult, currentHeight) {
        return __awaiter(this, void 0, void 0, function* () {
            request.setSigned();
            let height = currentHeight;
            if (height == null) {
                height = yield this.getCurrentHeight();
            }
            const sig = yield this.signHash(request.signingid.toAddress(), request.getDetailsHash(height), primaryAddrWif, getIdentityResult, height, request.systemid.toAddress());
            request.signature = new verus_typescript_primitives_1.VerusIDSignature({ signature: sig }, verus_typescript_primitives_1.IDENTITY_AUTH_SIG_VDXF_KEY, false);
            return request;
        });
    }
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
    createIdentityUpdateRequest(signingId, details, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            let chainId;
            if (chainIAddr != null)
                chainId = chainIAddr;
            else
                chainId = yield this.getChainId();
            const req = new verus_typescript_primitives_1.IdentityUpdateRequest({
                systemid: verus_typescript_primitives_1.IdentityID.fromAddress(chainId),
                signingid: verus_typescript_primitives_1.IdentityID.fromAddress(signingId),
                details,
            });
            if (primaryAddrWif) {
                return this.signIdentityUpdateRequest(req, primaryAddrWif, getIdentityResult, currentHeight);
            }
            else
                return req;
        });
    }
    verifyLoginConsentRequest(request, getIdentityResult, chainIAddr, sigBlockTime) {
        return __awaiter(this, void 0, void 0, function* () {
            const sigInfo = yield this.getSignatureInfo(request.signing_id, request.signature.signature, chainIAddr);
            let blocktime;
            if (sigBlockTime)
                blocktime = sigBlockTime;
            else {
                const _blockres = yield this.interface.getBlock(sigInfo.height.toString());
                if (_blockres.error)
                    throw new Error(_blockres.error.message);
                blocktime = _blockres.result.time;
            }
            if ((0, bignumber_js_1.default)(blocktime)
                .minus(request.challenge.created_at)
                .abs()
                .isGreaterThan(LOGIN_CONSENT_SIG_TIME_DIFF_THRESHOLD)) {
                return false;
            }
            return this.verifyHash(request.signing_id, request.signature.signature, request.getChallengeHash(sigInfo.height), getIdentityResult, chainIAddr);
        });
    }
    verifyIdentityUpdateRequest(request, getIdentityResult, chainIAddr, sigBlockTime) {
        return __awaiter(this, void 0, void 0, function* () {
            const sigInfo = yield this.getSignatureInfo(request.signingid.toAddress(), request.signature.signature, chainIAddr);
            let blocktime;
            if (sigBlockTime)
                blocktime = sigBlockTime;
            else {
                const _blockres = yield this.interface.getBlock(sigInfo.height.toString());
                if (_blockres.error)
                    throw new Error(_blockres.error.message);
                blocktime = _blockres.result.time;
            }
            if ((0, bignumber_js_1.default)(blocktime)
                .minus(request.details.createdat.toString())
                .abs()
                .isGreaterThan(LOGIN_CONSENT_SIG_TIME_DIFF_THRESHOLD)) {
                return false;
            }
            return this.verifyHash(request.signingid.toAddress(), request.signature.signature, request.getDetailsHash(sigInfo.height), getIdentityResult, chainIAddr);
        });
    }
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
    signIdentityUpdateResponse(response, primaryAddrWif, getIdentityResult, currentHeight) {
        return __awaiter(this, void 0, void 0, function* () {
            response.setSigned();
            let height = currentHeight;
            if (height == null) {
                height = yield this.getCurrentHeight();
            }
            const sig = yield this.signHash(response.signingid.toAddress(), response.getDetailsHash(height), primaryAddrWif, getIdentityResult, height, response.systemid.toAddress());
            response.signature = new verus_typescript_primitives_1.VerusIDSignature({ signature: sig }, verus_typescript_primitives_1.LOGIN_CONSENT_RESPONSE_SIG_VDXF_KEY, false);
            return response;
        });
    }
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
    createIdentityUpdateResponse(signingId, details, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            let chainId;
            if (chainIAddr != null)
                chainId = chainIAddr;
            else
                chainId = yield this.getChainId();
            const req = new verus_typescript_primitives_1.IdentityUpdateResponse({
                signingid: verus_typescript_primitives_1.IdentityID.fromAddress(signingId),
                systemid: verus_typescript_primitives_1.IdentityID.fromAddress(chainId),
                details
            });
            if (primaryAddrWif) {
                return this.signIdentityUpdateResponse(req, primaryAddrWif, getIdentityResult, currentHeight);
            }
            else
                return req;
        });
    }
    verifyResponse(response, getIdentityResult, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            const sigInfo = yield this.getSignatureInfo(response.signing_id, response.signature.signature, chainIAddr);
            return this.verifyHash(response.signing_id, response.signature.signature, response.getDecisionHash(sigInfo.height), getIdentityResult, chainIAddr);
        });
    }
    verifyIdentityUpdateResponse(response, getIdentityResult, chainIAddr, sigBlockTime) {
        return __awaiter(this, void 0, void 0, function* () {
            const sigInfo = yield this.getSignatureInfo(response.signingid.toAddress(), response.signature.signature, chainIAddr);
            let blocktime;
            if (sigBlockTime)
                blocktime = sigBlockTime;
            else {
                const _blockres = yield this.interface.getBlock(sigInfo.height.toString());
                if (_blockres.error)
                    throw new Error(_blockres.error.message);
                blocktime = _blockres.result.time;
            }
            if ((0, bignumber_js_1.default)(blocktime)
                .minus(response.details.createdat.toString())
                .abs()
                .isGreaterThan(LOGIN_CONSENT_SIG_TIME_DIFF_THRESHOLD)) {
                return false;
            }
            return this.verifyHash(response.signingid.toAddress(), response.signature.signature, response.getDetailsHash(sigInfo.height), getIdentityResult, chainIAddr);
        });
    }
    verifySignedSessionObject(object, getIdentityResult, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            const sigInfo = yield this.getSignatureInfo(object.signing_id, object.signature.signature, chainIAddr);
            return this.verifyHash(object.signing_id, object.signature.signature, object.getDataHash(sigInfo.height), getIdentityResult, chainIAddr);
        });
    }
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
    createSignedSessionObject(signingId, data, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            let chainId;
            if (chainIAddr != null)
                chainId = chainIAddr;
            else
                chainId = yield this.getChainId();
            const object = new verus_typescript_primitives_1.SignedSessionObject({
                signing_id: signingId,
                data,
                system_id: chainId
            });
            if (primaryAddrWif) {
                return this.signSessionObject(object, primaryAddrWif, getIdentityResult, currentHeight);
            }
            else
                return object;
        });
    }
    signLoginConsentResponse(response, primaryAddrWif, getIdentityResult, currentHeight) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.signLoginResponse(response, primaryAddrWif, getIdentityResult, currentHeight);
        });
    }
    createLoginConsentResponse(signingId, decision, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.createLoginResponse(signingId, decision, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr);
        });
    }
    verifyLoginConsentResponse(response, getIdentityResult, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.verifyResponse(response, getIdentityResult, chainIAddr);
        });
    }
    createVerusPayInvoice(details, signingIdIAddr, primaryAddrWif, getIdentityResult, currentHeight, chainIAddr) {
        return __awaiter(this, void 0, void 0, function* () {
            let chainId;
            if (chainIAddr != null)
                chainId = chainIAddr;
            else
                chainId = yield this.getChainId();
            const inv = new verus_typescript_primitives_1.VerusPayInvoice({
                details: details
            });
            if (signingIdIAddr && primaryAddrWif) {
                return this.signVerusPayInvoice(inv, signingIdIAddr, chainId, primaryAddrWif, getIdentityResult, currentHeight);
            }
            else
                return inv;
        });
    }
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
            const sig = new utxo_lib_1.IdentitySignature(utxo_lib_1.networks.verus, ID_SIG_VERSION, ID_SIG_TYPE, null, [Buffer.from(request.signature.signature, "base64")]);
            return sig.verifyHashOffline(request.getChallengeHash(), address)[0];
        });
    }
    // When using this function with a remote RPC server, PLEASE USE THE VERUSID DECODED FROM rawIdentityTransaction
    // AS YOUR BASE FOR PASSING IN THE IDENTITY PARAMETER (what you want to update). Otherwise if you're using an 
    // untrusted server to get your identity base and then editing, you could be updating an ID with data you don't
    // want to update.
    createUpdateIdentityTransaction(identity, changeAddress, rawIdentityTransaction, identityTransactionHeight, utxoList, chainIAddr, fee = 0.0001, fundRawTransactionResult, currentHeight, updateIdentityTransactionHex) {
        return __awaiter(this, void 0, void 0, function* () {
            let height = currentHeight;
            let chainId;
            if (height == null) {
                height = yield this.getCurrentHeight();
            }
            let vout = -1;
            let identityOnOutput;
            function getIdentityFromIdTx(transaction, idAddr, strict = false) {
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
                    if (!outMaster.eval_code.eq(new bn_js_1.BN(verus_typescript_primitives_1.EVALS.EVAL_NONE))) {
                        if (strict)
                            throw new Error("Unsupported master eval code " + outMaster.eval_code.toNumber() + " found in transaction output");
                        continue;
                    }
                    // Notary evidence eval codes are supported even in strict mode to allow for data included in the transaction as a result of 
                    // a signdata style updateidentity request. The data itself isn't verified and must be clearly displayed to the user, or the app
                    // must verify that the key the data is under is indeed in the request signer's namespace
                    if (!outParams.eval_code.eq(new bn_js_1.BN(verus_typescript_primitives_1.EVALS.EVAL_IDENTITY_PRIMARY))) {
                        if (strict && !outParams.eval_code.eq(new bn_js_1.BN(verus_typescript_primitives_1.EVALS.EVAL_NOTARY_EVIDENCE))) {
                            throw new Error("Unsupported params eval code " + outParams.eval_code.toNumber() + " found in transaction output");
                        }
                        continue;
                    }
                    if (strict && id != null)
                        throw new Error("Multiple identity outputs found in transaction");
                    id = new verus_typescript_primitives_1.Identity();
                    id.fromBuffer(outParams.getParamObject());
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
            const identityTransaction = utxo_lib_1.Transaction.fromHex(rawIdentityTransaction, utxo_lib_1.networks.verus);
            let unfundedTxHex;
            let identityAddress;
            if (identity instanceof verus_typescript_primitives_1.Identity) {
                // If identity is an identity object, assume that the object can be used at the output and that the user filled it in correctly
                identity.upgradeVersion();
                unfundedTxHex = createUnfundedIdentityUpdate(identity.toBuffer().toString('hex'), utxo_lib_1.networks.verus, height + 20);
                identityAddress = identity.getIdentityAddress();
                const identityFromIdTx = getIdentityFromIdTx(identityTransaction, identityAddress);
                vout = identityFromIdTx.vout;
                identityOnOutput = identity;
            }
            else if (identity instanceof verus_typescript_primitives_1.IdentityUpdateRequestDetails) {
                // If identity is an identityupdaterequest, that only contains a partial identity with the changes the user wants to make, so we 
                // need to fill in the rest of the ID in a way that doesn't trust the server without verification
                if (identity.txid && identity.txid !== identityTransaction.getId()) {
                    throw new Error("Identity update request txid does not match the txid of the identity transaction");
                }
                ;
                if (updateIdentityTransactionHex) {
                    unfundedTxHex = updateIdentityTransactionHex;
                }
                else {
                    const idCliJson = identity.toCLIJson();
                    const hexRes = (yield this.interface.updateIdentity(idCliJson, true));
                    if (hexRes.error)
                        throw new Error(hexRes.error.message);
                    else
                        unfundedTxHex = hexRes.result;
                }
                const unfundedTx = utxo_lib_1.Transaction.fromHex(unfundedTxHex, utxo_lib_1.networks.verus);
                unfundedTx.ins = [];
                unfundedTxHex = unfundedTx.toHex();
                identityAddress = identity.getIdentityAddress();
                const detailsFromRawTransaction = getIdentityFromIdTx(identityTransaction, identityAddress);
                vout = detailsFromRawTransaction.vout;
                const identityFromServer = getIdentityFromIdTx(unfundedTx, identityAddress, true).identity;
                const identityFromRawTransaction = detailsFromRawTransaction.identity;
                const identityFromRawTransactionJson = identityFromRawTransaction.toJson();
                identityOnOutput = identityFromServer;
                const partialIdentity = identity.identity;
                const serverIdentityJson = identityFromServer.toJson();
                const partialIdentityJson = partialIdentity.toJson();
                const changedKeys = Object.keys(partialIdentityJson);
                // Compare keys that were both changed and unchanged to ensure that changes are the same in funded tx from server
                let serverChangedKeysComp = {};
                let serverUnchangedKeysComp = {};
                let fromTxUnchangedKeysComp = {};
                // Separate out changed keys and unchanged keys, keeping name in all categories as it
                // should never be null or changed
                for (const key of Object.keys(identityFromRawTransactionJson)) {
                    if (key === 'name') {
                        serverChangedKeysComp[key] = serverIdentityJson[key];
                        serverUnchangedKeysComp[key] = serverIdentityJson[key];
                        fromTxUnchangedKeysComp[key] = identityFromRawTransactionJson[key];
                    }
                    else if (changedKeys.includes(key)) {
                        serverChangedKeysComp[key] = serverIdentityJson[key];
                    }
                    else {
                        serverUnchangedKeysComp[key] = serverIdentityJson[key];
                        fromTxUnchangedKeysComp[key] = identityFromRawTransactionJson[key];
                    }
                }
                const serverKeysChangedCompJson = serverChangedKeysComp;
                const serverKeysUnchangedCompJson = serverUnchangedKeysComp;
                const fromTxKeysUnchangedCompJson = fromTxUnchangedKeysComp;
                // Ignore cmm fields that contained the "data" field because we can't establish if the cmm and/or encryption was 
                // done correctly yet
                if (identity.containsSignData()) {
                    const signDataKeys = identity.signdatamap.keys();
                    if (serverKeysChangedCompJson.contentmultimap) {
                        for (const key of signDataKeys) {
                            delete serverKeysChangedCompJson.contentmultimap[key];
                        }
                    }
                    else
                        throw new Error("Expected cmm in identity update request");
                }
                else if (unfundedTx.outs.length > 1) {
                    // Outputs without signdata should only have an identity output and nothing else
                    throw new Error("Expected only one output in identity update request");
                }
                // Create partialidentity from the server identity json, taking only keys that were submitted to be modified,
                // and then serialize it and compare it to the partial identity that was submitted, to ensure they are the same.
                const serverPartialIdChangedComp = verus_typescript_primitives_1.PartialIdentity.fromJson(serverKeysChangedCompJson);
                if (serverPartialIdChangedComp.toBuffer().toString('hex') !== partialIdentity.toBuffer().toString('hex')) {
                    throw new Error("Identity update request changes do not appear to match the changes in the identity transaction, got " +
                        JSON.stringify(serverPartialIdChangedComp.toJson()) +
                        " expected " +
                        JSON.stringify(partialIdentity.toJson()));
                }
                const serverPartialIdUnchangedComp = verus_typescript_primitives_1.PartialIdentity.fromJson(serverKeysUnchangedCompJson);
                const fromTxPartialIdUnchangedComp = verus_typescript_primitives_1.PartialIdentity.fromJson(fromTxKeysUnchangedCompJson);
                if (serverPartialIdUnchangedComp.toBuffer().toString('hex') !== fromTxPartialIdUnchangedComp.toBuffer().toString('hex')) {
                    throw new Error("Unchanged identity properties returned from server do not appear to match the unchanged values from the identity transaction, got " +
                        JSON.stringify(serverPartialIdUnchangedComp.toJson()) +
                        " expected " +
                        JSON.stringify(fromTxPartialIdUnchangedComp.toJson()));
                }
            }
            else
                throw new Error("Invalid identity type");
            let fundedTxHex;
            if (utxoList == null) {
                fundedTxHex = unfundedTxHex;
            }
            else if (fundRawTransactionResult == null) {
                const _fundRawTxRes = yield this.interface.fundRawTransaction(unfundedTxHex, utxoList.map(utxo => {
                    return {
                        voutnum: utxo.outputIndex,
                        txid: utxo.txid,
                    };
                }), changeAddress, fee);
                if (_fundRawTxRes.error)
                    throw new Error("Couldn't fund raw transaction");
                else
                    fundedTxHex = _fundRawTxRes.result.hex;
            }
            else
                fundedTxHex = fundRawTransactionResult.hex;
            if (chainIAddr != null)
                chainId = chainIAddr;
            else
                chainId = yield this.getChainId();
            const deltas = new Map();
            if (utxoList) {
                const validation = validateFundedCurrencyTransfer(chainId, fundedTxHex, unfundedTxHex, changeAddress, utxo_lib_1.networks.verus, utxoList);
                if (!validation.valid)
                    throw new Error(validation.message);
                else {
                    for (const key in validation.sent) {
                        if ((0, bignumber_js_1.default)(validation.sent[key]).isGreaterThan((0, bignumber_js_1.default)(0))) {
                            throw new Error("Cannot send currency and update ID.");
                        }
                    }
                    for (const key in validation.fees) {
                        if (deltas.has(key))
                            deltas.set(key, deltas.get(key).minus((0, bignumber_js_1.default)(validation.fees[key])));
                        else
                            deltas.set(key, (0, bignumber_js_1.default)(validation.fees[key]).multipliedBy((0, bignumber_js_1.default)(-1)));
                    }
                }
                ;
                const feeSatoshis = (0, bignumber_js_1.default)(fee).multipliedBy((0, bignumber_js_1.default)(10).pow((0, bignumber_js_1.default)(8)));
                deltas.forEach((value, key) => {
                    if ((key !== chainId || value.isGreaterThan(0)) || (key === chainId && value.multipliedBy(-1).isGreaterThan(feeSatoshis))) {
                        throw new Error("Incorrect fee.");
                    }
                });
                const fundedTx = utxo_lib_1.Transaction.fromHex(fundedTxHex, utxo_lib_1.networks.verus);
                const utxosUsed = [];
                // Add funding UTXOs to utxosUsed
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
                const txid = identityTransaction.getId();
                // Add ID defintion to identity update tx hex
                const completeIdentityUpdate = completeFundedIdentityUpdate(fundedTxHex, utxo_lib_1.networks.verus, utxoList.map(x => Buffer.from(x.script, 'hex')), {
                    hash: Buffer.from(txid, 'hex').reverse(),
                    index: vout,
                    script: identityTransaction.outs[vout].script,
                    sequence: 4294967295
                });
                // Add ID definition UTXO to utxosUsed
                utxosUsed.push({
                    address: identityAddress,
                    txid: txid,
                    outputIndex: vout,
                    script: identityTransaction.outs[vout].script.toString('hex'),
                    satoshis: 0,
                    height: identityTransactionHeight,
                    isspendable: 0,
                    blocktime: 0 // Filled in to avoid getblock call because blocktime is not currently checked for the ID definition utxo
                });
                return { hex: completeIdentityUpdate, utxos: utxosUsed, identity: identityOnOutput, deltas };
            }
            else
                return { hex: fundedTxHex, utxos: [], identity: identityOnOutput, deltas };
        });
    }
    createRevokeIdentityTransaction(_identity, changeAddress, rawIdentityTransaction, identityTransactionHeight, utxoList, chainIAddr, fee = 0.0001, fundRawTransactionResult, currentHeight) {
        return __awaiter(this, void 0, void 0, function* () {
            const identity = new verus_typescript_primitives_1.Identity();
            identity.fromBuffer(_identity.toBuffer());
            identity.clearContentMultiMap();
            identity.revoke();
            return this.createUpdateIdentityTransaction(identity, changeAddress, rawIdentityTransaction, identityTransactionHeight, utxoList, chainIAddr, fee, fundRawTransactionResult, currentHeight);
        });
    }
    createRecoverIdentityTransaction(_identity, changeAddress, rawIdentityTransaction, identityTransactionHeight, utxoList, chainIAddr, fee = 0.0001, fundRawTransactionResult, currentHeight) {
        return __awaiter(this, void 0, void 0, function* () {
            const identity = new verus_typescript_primitives_1.Identity();
            identity.fromBuffer(_identity.toBuffer());
            identity.clearContentMultiMap();
            identity.unrevoke();
            return this.createUpdateIdentityTransaction(identity, changeAddress, rawIdentityTransaction, identityTransactionHeight, utxoList, chainIAddr, fee, fundRawTransactionResult, currentHeight);
        });
    }
    /**
     *
     * @param unsignedTxHex The unsigned transaction hex
     * @param inputs A list of UTXOs that are being used as inputs for the transaction, in the order they appear in the unsigned tx
     * @param keys A list of WIF keys that correspond to the UTXOs in the inputs list, each utxo will be signed with each key in the list at the position of the utxo in the inputs list
     */
    signUpdateIdentityTransaction(unsignedTxHex, inputs, keys) {
        const txb = utxo_lib_1.smarttxs.getFundedTxBuilder(unsignedTxHex, utxo_lib_1.networks.verus, inputs.map(x => Buffer.from(x.script, 'hex')));
        for (let i = 0; i < keys.length; i++) {
            if (inputs[i] && keys[i] && Array.isArray(keys[i]) && keys[i].length > 0) {
                const keysForInput = keys[i];
                for (let j = 0; j < keysForInput.length; j++) {
                    if (keysForInput[j]) {
                        const keyPair = utxo_lib_1.ECPair.fromWIF(keysForInput[j], utxo_lib_1.networks.verus);
                        txb.sign(i, keyPair, null, utxo_lib_1.Transaction.SIGHASH_ALL, inputs[i].satoshis);
                    }
                }
            }
        }
        return txb.build().toHex();
    }
}
exports.default = VerusIdInterface;
