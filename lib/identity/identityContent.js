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
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadCurrentIdentityContent = loadCurrentIdentityContent;
const verus_typescript_primitives_1 = require("verus-typescript-primitives");
const vdxf_1 = require("verus-typescript-primitives/dist/constants/vdxf");
const identityAuthority_1 = require("./identityAuthority");
const fundingPrimitives_1 = require("./fundingPrimitives");
const CONFIRMED_BLOCK_VERBOSITY = 1;
const FIRST_CONTENT_HEIGHT = 0;
const DEFAULT_TX_PROOF_HEIGHT = 0;
function confirmedBlockHash(rpc, height) {
    return __awaiter(this, void 0, void 0, function* () {
        const response = yield rpc.getBlock(String(height), CONFIRMED_BLOCK_VERBOSITY);
        const block = response.result;
        if (response.error ||
            !block ||
            typeof block === "string" ||
            block.height !== height ||
            !Number.isSafeInteger(block.confirmations) ||
            block.confirmations < 1) {
            throw new Error("A confirmed active block is required to read identity content.");
        }
        return (0, verus_typescript_primitives_1.normalizeFixedLengthHex)(block.hash, vdxf_1.HASH256_BYTE_LENGTH);
    });
}
/**
 * Load complete removal-aware content for a key at a confirmed chain revision.
 * Recheck the active block and identity outpoint before returning the snapshot.
 * Values are not decoded and results are not cached; consumers apply their own
 * credential/profile policy to the raw CMM after this provenance check.
 */
function loadCurrentIdentityContent(source, binding, vdxfKey) {
    return __awaiter(this, void 0, void 0, function* () {
        const { rpc, systemID } = source;
        const chain = rpc.chain;
        const expected = Object.assign({}, binding);
        const capturedSource = { rpc, systemID };
        const sourceUnchanged = () => source.rpc === rpc &&
            source.systemID === systemID &&
            rpc.chain === chain &&
            binding.systemID === expected.systemID &&
            binding.identityID === expected.identityID;
        if (systemID !== expected.systemID) {
            throw new Error("Identity content must be read on the bound lookup system.");
        }
        (0, fundingPrimitives_1.validAddress)(expected.identityID, true);
        (0, fundingPrimitives_1.validAddress)(expected.systemID, true);
        (0, fundingPrimitives_1.validAddress)(vdxfKey, true);
        const infoResponse = yield rpc.getInfo();
        const info = infoResponse.result;
        if (infoResponse.error ||
            !info ||
            info.chainid !== systemID ||
            info.blocks < 1 ||
            !Number.isSafeInteger(info.longestchain) ||
            info.longestchain < 0 ||
            info.longestchain > info.blocks ||
            !sourceUnchanged()) {
            throw new Error("A synchronized RPC on the bound lookup system is required to read identity content.");
        }
        const readHeight = (0, verus_typescript_primitives_1.assertUint32)(info.blocks);
        const blockHash = yield confirmedBlockHash(rpc, readHeight);
        const contentResponse = yield rpc.getIdentityContent(expected.identityID, FIRST_CONTENT_HEIGHT, readHeight, false, DEFAULT_TX_PROOF_HEIGHT, vdxfKey);
        const content = contentResponse.result;
        if (contentResponse.error ||
            !content ||
            content.fromheight !== FIRST_CONTENT_HEIGHT ||
            content.toheight !== readHeight ||
            !sourceUnchanged()) {
            throw new Error("A complete effective identity content read is required.");
        }
        const revision = Object.assign(Object.assign({}, content), { systemID });
        (0, identityAuthority_1.validateIdentityRevision)(revision, expected);
        const hasEffectiveCmm = Object.prototype.hasOwnProperty.call(content.identity, "contentmultimap");
        if (revision.blockheight < 1 ||
            revision.blockheight > readHeight ||
            (!hasEffectiveCmm &&
                revision.identity.version >= verus_typescript_primitives_1.Identity.VERSION_PBAAS.toNumber())) {
            throw new Error("Identity content is missing its confirmed revision or effective CMM.");
        }
        if (!hasEffectiveCmm) {
            // Core omits CMM for legacy identities, which cannot carry multimap content.
            // Normalize a copy so the caller's RPC response remains unchanged.
            revision.identity = Object.assign(Object.assign({}, revision.identity), { contentmultimap: {} });
        }
        const effectiveCmm = revision.identity.contentmultimap;
        if (effectiveCmm == null ||
            typeof effectiveCmm !== "object" ||
            (Object.getPrototypeOf(effectiveCmm) !== Object.prototype &&
                Object.getPrototypeOf(effectiveCmm) !== null)) {
            throw new Error("Expected a raw effective identity CMM object.");
        }
        const [currentBlockHash, current] = yield Promise.all([
            confirmedBlockHash(rpc, readHeight),
            (0, identityAuthority_1.loadIdentityRevision)(capturedSource, expected),
        ]);
        if (!sourceUnchanged() ||
            currentBlockHash !== blockHash ||
            current.txid !== revision.txid.toLowerCase() ||
            current.vout !== revision.vout ||
            current.blockheight !== revision.blockheight) {
            throw new Error("Identity state changed while reading effective content; retry the read.");
        }
        return { revision, readHeight, blockHash };
    });
}
