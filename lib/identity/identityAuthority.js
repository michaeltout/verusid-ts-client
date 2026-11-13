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
exports.MAX_IDENTITY_SIGNATURE_THRESHOLD = exports.MAX_IDENTITY_PRIMARY_AUTHORITIES = void 0;
exports.validateIdentityVersion = validateIdentityVersion;
exports.validateIdentityThreshold = validateIdentityThreshold;
exports.normalizeIdentityKeyID = normalizeIdentityKeyID;
exports.getIdentityPrimaryKeyIDs = getIdentityPrimaryKeyIDs;
exports.validateIdentityRevision = validateIdentityRevision;
exports.loadIdentityRevision = loadIdentityRevision;
exports.loadIdentityRevisionAtOutpoint = loadIdentityRevisionAtOutpoint;
const bn_js_1 = __importDefault(require("bn.js"));
const utxo_lib_1 = require("@bitgo/utxo-lib");
const verus_typescript_primitives_1 = require("verus-typescript-primitives");
const vdxf_1 = require("verus-typescript-primitives/dist/constants/vdxf");
const fundingPrimitives_1 = require("./fundingPrimitives");
exports.MAX_IDENTITY_PRIMARY_AUTHORITIES = 25;
exports.MAX_IDENTITY_SIGNATURE_THRESHOLD = 13;
const GET_IDENTITY_HISTORY = "getidentityhistory";
/** Check before upgrading, which would also promote invalid old versions. */
function validateIdentityVersion(version) {
    if (!bn_js_1.default.isBN(version) ||
        version.lt(verus_typescript_primitives_1.Identity.VERSION_FIRSTVALID) ||
        version.gt(verus_typescript_primitives_1.Identity.VERSION_LASTVALID)) {
        throw new Error("Unsupported identity version.");
    }
}
/** Share the daemon's threshold bounds between JSON authorities and typed identity builders. */
function validateIdentityThreshold(minimumSignatures, keyCount = exports.MAX_IDENTITY_PRIMARY_AUTHORITIES) {
    const valid = bn_js_1.default.isBN(minimumSignatures)
        ? minimumSignatures.gten(1) &&
            minimumSignatures.lten(exports.MAX_IDENTITY_SIGNATURE_THRESHOLD) &&
            minimumSignatures.lten(keyCount)
        : Number.isInteger(minimumSignatures) &&
            minimumSignatures >= 1 &&
            minimumSignatures <= exports.MAX_IDENTITY_SIGNATURE_THRESHOLD &&
            minimumSignatures <= keyCount;
    if (!valid) {
        throw new Error(`Identity signature threshold must be 1 to ${exports.MAX_IDENTITY_SIGNATURE_THRESHOLD} and no greater than its primary key count.`);
    }
}
/** Public-key and public-key-hash representations identify the same authority. */
function normalizeIdentityKeyID(primary, network = utxo_lib_1.networks.verus) {
    if (Buffer.isBuffer(primary) ||
        (typeof primary === "string" &&
            /^(?:(?:02|03)[0-9a-fA-F]{64}|04[0-9a-fA-F]{128})$/.test(primary))) {
        const publicKey = Buffer.isBuffer(primary)
            ? primary
            : Buffer.from(primary, "hex");
        // Curve validation is independent of address versions; ECPair requires a
        // complete network object even when only validating public-key bytes.
        utxo_lib_1.ECPair.fromPublicKeyBuffer(publicKey, utxo_lib_1.networks.verus);
        return utxo_lib_1.crypto.hash160(publicKey).toString("hex");
    }
    if (typeof primary !== "string") {
        throw new Error("Identity primary authority must be a public key or key hash.");
    }
    const decoded = (0, verus_typescript_primitives_1.fromBase58Check)(primary);
    if (decoded.version !== network.pubKeyHash ||
        decoded.hash.length !== vdxf_1.HASH160_BYTE_LENGTH ||
        decoded.hash.equals(Buffer.alloc(vdxf_1.HASH160_BYTE_LENGTH))) {
        throw new Error("Identity primary authority must be a nonnull public key or key hash.");
    }
    return decoded.hash.toString("hex");
}
/** Normalize primary membership without letting duplicate encodings inflate the threshold. */
function getIdentityPrimaryKeyIDs(primaryAddresses, minimumSignatures, network = utxo_lib_1.networks.verus) {
    if (!Array.isArray(primaryAddresses) ||
        primaryAddresses.length < 1 ||
        primaryAddresses.length > exports.MAX_IDENTITY_PRIMARY_AUTHORITIES ||
        primaryAddresses.some((primary) => typeof primary !== "string")) {
        throw new Error("Invalid identity primary authorities.");
    }
    if (!Number.isInteger(minimumSignatures)) {
        throw new Error("Identity signature threshold must be an integer.");
    }
    const keys = new Set(primaryAddresses.map((primary) => normalizeIdentityKeyID(primary, network)));
    validateIdentityThreshold(minimumSignatures, keys.size);
    return keys;
}
/** Validate RPC state and its source binding, returning normalized primary membership. */
function validateIdentityRevision(revision, binding) {
    var _a;
    (0, fundingPrimitives_1.validAddress)(binding.identityID, true);
    (0, fundingPrimitives_1.validAddress)(binding.systemID, true);
    if (!revision ||
        revision.systemID !== binding.systemID ||
        ((_a = revision.identity) === null || _a === void 0 ? void 0 : _a.identityaddress) !== binding.identityID) {
        throw new Error("The identity or lookup system does not match.");
    }
    const { version, flags } = revision.identity;
    if (!Number.isInteger(version) ||
        (revision.status !== "active" && revision.status !== "revoked")) {
        throw new Error("Unsupported identity state.");
    }
    validateIdentityVersion(new bn_js_1.default(version));
    (0, verus_typescript_primitives_1.assertUint32)(flags);
    const revoked = !new bn_js_1.default(flags).and(verus_typescript_primitives_1.IDENTITY_FLAG_REVOKED).isZero();
    if (revoked !== (revision.status === "revoked")) {
        throw new Error("Inconsistent identity revocation state.");
    }
    (0, verus_typescript_primitives_1.assertUint32)(revision.blockheight);
    (0, verus_typescript_primitives_1.assertUint32)(revision.vout);
    (0, verus_typescript_primitives_1.normalizeFixedLengthHex)(revision.txid, vdxf_1.HASH256_BYTE_LENGTH);
    return getIdentityPrimaryKeyIDs(revision.identity.primaryaddresses, revision.identity.minimumsignatures);
}
/** Always fetch current state anew when height is omitted; no authority cache. */
function loadIdentityRevision(source, binding, height) {
    return __awaiter(this, void 0, void 0, function* () {
        var _a;
        (0, fundingPrimitives_1.validAddress)(binding.systemID, true);
        (0, fundingPrimitives_1.validAddress)(binding.identityID, true);
        if (source.systemID !== binding.systemID) {
            throw new Error("Identity RPC is connected to a different system.");
        }
        if (height !== undefined)
            (0, verus_typescript_primitives_1.assertUint32)(height);
        const response = yield source.rpc.getIdentity(binding.identityID, height);
        if (response.error || !response.result) {
            throw new Error(((_a = response.error) === null || _a === void 0 ? void 0 : _a.message) || "Identity was not found.");
        }
        const revision = Object.assign(Object.assign({}, response.result), { systemID: source.systemID });
        validateIdentityRevision(revision, binding);
        if (height !== undefined && revision.blockheight > height) {
            throw new Error("Identity revision is newer than the requested height.");
        }
        return Object.assign(Object.assign({}, revision), { txid: (0, verus_typescript_primitives_1.normalizeFixedLengthHex)(revision.txid, vdxf_1.HASH256_BYTE_LENGTH) });
    });
}
// The existing RPC transport supports arbitrary ApiRequests, but has no typed
// getidentityhistory method. Keep this narrow adapter local to revision lookup.
class IdentityHistoryRequest extends verus_typescript_primitives_1.ApiRequest {
    constructor(chain, identityID, height) {
        super(chain, GET_IDENTITY_HISTORY);
        this.identityID = identityID;
        this.height = height;
    }
    getParams() {
        return [this.identityID, this.height, this.height];
    }
    toJson() {
        return {
            chain: this.chain,
            identityID: this.identityID,
            height: this.height,
        };
    }
}
/** Resolve the approved outpoint exactly, including multiple updates in one block. */
function loadIdentityRevisionAtOutpoint(source, binding, original) {
    return __awaiter(this, void 0, void 0, function* () {
        var _a, _b, _c;
        (0, verus_typescript_primitives_1.assertUint32)(original.lookupHeight);
        (0, verus_typescript_primitives_1.assertUint32)(original.vout);
        const txid = (0, verus_typescript_primitives_1.normalizeFixedLengthHex)(original.txid, vdxf_1.HASH256_BYTE_LENGTH);
        const atHeight = yield loadIdentityRevision(source, binding, original.lookupHeight);
        if (atHeight.txid === txid && atHeight.vout === original.vout)
            return atHeight;
        const response = yield source.rpc.request(new IdentityHistoryRequest(source.rpc.chain, binding.identityID, original.lookupHeight));
        if (response.error || !Array.isArray((_a = response.result) === null || _a === void 0 ? void 0 : _a.history)) {
            throw new Error(((_b = response.error) === null || _b === void 0 ? void 0 : _b.message) || "Identity revision history is unavailable.");
        }
        const matches = response.result.history.filter((entry) => {
            var _a, _b;
            return ((_b = (_a = entry === null || entry === void 0 ? void 0 : entry.output) === null || _a === void 0 ? void 0 : _a.txid) === null || _b === void 0 ? void 0 : _b.toLowerCase()) === txid &&
                entry.output.voutnum === original.vout;
        });
        if (matches.length !== 1 || matches[0].height !== original.lookupHeight) {
            throw new Error("The exact original identity revision was not found.");
        }
        const entry = matches[0];
        (0, verus_typescript_primitives_1.assertUint32)((_c = entry.identity) === null || _c === void 0 ? void 0 : _c.flags);
        const revision = {
            identity: entry.identity,
            status: new bn_js_1.default(entry.identity.flags).and(verus_typescript_primitives_1.IDENTITY_FLAG_REVOKED).isZero()
                ? "active"
                : "revoked",
            blockheight: entry.height,
            txid,
            vout: entry.output.voutnum,
            systemID: source.systemID,
            // Historical entries do not report wallet-local capabilities. They must
            // never be interpreted as proof that this wallet controls the identity.
            cansignfor: false,
            canspendfor: false,
        };
        validateIdentityRevision(revision, binding);
        return revision;
    });
}
