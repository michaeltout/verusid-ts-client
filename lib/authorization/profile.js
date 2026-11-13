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
exports.assertAppDelegatorProfileSupportedV1 = assertAppDelegatorProfileSupportedV1;
const verus_typescript_primitives_1 = require("verus-typescript-primitives");
const identityContent_1 = require("../identity/identityContent");
/**
 * Reject future profiles without interpreting their values or caching absence.
 * Call again on continuation and immediately before sensitive execution. The
 * unsupported error propagates so the wallet can explain this policy rejection.
 */
function assertAppDelegatorProfileSupportedV1(source, binding) {
    return __awaiter(this, void 0, void 0, function* () {
        const { revision } = yield (0, identityContent_1.loadCurrentIdentityContent)(source, binding, verus_typescript_primitives_1.DELEGATOR_PROFILE_VDXF_KEY.vdxfid);
        // Filtered reads may include siblings; only this reserved outer key matters.
        (0, verus_typescript_primitives_1.assertDelegatorProfileSupportedV1)(revision.identity.contentmultimap);
    });
}
