"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MAX_SAFE_INTEGER_BN = void 0;
const bn_js_1 = __importDefault(require("bn.js"));
/** BN form of JavaScript's exact-integer limit. Treat this value as read-only. */
exports.MAX_SAFE_INTEGER_BN = new bn_js_1.default(Number.MAX_SAFE_INTEGER);
