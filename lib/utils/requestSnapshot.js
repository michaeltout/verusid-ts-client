"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.snapshotRequestValue = snapshotRequestValue;
const bn_js_1 = require("bn.js");
/**
 * Detach mutable request data before RPC or callback awaits. Preserve primitive
 * classes and fields: serialization can normalize invalid inputs or omit fields
 * whose presence flags were not updated, hiding changes to the reviewed data.
 */
function snapshotRequestValue(value) {
    if (value == null || typeof value !== "object")
        return value;
    if (Buffer.isBuffer(value))
        return Buffer.from(value);
    if (bn_js_1.BN.isBN(value))
        return value.clone();
    if (Array.isArray(value))
        return value.map(snapshotRequestValue);
    if (value instanceof Map) {
        return new Map([...value].map(([key, entry]) => [
            snapshotRequestValue(key),
            snapshotRequestValue(entry),
        ]));
    }
    const copy = Object.create(Object.getPrototypeOf(value));
    for (const key of Object.keys(value)) {
        copy[key] = snapshotRequestValue(value[key]);
    }
    return copy;
}
