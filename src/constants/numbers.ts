import BN from "bn.js";

/** BN form of JavaScript's exact-integer limit. Treat this value as read-only. */
export const MAX_SAFE_INTEGER_BN = new BN(Number.MAX_SAFE_INTEGER);
