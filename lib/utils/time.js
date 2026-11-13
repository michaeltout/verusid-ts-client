"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getUnixTime = getUnixTime;
const time_1 = require("../constants/time");
/** Current Unix time in whole seconds, as used by signed request timestamps. */
function getUnixTime() {
    return Math.floor(Date.now() / time_1.MILLISECONDS_PER_SECOND);
}
