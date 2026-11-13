"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SECONDS_PER_DAY = exports.SECONDS_PER_HOUR = exports.SECONDS_PER_MINUTE = exports.MILLISECONDS_PER_SECOND = void 0;
/** Shared time units; feature-specific deadlines belong with their policies. */
exports.MILLISECONDS_PER_SECOND = 1000;
exports.SECONDS_PER_MINUTE = 60;
exports.SECONDS_PER_HOUR = 60 * exports.SECONDS_PER_MINUTE;
exports.SECONDS_PER_DAY = 24 * exports.SECONDS_PER_HOUR;
