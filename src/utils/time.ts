import { MILLISECONDS_PER_SECOND } from "../constants/time";

/** Current Unix time in whole seconds, as used by signed request timestamps. */
export function getUnixTime(): number {
  return Math.floor(Date.now() / MILLISECONDS_PER_SECOND);
}
