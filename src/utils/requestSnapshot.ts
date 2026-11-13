import { BN } from "bn.js";

/**
 * Detach mutable request data before RPC or callback awaits. Preserve primitive
 * classes and fields: serialization can normalize invalid inputs or omit fields
 * whose presence flags were not updated, hiding changes to the reviewed data.
 */
export function snapshotRequestValue<T>(value: T): T {
  if (value == null || typeof value !== "object") return value;
  if (Buffer.isBuffer(value)) return Buffer.from(value) as T;
  if (BN.isBN(value)) return value.clone() as T;
  if (Array.isArray(value)) return value.map(snapshotRequestValue) as T;

  if (value instanceof Map) {
    return new Map(
      [...value].map(([key, entry]) => [
        snapshotRequestValue(key),
        snapshotRequestValue(entry),
      ])
    ) as T;
  }

  const copy = Object.create(Object.getPrototypeOf(value));

  for (const key of Object.keys(value)) {
    copy[key] = snapshotRequestValue((value as any)[key]);
  }

  return copy;
}
