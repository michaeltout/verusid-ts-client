/**
 * Detach mutable request data before RPC or callback awaits. Preserve primitive
 * classes and fields: serialization can normalize invalid inputs or omit fields
 * whose presence flags were not updated, hiding changes to the reviewed data.
 */
export declare function snapshotRequestValue<T>(value: T): T;
