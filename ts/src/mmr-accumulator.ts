// src/mmr-accumulator.ts

// Copyright (c) 2026 bitcoincashautist
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * MMR Accumulator for Simplified Header Verification (SHV) clients.
 *
 * Functional implementation using immutable state objects, designed to
 * complement the LibAuth library's functional paradigm.
 *
 * State structure:
 *   { leafCount: bigint, peaks: Uint8Array[] }
 *
 * - leafCount: Number of leaves in the MMR (BigInt for 64-bit support)
 * - peaks: Array of 32-byte hashes, ordered tallest to shortest
 *
 * Example with 11 leaves (binary 1011):
 *   peaks[0]: height-3 peak covering leaves 0-7
 *   peaks[1]: height-1 peak covering leaves 8-9
 *   peaks[2]: height-0 peak (leaf 10 itself)
 */

import { hash256 } from "@bitauth/libauth";

// ============================================================================
// Types
// ============================================================================

/**
 * A 32-byte hash value.
 */
export type Hash = Uint8Array;

/**
 * MMR Accumulator state.
 * Immutable by convention; all operations return new state objects.
 */
export interface AccumulatorState {
    /** Number of leaves in the MMR */
    readonly leafCount: bigint;
    /** Peak hashes, ordered from tallest (leftmost) to shortest (rightmost) */
    readonly peaks: readonly Hash[];
}

/**
 * Result of getMountain(): identifies which peak covers a given leaf.
 */
export interface MountainInfo {
    /** Height of the mountain (number of levels above leaves) */
    readonly mountainHeight: number;
    /** Index into the peaks array */
    readonly peakIndex: number;
}

// ============================================================================
// Bit manipulation helpers
// ============================================================================

/**
 * Count set bits in a BigInt.
 */
export function popcount(n: bigint): number {
    let count = 0;
    let remaining = n;
    while (remaining > 0n) {
        count += Number(remaining & 1n);
        remaining >>= 1n;
    }
    return count;
}

/**
 * Count trailing one bits in a BigInt.
 */
export function countTrailingOnes(n: bigint): number {
    let count = 0;
    let remaining = n;
    while ((remaining & 1n) === 1n) {
        count++;
        remaining >>= 1n;
    }
    return count;
}

/**
 * Count trailing zero bits in a BigInt.
 * Returns 64 if n is 0 (matching C++ behavior for uint64_t).
 */
export function countTrailingZeros(n: bigint): number {
    if (n === 0n) return 64;
    let count = 0;
    let remaining = n;
    while ((remaining & 1n) === 0n) {
        count++;
        remaining >>= 1n;
    }
    return count;
}

/**
 * Return the bit width (position of highest set bit + 1).
 * Returns 0 if n is 0.
 */
export function bitWidth(n: bigint): number {
    let width = 0;
    let remaining = n;
    while (remaining > 0n) {
        width++;
        remaining >>= 1n;
    }
    return width;
}

// ============================================================================
// Hashing
// ============================================================================

/**
 * Compute the merged node hash (SHA256d of concatenated children).
 * This matches Bitcoin's Merkle tree node computation.
 */
export function merge(left: Uint8Array, right: Uint8Array): Hash {
    const concat = new Uint8Array(64);
    concat.set(left, 0);
    concat.set(right, 32);
    return hash256(concat);
}

/**
 * Compute the leaf hash for a block header.
 * This is the standard Bitcoin block hash (SHA256d).
 */
export function leaf(header: Uint8Array): Hash {
    if (header.length !== 80) {
        throw new Error(`header must be 80 bytes, got ${header.length}`);
    }
    return hash256(header);
}

// ============================================================================
// State creation
// ============================================================================

/**
 * Create an empty accumulator state.
 */
export function empty(): AccumulatorState {
    return { leafCount: 0n, peaks: [] };
}

/**
 * Create an accumulator state with validation.
 * @throws Error if peak count doesn't match popcount(leafCount)
 */
export function create(leafCount: bigint, peaks: readonly Uint8Array[]): AccumulatorState {
    if (leafCount < 0n) {
        throw new Error(`leafCount must be non-negative, got ${leafCount}`);
    }
    const expectedPeakCount = popcount(leafCount);
    if (peaks.length !== expectedPeakCount) {
        throw new Error(
            `leafCount ${leafCount} requires ${expectedPeakCount} peaks, got ${peaks.length}`
        );
    }
    for (const peak of peaks) {
        if (peak.length !== 32) {
            throw new Error(`peak must be 32 bytes, got ${peak.length}`);
        }
    }
    return {
        leafCount,
        peaks: peaks.map((p) => Uint8Array.from(p)),
    };
}

/**
 * Create a deep copy of a state.
 */
export function clone(state: AccumulatorState): AccumulatorState {
    return {
        leafCount: state.leafCount,
        peaks: state.peaks.map((p) => Uint8Array.from(p)),
    };
}

/**
 * Check if a state is empty.
 */
export function isEmpty(state: AccumulatorState): boolean {
    return state.leafCount === 0n;
}

/**
 * Get the number of peaks.
 */
export function peakCount(state: AccumulatorState): number {
    return state.peaks.length;
}

// ============================================================================
// Core operations
// ============================================================================

/**
 * Extend the accumulator with a new leaf.
 * Returns a new state; the original is not modified.
 *
 * The number of merges equals the trailing 1-bits in the current leaf count.
 */
export function extend(state: AccumulatorState, leafHash: Uint8Array): AccumulatorState {
    if (leafHash.length !== 32) {
        throw new Error(`leaf must be 32 bytes, got ${leafHash.length}`);
    }

    const mergeCount = countTrailingOnes(state.leafCount);

    // Copy peaks array
    const newPeaks: Hash[] = state.peaks.map((p) => Uint8Array.from(p));
    let current: Hash = Uint8Array.from(leafHash);

    // Merge with smallest peaks (from end)
    for (let i = 0; i < mergeCount; i++) {
        const peak = newPeaks.pop();
        if (!peak) {
            throw new Error("internal error: expected peak for merge");
        }
        current = merge(peak, current);
    }

    newPeaks.push(current);

    return {
        leafCount: state.leafCount + 1n,
        peaks: newPeaks,
    };
}

/**
 * Build an accumulator from an array of leaf hashes.
 */
export function build(leaves: readonly Uint8Array[]): AccumulatorState {
    let state = empty();
    for (const leafHash of leaves) {
        state = extend(state, leafHash);
    }
    return state;
}

/**
 * Compute the Bitcoin-style Merkle root.
 *
 * Bags peaks from smallest to largest, duplicating nodes as needed
 * to match heights before merging.
 *
 * Returns 32 zero bytes for an empty accumulator.
 */
export function getRoot(state: AccumulatorState): Hash {
    if (state.leafCount === 0n) {
        return new Uint8Array(32);
    }

    if (state.peaks.length === 1) {
        return Uint8Array.from(state.peaks[0]);
    }

    // Start with smallest peak
    let current: Hash = Uint8Array.from(state.peaks[state.peaks.length - 1]);
    let remaining = state.leafCount;
    let height = countTrailingZeros(remaining);

    // Work backwards through larger peaks
    for (let i = state.peaks.length - 1; i > 0; i--) {
        // Clear lowest set bit to find next peak's height
        remaining &= remaining - 1n;
        const nextHeight = countTrailingZeros(remaining);

        // Duplicate until heights match
        while (height < nextHeight) {
            current = merge(current, current);
            height++;
        }

        // Merge with next larger peak
        current = merge(state.peaks[i - 1], current);
        height++;
    }

    return current;
}

// ============================================================================
// Path computation
// ============================================================================

/**
 * Walk a Merkle path and compute the resulting hash.
 *
 * Index bits determine sibling orientation at each level:
 * - 1-bit: sibling is on the left
 * - 0-bit: sibling is on the right
 */
export function computePath(
    index: bigint,
    start: Uint8Array,
    siblings: readonly Uint8Array[]
): Hash {
    let current: Hash = Uint8Array.from(start);
    let idx = index;

    for (const sibling of siblings) {
        if ((idx & 1n) === 1n) {
            current = merge(sibling, current);
        } else {
            current = merge(current, sibling);
        }
        idx >>= 1n;
    }

    return current;
}

/**
 * Find the mountain (peak) containing a given leaf index.
 */
export function getMountain(leafIndex: bigint, leafCount: bigint): MountainInfo {
    let remaining = leafCount;
    let mountainStart = 0n;
    let mountainHeight = 0;
    let peakIndex = 0;

    while (remaining > 0n) {
        mountainHeight = bitWidth(remaining) - 1;
        const mountainSize = 1n << BigInt(mountainHeight);

        if (leafIndex < mountainStart + mountainSize) {
            break;
        }

        mountainStart += mountainSize;
        remaining -= mountainSize;
        peakIndex++;
    }

    return { mountainHeight, peakIndex };
}

// ============================================================================
// Proof verification
// ============================================================================

/**
 * Verify an inclusion proof against the appropriate peak.
 *
 * Proof length must equal the height of the mountain containing the leaf.
 * Empty proof is valid when the leaf is a lone peak.
 */
export function verifyProofToPeak(
    state: AccumulatorState,
    leafIndex: bigint,
    leafHash: Uint8Array,
    siblings: readonly Uint8Array[]
): boolean {
    if (leafIndex < 0n || leafIndex >= state.leafCount) {
        return false;
    }

    const { mountainHeight, peakIndex } = getMountain(leafIndex, state.leafCount);

    if (siblings.length !== mountainHeight) {
        return false;
    }

    const computed = computePath(leafIndex, leafHash, siblings);
    return hashEquals(computed, state.peaks[peakIndex]);
}

/**
 * Verify an inclusion proof against the current root.
 *
 * Proof contains the full path including duplicated siblings from bagging.
 * Proof length always equals bitWidth(leafCount - 1).
 */
export function verifyProofToRoot(
    state: AccumulatorState,
    leafIndex: bigint,
    leafHash: Uint8Array,
    siblings: readonly Uint8Array[]
): boolean {
    if (leafIndex < 0n || leafIndex >= state.leafCount) {
        return false;
    }

    const expectedLength = bitWidth(state.leafCount - 1n);
    if (siblings.length !== expectedLength) {
        return false;
    }

    const computed = computePath(leafIndex, leafHash, siblings);
    const root = getRoot(state);
    return hashEquals(computed, root);
}

// ============================================================================
// Bootstrap
// ============================================================================

/**
 * Bootstrap an accumulator from a proof-to-root for the last leaf.
 *
 * The proof contains all MMR peaks as siblings, interleaved with
 * duplicates from the bagging process.
 *
 * Returns null if the proof structure is invalid.
 */
export function bootstrapFromProof(
    leafCount: bigint,
    lastLeaf: Uint8Array,
    siblings: readonly Uint8Array[]
): AccumulatorState | null {
    if (leafCount < 0n) {
        return null;
    }

    if (leafCount === 0n) {
        return siblings.length === 0 ? empty() : null;
    }

    if (leafCount === 1n) {
        return siblings.length === 0
            ? { leafCount: 1n, peaks: [Uint8Array.from(lastLeaf)] }
            : null;
    }

    const expectedLength = bitWidth(leafCount - 1n);
    if (siblings.length !== expectedLength) {
        return null;
    }

    const peakCountVal = popcount(leafCount);
    const peaks: Hash[] = new Array(peakCountVal);

    let remaining = leafCount;
    let proofIdx = 0;
    let peakIdx = peakCountVal;
    let currentHeight = 0;

    let computed: Hash = Uint8Array.from(lastLeaf);
    let idx = leafCount - 1n;

    while (remaining > 0n) {
        const peakHeight = countTrailingZeros(remaining);

        // Advance through proof to reach peak height
        while (currentHeight < peakHeight) {
            if ((idx & 1n) === 1n) {
                computed = merge(siblings[proofIdx], computed);
            } else {
                computed = merge(computed, siblings[proofIdx]);
            }
            idx >>= 1n;
            proofIdx++;
            currentHeight++;
        }

        peakIdx--;

        if (peakHeight === 0 && peakIdx === peakCountVal - 1) {
            // Smallest peak is lastLeaf itself
            peaks[peakIdx] = Uint8Array.from(lastLeaf);
        } else if (proofIdx < siblings.length) {
            // Next sibling is this peak
            peaks[peakIdx] = Uint8Array.from(siblings[proofIdx]);
            // Continue path computation
            if ((idx & 1n) === 1n) {
                computed = merge(siblings[proofIdx], computed);
            } else {
                computed = merge(computed, siblings[proofIdx]);
            }
            idx >>= 1n;
            proofIdx++;
            currentHeight++;
        } else {
            // Exhausted proof; computed value is final peak
            peaks[peakIdx] = computed;
        }

        remaining &= remaining - 1n;
    }

    return { leafCount, peaks };
}

// ============================================================================
// Serialization
// ============================================================================

/**
 * Serialize state to bytes.
 * Format: 8-byte little-endian leafCount + concatenated 32-byte peaks
 */
export function serialize(state: AccumulatorState): Uint8Array {
    const result = new Uint8Array(8 + 32 * state.peaks.length);

    // Write leafCount as 8-byte little-endian
    let n = state.leafCount;
    for (let i = 0; i < 8; i++) {
        result[i] = Number(n & 0xffn);
        n >>= 8n;
    }

    // Write peaks
    for (let i = 0; i < state.peaks.length; i++) {
        result.set(state.peaks[i], 8 + 32 * i);
    }

    return result;
}

/**
 * Deserialize state from bytes.
 * @throws Error if data length is invalid
 */
export function deserialize(data: Uint8Array): AccumulatorState {
    if (data.length < 8) {
        throw new Error(`need at least 8 bytes, got ${data.length}`);
    }

    // Read leafCount as 8-byte little-endian
    let leafCount = 0n;
    for (let i = 7; i >= 0; i--) {
        leafCount = (leafCount << 8n) | BigInt(data[i]);
    }

    const expectedPeakCount = popcount(leafCount);
    const expectedLength = 8 + 32 * expectedPeakCount;

    if (data.length !== expectedLength) {
        throw new Error(`expected ${expectedLength} bytes, got ${data.length}`);
    }

    const peaks: Hash[] = [];
    for (let i = 0; i < expectedPeakCount; i++) {
        peaks.push(Uint8Array.from(data.slice(8 + 32 * i, 8 + 32 * (i + 1))));
    }

    return { leafCount, peaks };
}

// ============================================================================
// Utilities
// ============================================================================

/**
 * Compare two hashes for equality.
 */
export function hashEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/**
 * Compare two states for equality.
 */
export function stateEquals(a: AccumulatorState, b: AccumulatorState): boolean {
    if (a.leafCount !== b.leafCount) return false;
    if (a.peaks.length !== b.peaks.length) return false;
    for (let i = 0; i < a.peaks.length; i++) {
        if (!hashEquals(a.peaks[i], b.peaks[i])) return false;
    }
    return true;
}

/**
 * Convert a hash to a hex string (for debugging/display).
 */
export function hashToHex(hash: Uint8Array): string {
    return Array.from(hash)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

/**
 * Convert a hex string to a hash.
 * @throws Error if the hex string is invalid or wrong length
 */
export function hexToHash(hex: string): Hash {
    if (hex.length !== 64) {
        throw new Error(`hex string must be 64 characters, got ${hex.length}`);
    }
    const hash = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        hash[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return hash;
}
