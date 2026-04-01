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
 * Maintains only the minimal state needed to verify proofs and extend the MMR:
 * the leaf count and the peaks (one per set bit in the binary representation
 * of leafCount). This is O(log n) storage for n leaves.
 *
 * Unlike a server-side MMR class which stores all internal nodes for proof
 * generation, this module stores only peaks, making it suitable for light
 * clients with limited storage.
 *
 * Example with 11 leaves (indices 0-10):
 *
 *            [6]
 *         _ /   \ _
 *       /           \
 *      2             5
 *    /   \         /   \
 *   0     1       3     4      [7]
 *  / \   / \     / \   / \     / \
 * 0   1 2   3   4   5 6   7   8   9  [10]
 *
 * Peaks marked with []: [6], [7], [10].
 * For leafCount = 11 (binary 1011), the accumulator stores 3 peaks:
 *   - peaks[0]: node 6, height-3 peak covering leaves 0-7
 *   - peaks[1]: node 7, height-1 peak covering leaves 8-9
 *   - peaks[2]: leaf 10, height-0 peak (the leaf hash itself)
 *
 * Peaks are ordered from tallest to shortest (left to right in the tree).
 * The number of peaks equals popcount(leafCount).
 *
 * ## Input Validation Philosophy
 *
 * Functions that construct or modify accumulator state (`create`, `extend`,
 * `batchExtend`) throw errors on invalid input, as they are expected to be
 * called with trusted/validated data.
 *
 * Functions that verify untrusted proofs (`verifyProofToPeak`, `verifyProofToRoot`,
 * `bootstrapFromProof`) return `false` or `null` on invalid input, as they must
 * handle adversarial data gracefully without throwing.
 */

import { hash256 } from "@bitauth/libauth";

// ============================================================================
// Types
// ============================================================================

/**
 * MMR Accumulator state.
 * Immutable by convention; all operations return new state objects.
 */
export interface AccumulatorState {
    /** Number of leaves in the MMR */
    readonly leafCount: bigint;
    /** Peak hashes, ordered from tallest (leftmost) to shortest (rightmost) */
    readonly peaks: readonly Uint8Array[];
}

// ============================================================================
// Bit manipulation helpers
// ============================================================================

/**
 * Count set bits (population count) in a BigInt.
 * @param n - A non-negative integer in uint64 range.
 * @returns The number of 1-bits in the binary representation of n.
 * @throws Error if n is negative or exceeds uint64 range.
 * @example
 * popcount(0n);   // => 0
 * popcount(11n);  // => 3 (binary 1011 has three 1-bits)
 * popcount(16n);  // => 1 (binary 10000 has one 1-bit)
 */
export function popcount(n: bigint): number {
    if (n < 0n || n >= 1n << 64n) {
        throw new Error(`n must be a uint64, got ${n}`);
    }
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
 * @param n - A non-negative integer in uint64 range.
 * @returns The number of consecutive 1-bits at the least significant end.
 * @throws Error if n is negative or exceeds uint64 range.
 * @example
 * countTrailingOnes(0n);   // => 0 (binary 0)
 * countTrailingOnes(7n);   // => 3 (binary 111)
 * countTrailingOnes(11n);  // => 2 (binary 1011)
 */
export function countTrailingOnes(n: bigint): number {
    if (n < 0n || n >= 1n << 64n) {
        throw new Error(`n must be a uint64, got ${n}`);
    }
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
 * @param n - A non-negative integer in uint64 range.
 * @returns The number of consecutive 0-bits at the least significant end.
 * @throws Error if n is negative or exceeds uint64 range.
 * @example
 * countTrailingZeros(0n);   // => 64
 * countTrailingZeros(1n);   // => 0 (binary 1)
 * countTrailingZeros(8n);   // => 3 (binary 1000)
 * countTrailingZeros(12n);  // => 2 (binary 1100)
 */
export function countTrailingZeros(n: bigint): number {
    if (n < 0n || n >= 1n << 64n) {
        throw new Error(`n must be a uint64, got ${n}`);
    }
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
 * @param n - A non-negative integer in uint64 range.
 * @returns The minimum number of bits needed to represent n.
 * @throws Error if n is negative or exceeds uint64 range.
 * @example
 * bitWidth(0n);   // => 0
 * bitWidth(1n);   // => 1 (binary 1)
 * bitWidth(8n);   // => 4 (binary 1000)
 * bitWidth(11n);  // => 4 (binary 1011)
 */
export function bitWidth(n: bigint): number {
    if (n < 0n || n >= 1n << 64n) {
        throw new Error(`n must be a uint64, got ${n}`);
    }
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
 * Compute the leaf node hash for a block header.
 * This is the standard Bitcoin block hash (SHA256d of 80-byte header).
 * @param header - The 80-byte raw block header.
 * @returns The 32-byte double-SHA256 hash.
 * @throws Error if header is not exactly 80 bytes.
 * @example
 * const header = new Uint8Array(80); // Genesis block header bytes
 * const blockHash = leaf(header);
 * console.log(hashToHex(blockHash));
 */
export function leaf(header: Uint8Array): Uint8Array {
    if (header.length !== 80) {
        throw new Error(`header must be 80 bytes, got ${header.length}`);
    }
    return hash256(header);
}

/**
 * Compute a merged node hash from two children.
 * This matches Bitcoin's Merkle tree node computation: SHA256d(left || right).
 * @param left - The 32-byte left child hash.
 * @param right - The 32-byte right child hash.
 * @returns The 32-byte double-SHA256 hash of the concatenation.
 * @example
 * const parent = merge(leftChildHash, rightChildHash);
 */
export function merge(left: Uint8Array, right: Uint8Array): Uint8Array {
    const concat = new Uint8Array(64);
    concat.set(left, 0);
    concat.set(right, 32);
    return hash256(concat);
}

// ============================================================================
// State creation and utilities
// ============================================================================

/**
 * Create an empty accumulator state.
 * Initial state has leafCount = 0 and no peaks.
 * @returns A new empty accumulator state.
 * @example
 * const state = empty();
 * console.log(state.leafCount); // => 0n
 * console.log(state.peaks.length); // => 0
 */
export function empty(): AccumulatorState {
    return { leafCount: 0n, peaks: [] };
}

/**
 * Create an accumulator state with the given leaf count and peaks.
 * @param leafCount - The number of leaves in the MMR.
 * @param peaks - The peak hashes, ordered tallest to shortest.
 * @returns A new accumulator state.
 * @throws Error if leafCount is negative.
 * @throws Error if peak count doesn't match popcount(leafCount).
 * @throws Error if any peak is not 32 bytes.
 * @example
 * // Create accumulator for 3 leaves (binary 11): 2 peaks
 * const state = create(3n, [peak0, peak1]);
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
 * Create a deep copy of an accumulator state.
 * @param state - The state to copy.
 * @returns A new state with copied peaks.
 * @example
 * const copy = clone(state);
 * // Modifying copy.peaks[0] won't affect original
 */
export function clone(state: AccumulatorState): AccumulatorState {
    return {
        leafCount: state.leafCount,
        peaks: state.peaks.map((p) => Uint8Array.from(p)),
    };
}

/**
 * Check if an accumulator state is empty (no leaves).
 * @param state - The accumulator state.
 * @returns true if leafCount is 0.
 * @example
 * isEmpty(empty()); // => true
 * isEmpty(extend(empty(), someLeaf)); // => false
 */
export function isEmpty(state: AccumulatorState): boolean {
    return state.leafCount === 0n;
}

/**
 * Get the number of peaks stored.
 * @param state - The accumulator state.
 * @returns The number of peaks (equals popcount(leafCount)).
 * @example
 * peakCount(create(11n, peaks)); // => 3 (binary 1011 has 3 set bits)
 */
export function peakCount(state: AccumulatorState): number {
    return state.peaks.length;
}

/**
 * Compare two hashes for equality.
 * @param a - First hash.
 * @param b - Second hash.
 * @returns true if both hashes have identical bytes.
 * @example
 * hashEquals(hash1, hash2); // => true if identical
 */
export function hashEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/**
 * Compare two accumulator states for equality.
 * Two accumulators are equal iff they have the same leaf count and peaks.
 * @param a - First accumulator state.
 * @param b - Second accumulator state.
 * @returns true if both states are identical.
 * @example
 * const s1 = build(leaves);
 * const s2 = build(leaves);
 * stateEquals(s1, s2); // => true
 */
export function stateEquals(a: AccumulatorState, b: AccumulatorState): boolean {
    if (a.leafCount !== b.leafCount) return false;
    if (a.peaks.length !== b.peaks.length) return false;
    for (let i = 0; i < a.peaks.length; i++) {
        if (!hashEquals(a.peaks[i], b.peaks[i])) return false;
    }
    return true;
}

// ============================================================================
// Accumulator extension
// ============================================================================

/**
 * Extend the accumulator with a new leaf.
 * Returns a new state; the original is not modified.
 *
 * When appending a leaf node, the number of merges equals the number of
 * trailing 1-bits in the binary representation of leafCount.
 * This requires O(log n) hash operations in the worst case (when leafCount + 1
 * is a power of two). On average, each extend requires fewer than 2 merges.
 *
 * @param state - The current accumulator state.
 * @param leafHash - The 32-byte hash of the new leaf.
 * @returns A new state with the leaf appended.
 * @throws Error if leafHash is not 32 bytes.
 * @example
 * const header = new Uint8Array(80); // block header bytes
 * const leafHash = leaf(header);
 * const newState = extend(state, leafHash);
 * console.log(newState.leafCount); // => state.leafCount + 1n
 */
export function extend(state: AccumulatorState, leafHash: Uint8Array): AccumulatorState {
    if (leafHash.length !== 32) {
        throw new Error(`leaf must be 32 bytes, got ${leafHash.length}`);
    }

    // Number of merges equals trailing 1-bits in current leaf count.
    const mergeCount = countTrailingOnes(state.leafCount);

    // Copy peaks array for mutation.
    const newPeaks: Uint8Array[] = state.peaks.map((p) => Uint8Array.from(p));
    let current: Uint8Array = Uint8Array.from(leafHash);

    // Merge with smallest peaks (from back) as they combine with new leaf.
    for (let i = 0; i < mergeCount; i++) {
        current = merge(newPeaks.pop()!, current);
    }

    newPeaks.push(current);

    return {
        leafCount: state.leafCount + 1n,
        peaks: newPeaks,
    };
}

/**
 * Extend the accumulator with multiple leaves efficiently.
 * Returns a new state; the original is not modified.
 *
 * More efficient than repeated extend() calls for bulk operations
 * as it avoids intermediate state object allocations.
 *
 * @param state - The current accumulator state.
 * @param leaves - Array of 32-byte leaf hashes to append.
 * @returns A new state with all leaves appended.
 * @throws Error if any leaf is not 32 bytes.
 * @example
 * const leafHashes = headers.map(h => leaf(h));
 * const newState = batchExtend(state, leafHashes);
 */
export function batchExtend(
    state: AccumulatorState,
    leaves: readonly Uint8Array[]
): AccumulatorState {
    if (leaves.length === 0) {
        return clone(state);
    }

    // Work with mutable copies internally.
    let leafCount = state.leafCount;
    const peaks: Uint8Array[] = state.peaks.map((p) => Uint8Array.from(p));

    for (const leafHash of leaves) {
        if (leafHash.length !== 32) {
            throw new Error(`leaf must be 32 bytes, got ${leafHash.length}`);
        }

        const mergeCount = countTrailingOnes(leafCount);
        let current: Uint8Array = Uint8Array.from(leafHash);

        for (let i = 0; i < mergeCount; i++) {
            current = merge(peaks.pop()!, current);
        }

        peaks.push(current);
        leafCount++;
    }

    return { leafCount, peaks };
}

/**
 * Build an accumulator from a sequence of leaf hashes.
 * @param leaves - Array of 32-byte leaf hashes.
 * @returns A new accumulator containing all leaves.
 * @throws Error if any leaf is not 32 bytes.
 * @example
 * const leafHashes = headers.map(h => leaf(h));
 * const state = build(leafHashes);
 * console.log(state.leafCount); // => BigInt(headers.length)
 */
export function build(leaves: readonly Uint8Array[]): AccumulatorState {
    return batchExtend(empty(), leaves);
}

// ============================================================================
// Merkle root computation
// ============================================================================

/**
 * Compute the Bitcoin-style Merkle root.
 *
 * Starting from the smallest peak (rightmost in the tree), the algorithm works
 * backwards through progressively larger peaks. Before merging with each larger
 * peak, the running hash is duplicated until its height matches the next peak's
 * height. This produces the same root as Bitcoin's Merkle tree construction,
 * where unpaired nodes are duplicated to form a balanced tree.
 *
 * Peak heights correspond to the positions of set bits in leafCount; the bit
 * manipulation `leafCount & (leafCount - 1)` clears the lowest set bit,
 * allowing countTrailingZeros to yield each successive peak height.
 *
 * @param state - The accumulator state.
 * @returns The 32-byte Merkle root (32 zero bytes for empty accumulator).
 * @example
 * const root = getRoot(state);
 * console.log(hashToHex(root));
 */
export function getRoot(state: AccumulatorState): Uint8Array {
    if (state.leafCount === 0n) {
        return new Uint8Array(32);
    }

    if (state.peaks.length === 1) {
        return Uint8Array.from(state.peaks[0]);
    }

    // Bag peaks from smallest to largest, duplicating to match heights.
    let hash: Uint8Array = Uint8Array.from(state.peaks[state.peaks.length - 1]);
    let remaining = state.leafCount;
    let height = countTrailingZeros(remaining);

    for (let i = state.peaks.length - 1; i > 0; i--) {
        // Clear lowest set bit to find next peak's height.
        remaining &= remaining - 1n;
        const nextHeight = countTrailingZeros(remaining);

        // Duplicate until heights match.
        while (height < nextHeight) {
            hash = merge(hash, hash);
            height++;
        }

        // Merge with next larger peak.
        hash = merge(state.peaks[i - 1], hash);
        height++;
    }

    return hash;
}

// ============================================================================
// Proof verification
// ============================================================================

/**
 * Verify an inclusion proof against the appropriate peak.
 *
 * The bits of leafIndex determine orientation: a 1-bit means the sibling is on
 * the left, a 0-bit means it is on the right. The proof may be empty when the
 * leaf is a lone peak; this occurs when leafIndex === leafCount - 1 and
 * leafCount is odd.
 *
 * Returns false (rather than throwing) for invalid inputs, as this function
 * is designed to handle untrusted proof data.
 *
 * @param state - The trusted accumulator state.
 * @param leafIndex - Position of the leaf being proven (0-indexed).
 * @param leafHash - The 32-byte leaf hash being proven.
 * @param siblings - Sibling hashes from leaf level upward to peak.
 * @returns true if the computed path matches the peak covering leafIndex.
 * @example
 * const isValid = verifyProofToPeak(state, 5n, leafHash, siblings);
 * if (isValid) {
 *     console.log("Proof verified against peak");
 * }
 */
export function verifyProofToPeak(
    state: AccumulatorState,
    leafIndex: bigint,
    leafHash: Uint8Array,
    siblings: readonly Uint8Array[]
): boolean {
    // Input validation
    if (leafHash.length !== 32) {
        return false;
    }
    for (const sibling of siblings) {
        if (sibling.length !== 32) {
            return false;
        }
    }

    // Malformed proof check.
    if (leafIndex < 0n || leafIndex >= state.leafCount) {
        return false;
    }

    // Find which peak covers this leaf.
    // XOR identifies where leafIndex and leafCount differ; the highest
    // differing bit indicates the mountain boundary.
    const diff = leafIndex ^ state.leafCount;
    const diffWidth = bitWidth(diff);
    const mountainHeight = diffWidth - 1;
    const peakIndex = popcount(state.leafCount >> BigInt(diffWidth));

    // Malformed proof check.
    if (siblings.length !== mountainHeight) {
        return false;
    }

    // Compute path to peak. No CVE-2012-2459 check needed: proof-to-peak
    // verifies against trusted accumulator state, which has 1-to-1 mapping
    // with leaf sequence, even if there are duplicate leaves.
    let current: Uint8Array = Uint8Array.from(leafHash);
    let idx = leafIndex;

    for (const sibling of siblings) {
        if ((idx & 1n) === 1n) {
            current = merge(sibling, current);
        } else {
            current = merge(current, sibling);
        }
        idx >>= 1n;
    }

    return hashEquals(current, state.peaks[peakIndex]);
}

/**
 * Verify an inclusion proof against the current root.
 *
 * The proof length is always bitWidth(leafCount - 1), which equals the height
 * of the bagged tree. The proof is empty only when leafCount === 1.
 *
 * Returns false (rather than throwing) for invalid inputs, as this function
 * is designed to handle untrusted proof data.
 *
 * @param state - The trusted accumulator state.
 * @param leafIndex - Position of the leaf being proven (0-indexed).
 * @param leafHash - The 32-byte leaf hash being proven.
 * @param siblings - Sibling hashes from leaf level upward to root.
 * @returns true if the computed path matches getRoot().
 * @example
 * const isValid = verifyProofToRoot(state, 5n, leafHash, siblings);
 * if (isValid) {
 *     console.log("Proof verified against root");
 * }
 */
export function verifyProofToRoot(
    state: AccumulatorState,
    leafIndex: bigint,
    leafHash: Uint8Array,
    siblings: readonly Uint8Array[]
): boolean {
    // Input validation
    if (leafHash.length !== 32) {
        return false;
    }
    for (const sibling of siblings) {
        if (sibling.length !== 32) {
            return false;
        }
    }

    // Malformed proof check.
    if (leafIndex < 0n || leafIndex >= state.leafCount) {
        return false;
    }

    // Malformed proof check && trivial verification if well formed.
    if (state.leafCount === 1n) {
        return siblings.length === 0 && hashEquals(leafHash, state.peaks[0]);
    }

    // Malformed proof check.
    const expectedLength = bitWidth(state.leafCount - 1n);
    if (siblings.length !== expectedLength) {
        return false;
    }

    // Compute path to root with CVE-2012-2459 protection.
    // The attack exploits bagging ambiguity: multiple MMR states can produce
    // the same root, allowing forged proofs for phantom positions. We detect
    // this by rejecting left-sibling duplicates, which only occur in forged
    // proofs (legitimate duplicates from bagging appear as right siblings).
    let current: Uint8Array = Uint8Array.from(leafHash);
    let idx = leafIndex;

    for (const sibling of siblings) {
        if ((idx & 1n) === 1n && hashEquals(sibling, current)) {
            return false;
        }
        if ((idx & 1n) === 1n) {
            current = merge(sibling, current);
        } else {
            current = merge(current, sibling);
        }
        idx >>= 1n;
    }

    return hashEquals(current, getRoot(state));
}

// ============================================================================
// Bootstrapping
// ============================================================================

/**
 * Bootstrap an accumulator from a proof-to-root for the last leaf.
 *
 * The proof contains all MMR peaks as siblings along the path, interleaved
 * with duplicates from the bagging process.
 *
 * Returns null (rather than throwing) for invalid proofs, as this function
 * is designed to handle untrusted proof data.
 *
 * Example with leafCount = 11 (binary 1011):
 *   Peaks: [height-3, height-1, height-0]
 *   Proof: [last_leaf_dup, peaks[1], dup, peaks[0]]
 *
 *   Iteration 1: peakHeight=0, extract peaks[2]=lastLeaf
 *   Iteration 2: peakHeight=1, extract peaks[1]=siblings[1]
 *   Iteration 3: peakHeight=3, skip 1 dup, extract peaks[0]=siblings[3]
 *
 * Example with leafCount = 8 (binary 1000):
 *   Peaks: [height-3]
 *   Proof: [sibling, intermediate, intermediate]  // 3 elements
 *
 *   Iteration 1: peakHeight=3, compute path through all 3 siblings,
 *                proof exhausted, extract peaks[0]=computed
 *
 * @param leafCount - Total number of leaves in the MMR.
 * @param lastLeaf - The 32-byte hash of the last leaf (at index leafCount - 1).
 * @param siblings - Proof-to-root siblings for the last leaf.
 * @returns The bootstrapped accumulator state, or null if proof is invalid.
 * @example
 * const state = bootstrapFromProof(1000n, lastLeafHash, proofSiblings);
 * if (state !== null) {
 *     // Optionally verify against a trusted root
 *     if (hashEquals(getRoot(state), trustedRoot)) {
 *         console.log("Bootstrapped and verified");
 *     }
 * }
 */
export function bootstrapFromProof(
    leafCount: bigint,
    lastLeaf: Uint8Array,
    siblings: readonly Uint8Array[]
): AccumulatorState | null {
    // Input validation
    if (lastLeaf.length !== 32) {
        return null;
    }
    for (const sibling of siblings) {
        if (sibling.length !== 32) {
            return null;
        }
    }

    // Edge case.
    if (leafCount === 0n) {
        if (siblings.length !== 0) {
            return null;
        }
        return empty();
    }

    // Trivial verification and initialization.
    if (leafCount === 1n) {
        if (siblings.length !== 0) {
            return null;
        }
        return { leafCount: 1n, peaks: [Uint8Array.from(lastLeaf)] };
    }

    // Malformed proof check.
    const expectedLength = bitWidth(leafCount - 1n);
    if (siblings.length !== expectedLength) {
        return null;
    }

    const peakCountVal = popcount(leafCount);
    const peaks: Uint8Array[] = new Array(peakCountVal);

    let remaining = leafCount;
    let proofIdx = 0;
    let peakIdx = peakCountVal;
    let currentHeight = 0;

    // Track path computation for extracting root as the only peak
    // when leaf count is power of two.
    let computed: Uint8Array = Uint8Array.from(lastLeaf);
    let idx = leafCount - 1n;

    // We must guard against CVE-2012-2459 throughout the whole path
    // (path segments inside & outside MMR structure) because MMR
    // structure is determined from leafCount, and it cannot be trusted.

    while (remaining > 0n) {
        const peakHeight = countTrailingZeros(remaining);

        // Advance through proof to reach peak height.
        while (currentHeight < peakHeight) {
            const sibling = siblings[proofIdx];

            // CVE-2012-2459 (proof-to-peak segment).
            if ((idx & 1n) === 1n && hashEquals(sibling, computed)) {
                return null;
            }

            if ((idx & 1n) === 1n) {
                computed = merge(sibling, computed);
            } else {
                computed = merge(computed, sibling);
            }
            idx >>= 1n;
            proofIdx++;
            currentHeight++;
        }

        peakIdx--;

        if (peakHeight === 0 && peakIdx === peakCountVal - 1) {
            // Smallest peak is the lastLeaf itself.
            peaks[peakIdx] = Uint8Array.from(lastLeaf);
        } else if (proofIdx < siblings.length) {
            // Next sibling in proof is this peak.
            peaks[peakIdx] = Uint8Array.from(siblings[proofIdx]);

            // CVE-2012-2459 (proof-to-root segment).
            if ((idx & 1n) === 1n && hashEquals(siblings[proofIdx], computed)) {
                return null;
            }

            if ((idx & 1n) === 1n) {
                computed = merge(siblings[proofIdx], computed);
            } else {
                computed = merge(computed, siblings[proofIdx]);
            }
            idx >>= 1n;
            proofIdx++;
            currentHeight++;
        } else {
            // Exhausted proof; computed value is the final peak (root).
            peaks[peakIdx] = Uint8Array.from(computed);
        }

        remaining &= remaining - 1n;
    }

    return { leafCount, peaks };
}

// ============================================================================
// Serialization
// ============================================================================

/**
 * Serialize accumulator state to bytes.
 * Format: 8-byte little-endian leafCount + concatenated 32-byte peaks.
 * @param state - The accumulator state to serialize.
 * @returns The serialized bytes.
 * @example
 * const bytes = serialize(state);
 * localStorage.setItem("accumulator", bytesToHex(bytes));
 */
export function serialize(state: AccumulatorState): Uint8Array {
    const result = new Uint8Array(8 + 32 * state.peaks.length);

    // Write leafCount as 8-byte little-endian.
    let n = state.leafCount;
    for (let i = 0; i < 8; i++) {
        result[i] = Number(n & 0xffn);
        n >>= 8n;
    }

    // Write peaks.
    for (let i = 0; i < state.peaks.length; i++) {
        result.set(state.peaks[i], 8 + 32 * i);
    }

    return result;
}

/**
 * Deserialize accumulator state from bytes.
 * @param data - The serialized bytes (from serialize()).
 * @returns The deserialized accumulator state.
 * @throws Error if data length is invalid or doesn't match leafCount.
 * @example
 * const bytes = hexToBytes(localStorage.getItem("accumulator"));
 * const state = deserialize(bytes);
 */
export function deserialize(data: Uint8Array): AccumulatorState {
    if (data.length < 8) {
        throw new Error(`need at least 8 bytes, got ${data.length}`);
    }

    // Read leafCount as 8-byte little-endian.
    let leafCount = 0n;
    for (let i = 7; i >= 0; i--) {
        leafCount = (leafCount << 8n) | BigInt(data[i]);
    }

    const expectedPeakCount = popcount(leafCount);
    const expectedLength = 8 + 32 * expectedPeakCount;

    if (data.length !== expectedLength) {
        throw new Error(`expected ${expectedLength} bytes, got ${data.length}`);
    }

    const peaks: Uint8Array[] = [];
    for (let i = 0; i < expectedPeakCount; i++) {
        peaks.push(Uint8Array.from(data.slice(8 + 32 * i, 8 + 32 * (i + 1))));
    }

    return { leafCount, peaks };
}

// ============================================================================
// Hex utilities
// ============================================================================

/**
 * Convert a hash to a hex string.
 * @param hash - The hash bytes to convert.
 * @returns The lowercase hex string representation.
 * @example
 * const hex = hashToHex(blockHash);
 * console.log(hex); // "000000000019d6689c085ae165831e93..."
 */
export function hashToHex(hash: Uint8Array): string {
    return Array.from(hash)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

/**
 * Convert a hex string to a hash.
 * @param hex - The 64-character hex string.
 * @returns The 32-byte hash.
 * @throws Error if the hex string is not exactly 64 characters.
 * @example
 * const hash = hexToHash("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
 */
export function hexToHash(hex: string): Uint8Array {
    if (hex.length !== 64) {
        throw new Error(`hex string must be 64 characters, got ${hex.length}`);
    }
    const hash = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        hash[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return hash;
}

/**
 * Convert a Bitcoin-style hex string (display order) to internal byte order.
 * Bitcoin displays hashes in big-endian (reversed) but stores them little-endian.
 * @param hex - The 64-character hex string in display order.
 * @returns The 32-byte hash in internal byte order.
 */
export function hexToHashReversed(hex: string): Uint8Array {
    if (hex.length !== 64) {
        throw new Error(`hex string must be 64 characters, got ${hex.length}`);
    }
    const hash = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        hash[31 - i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return hash;
}

/**
 * Convert a hash to Bitcoin-style hex string (display order).
 * Bitcoin displays hashes in big-endian (reversed) but stores them little-endian.
 * @param hash - The 32-byte hash in internal byte order.
 * @returns The lowercase hex string in display order.
 */
export function hashToHexReversed(hash: Uint8Array): string {
    const reversed = new Uint8Array(hash.length);
    for (let i = 0; i < hash.length; i++) {
        reversed[i] = hash[hash.length - 1 - i];
    }
    return Array.from(reversed)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}
