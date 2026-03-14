// Copyright (c) 2026 bitcoincashautist
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * MMR Accumulator for Simplified Header Verification (SHV) clients.
 *
 * Functional implementation using immutable state objects.
 * All functions consume arguments and return new values without mutation.
 *
 * State structure:
 *   { leafCount: bigint, peaks: Uint8Array[] }
 *
 * - leafCount: Number of leaves in the MMR (BigInt for 64-bit support)
 * - peaks: Array of 32-byte Uint8Array hashes, ordered tallest to shortest
 *
 * Example with 11 leaves (binary 1011):
 *   peaks[0]: height-3 peak covering leaves 0-7
 *   peaks[1]: height-1 peak covering leaves 8-9
 *   peaks[2]: height-0 peak (leaf 10 itself)
 */

// ============================================================================
// Bit manipulation helpers
// ============================================================================

/**
 * Count set bits in a BigInt.
 * @param {bigint} n - Non-negative integer
 * @returns {number} Number of 1-bits
 */
function popcount(n) {
    let count = 0;
    while (n > 0n) {
        count += Number(n & 1n);
        n >>= 1n;
    }
    return count;
}

/**
 * Count trailing one bits in a BigInt.
 * @param {bigint} n - Non-negative integer
 * @returns {number} Number of trailing 1-bits (0 if n is 0)
 */
function countTrailingOnes(n) {
    let count = 0;
    while ((n & 1n) === 1n) {
        count++;
        n >>= 1n;
    }
    return count;
}

/**
 * Count trailing zero bits in a BigInt.
 * @param {bigint} n - Non-negative integer
 * @returns {number} Number of trailing 0-bits (64 if n is 0)
 */
function countTrailingZeros(n) {
    if (n === 0n) return 64;
    let count = 0;
    while ((n & 1n) === 0n) {
        count++;
        n >>= 1n;
    }
    return count;
}

/**
 * Return the bit width (position of highest set bit + 1).
 * @param {bigint} n - Non-negative integer
 * @returns {number} Bit width (0 if n is 0)
 */
function bitWidth(n) {
    let width = 0;
    while (n > 0n) {
        width++;
        n >>= 1n;
    }
    return width;
}

// ============================================================================
// Hashing
// ============================================================================

/**
 * Compute SHA256 of data.
 * Uses Web Crypto API (async) - for sync version, use a library like js-sha256.
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>} 32-byte hash
 */
async function sha256(data) {
    const buffer = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(buffer);
}

/**
 * Compute SHA256d (double SHA256) of concatenated inputs.
 * This is Bitcoin's standard merged node hash.
 * @param {Uint8Array} left - 32-byte hash
 * @param {Uint8Array} right - 32-byte hash
 * @returns {Promise<Uint8Array>} 32-byte hash
 */
async function sha256d(left, right) {
    const concat = new Uint8Array(64);
    concat.set(left, 0);
    concat.set(right, 32);
    const first = await sha256(concat);
    return sha256(first);
}

// ============================================================================
// State creation and validation
// ============================================================================

/**
 * Create an empty accumulator state.
 * @returns {{leafCount: bigint, peaks: Uint8Array[]}}
 */
function empty() {
    return { leafCount: 0n, peaks: [] };
}

/**
 * Create an accumulator state with validation.
 * @param {bigint} leafCount - Number of leaves
 * @param {Uint8Array[]} peaks - Peak hashes, tallest to shortest
 * @returns {{leafCount: bigint, peaks: Uint8Array[]}}
 * @throws {Error} If peak count doesn't match popcount(leafCount)
 */
function create(leafCount, peaks) {
    if (leafCount < 0n) {
        throw new Error(`leafCount must be non-negative, got ${leafCount}`);
    }
    const expectedPeakCount = popcount(leafCount);
    if (peaks.length !== expectedPeakCount) {
        throw new Error(
            `leafCount ${leafCount} requires ${expectedPeakCount} peaks, got ${peaks.length}`
        );
    }
    // Return a copy to ensure immutability
    return {
        leafCount,
        peaks: peaks.map(p => new Uint8Array(p))
    };
}

/**
 * Check if a state is empty.
 * @param {{leafCount: bigint, peaks: Uint8Array[]}} state
 * @returns {boolean}
 */
function isEmpty(state) {
    return state.leafCount === 0n;
}

/**
 * Get the number of peaks.
 * @param {{leafCount: bigint, peaks: Uint8Array[]}} state
 * @returns {number}
 */
function peakCount(state) {
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
 *
 * @param {{leafCount: bigint, peaks: Uint8Array[]}} state - Current state
 * @param {Uint8Array} leaf - 32-byte leaf hash
 * @returns {Promise<{leafCount: bigint, peaks: Uint8Array[]}>} New state
 */
async function extend(state, leaf) {
    const mergeCount = countTrailingOnes(state.leafCount);

    // Copy peaks array (we'll modify the copy)
    const newPeaks = state.peaks.map(p => new Uint8Array(p));
    let current = new Uint8Array(leaf);

    // Merge with smallest peaks (from end)
    for (let i = 0; i < mergeCount; i++) {
        current = await sha256d(newPeaks.pop(), current);
    }

    newPeaks.push(current);

    return {
        leafCount: state.leafCount + 1n,
        peaks: newPeaks
    };
}

/**
 * Build an accumulator from an array of leaves.
 * @param {Uint8Array[]} leaves - Array of 32-byte leaf hashes
 * @returns {Promise<{leafCount: bigint, peaks: Uint8Array[]}>}
 */
async function build(leaves) {
    let state = empty();
    for (const leaf of leaves) {
        state = await extend(state, leaf);
    }
    return state;
}

/**
 * Compute the Bitcoin-style Merkle root.
 *
 * Bags peaks from smallest to largest, duplicating nodes as needed
 * to match heights before merging.
 *
 * @param {{leafCount: bigint, peaks: Uint8Array[]}} state
 * @returns {Promise<Uint8Array>} 32-byte root hash (zeros if empty)
 */
async function getRoot(state) {
    if (state.leafCount === 0n) {
        return new Uint8Array(32);
    }

    if (state.peaks.length === 1) {
        return new Uint8Array(state.peaks[0]);
    }

    // Start with smallest peak
    let current = new Uint8Array(state.peaks[state.peaks.length - 1]);
    let remaining = state.leafCount;
    let height = countTrailingZeros(remaining);

    // Work backwards through larger peaks
    for (let i = state.peaks.length - 1; i > 0; i--) {
        // Clear lowest set bit to find next peak's height
        remaining &= remaining - 1n;
        const nextHeight = countTrailingZeros(remaining);

        // Duplicate until heights match
        while (height < nextHeight) {
            current = await sha256d(current, current);
            height++;
        }

        // Merge with next larger peak
        current = await sha256d(state.peaks[i - 1], current);
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
 *
 * @param {bigint} index - Bit pattern for orientation
 * @param {Uint8Array} start - Starting hash (leaf)
 * @param {Uint8Array[]} siblings - Sibling hashes, leaf level upward
 * @returns {Promise<Uint8Array>} Computed hash at end of path
 */
async function computePath(index, start, siblings) {
    let current = new Uint8Array(start);
    let idx = index;

    for (const sibling of siblings) {
        if ((idx & 1n) === 1n) {
            current = await sha256d(sibling, current);
        } else {
            current = await sha256d(current, sibling);
        }
        idx >>= 1n;
    }

    return current;
}

/**
 * Find the mountain (peak) containing a given leaf index.
 *
 * @param {bigint} leafIndex - Leaf position
 * @param {bigint} leafCount - Total leaves
 * @returns {{mountainHeight: number, peakIndex: number}}
 */
function getMountain(leafIndex, leafCount) {
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
 *
 * @param {{leafCount: bigint, peaks: Uint8Array[]}} state
 * @param {bigint} leafIndex - Position of leaf being proven
 * @param {Uint8Array} leaf - 32-byte leaf hash
 * @param {Uint8Array[]} siblings - Sibling hashes to peak
 * @returns {Promise<boolean>}
 */
async function verifyProofToPeak(state, leafIndex, leaf, siblings) {
    if (leafIndex < 0n || leafIndex >= state.leafCount) {
        return false;
    }

    const { mountainHeight, peakIndex } = getMountain(leafIndex, state.leafCount);

    if (siblings.length !== mountainHeight) {
        return false;
    }

    const computed = await computePath(leafIndex, leaf, siblings);
    return hashEquals(computed, state.peaks[peakIndex]);
}

/**
 * Verify an inclusion proof against the current root.
 *
 * Proof contains the full path including duplicated siblings from bagging.
 * Proof length always equals bitWidth(leafCount - 1).
 *
 * @param {{leafCount: bigint, peaks: Uint8Array[]}} state
 * @param {bigint} leafIndex - Position of leaf being proven
 * @param {Uint8Array} leaf - 32-byte leaf hash
 * @param {Uint8Array[]} siblings - Sibling hashes to root
 * @returns {Promise<boolean>}
 */
async function verifyProofToRoot(state, leafIndex, leaf, siblings) {
    if (leafIndex < 0n || leafIndex >= state.leafCount) {
        return false;
    }

    const expectedLength = bitWidth(state.leafCount - 1n);
    if (siblings.length !== expectedLength) {
        return false;
    }

    const computed = await computePath(leafIndex, leaf, siblings);
    const root = await getRoot(state);
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
 * @param {bigint} leafCount - Total number of leaves
 * @param {Uint8Array} lastLeaf - 32-byte hash of last leaf
 * @param {Uint8Array[]} siblings - Proof-to-root for last leaf
 * @returns {Promise<{leafCount: bigint, peaks: Uint8Array[]}|null>}
 */
async function bootstrapFromProof(leafCount, lastLeaf, siblings) {
    if (leafCount < 0n) {
        return null;
    }

    if (leafCount === 0n) {
        return siblings.length === 0 ? empty() : null;
    }

    if (leafCount === 1n) {
        return siblings.length === 0
            ? { leafCount: 1n, peaks: [new Uint8Array(lastLeaf)] }
            : null;
    }

    const expectedLength = bitWidth(leafCount - 1n);
    if (siblings.length !== expectedLength) {
        return null;
    }

    const peakCountVal = popcount(leafCount);
    const peaks = new Array(peakCountVal).fill(null);

    let remaining = leafCount;
    let proofIdx = 0;
    let peakIdx = peakCountVal;
    let currentHeight = 0;

    let computed = new Uint8Array(lastLeaf);
    let idx = leafCount - 1n;

    while (remaining > 0n) {
        const peakHeight = countTrailingZeros(remaining);

        // Advance through proof to reach peak height
        while (currentHeight < peakHeight) {
            if ((idx & 1n) === 1n) {
                computed = await sha256d(siblings[proofIdx], computed);
            } else {
                computed = await sha256d(computed, siblings[proofIdx]);
            }
            idx >>= 1n;
            proofIdx++;
            currentHeight++;
        }

        peakIdx--;

        if (peakHeight === 0 && peakIdx === peakCountVal - 1) {
            // Smallest peak is lastLeaf itself
            peaks[peakIdx] = new Uint8Array(lastLeaf);
        } else if (proofIdx < siblings.length) {
            // Next sibling is this peak
            peaks[peakIdx] = new Uint8Array(siblings[proofIdx]);
            // Continue path computation
            if ((idx & 1n) === 1n) {
                computed = await sha256d(siblings[proofIdx], computed);
            } else {
                computed = await sha256d(computed, siblings[proofIdx]);
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
 *
 * @param {{leafCount: bigint, peaks: Uint8Array[]}} state
 * @returns {Uint8Array}
 */
function serialize(state) {
    const result = new Uint8Array(8 + 32 * state.peaks.length);

    // Write leafCount as 8-byte little-endian
    let n = state.leafCount;
    for (let i = 0; i < 8; i++) {
        result[i] = Number(n & 0xFFn);
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
 *
 * @param {Uint8Array} data
 * @returns {{leafCount: bigint, peaks: Uint8Array[]}}
 * @throws {Error} If data length is invalid
 */
function deserialize(data) {
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

    const peaks = [];
    for (let i = 0; i < expectedPeakCount; i++) {
        peaks.push(new Uint8Array(data.slice(8 + 32 * i, 8 + 32 * (i + 1))));
    }

    return { leafCount, peaks };
}

// ============================================================================
// Utilities
// ============================================================================

/**
 * Compare two 32-byte hashes for equality.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
function hashEquals(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/**
 * Compare two states for equality.
 * @param {{leafCount: bigint, peaks: Uint8Array[]}} a
 * @param {{leafCount: bigint, peaks: Uint8Array[]}} b
 * @returns {boolean}
 */
function stateEquals(a, b) {
    if (a.leafCount !== b.leafCount) return false;
    if (a.peaks.length !== b.peaks.length) return false;
    for (let i = 0; i < a.peaks.length; i++) {
        if (!hashEquals(a.peaks[i], b.peaks[i])) return false;
    }
    return true;
}

/**
 * Create a deep copy of a state.
 * @param {{leafCount: bigint, peaks: Uint8Array[]}} state
 * @returns {{leafCount: bigint, peaks: Uint8Array[]}}
 */
function clone(state) {
    return {
        leafCount: state.leafCount,
        peaks: state.peaks.map(p => new Uint8Array(p))
    };
}

// ============================================================================
// Exports
// ============================================================================

export {
    // State creation
    empty,
    create,
    clone,
    isEmpty,
    peakCount,

    // Core operations
    extend,
    build,
    getRoot,

    // Proof verification
    verifyProofToPeak,
    verifyProofToRoot,
    getMountain,
    computePath,

    // Bootstrap
    bootstrapFromProof,

    // Serialization
    serialize,
    deserialize,

    // Utilities
    hashEquals,
    stateEquals,

    // Bit helpers (exported for testing)
    popcount,
    countTrailingOnes,
    countTrailingZeros,
    bitWidth
};
