# Copyright (c) 2026 bitcoincashautist
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

r"""
MMR Accumulator for Simplified Header Verification (SHV) clients.

Maintains only the minimal state needed to verify proofs and extend the MMR:
the leaf count and the peaks (one per set bit in the binary representation
of leaf_count). This is O(log n) storage for n leaves.

Unlike server-side MMR which stores all internal nodes for proof generation,
this class stores only peaks, making it suitable for light clients.

Example with 11 leaves (indices 0-10):

           [6]
        _ /   \ _
      /           \
     2             5
   /   \         /   \
  0     1       3     4      [7]
 / \   / \     / \   / \     / \
0   1 2   3   4   5 6   7   8   9  [10]

Peaks marked with []: [6], [7], [10].
For leaf_count = 11 (binary 1011), the accumulator stores 3 peaks:

- peaks[0]: node 6, height-3 peak covering leaves 0-7
- peaks[1]: node 7, height-1 peak covering leaves 8-9
- peaks[2]: leaf 10, height-0 peak (the leaf hash itself)

Peaks are ordered from tallest to shortest (left to right in the tree).
The number of peaks equals popcount(leaf_count).

Input Validation Philosophy
---------------------------
Functions that construct or modify accumulator state (__init__, extend)
raise exceptions on invalid input, as they are expected to be called with
trusted/validated data.

Functions that verify untrusted proofs (verify_proof_to_peak, verify_proof_to_root,
bootstrap_from_proof) return False or None on invalid input, as they must
handle adversarial data gracefully without raising exceptions.
"""

from __future__ import annotations

import hashlib
from typing import List, Optional

def _popcount(n: int) -> int:
    """Return the number of set bits in n."""
    return bin(n).count('1')

def _countr_one(n: int) -> int:
    """Return the count of trailing one bits in n."""
    if n == 0:
        return 0
    count = 0
    while n & 1:
        count += 1
        n >>= 1
    return count

def _countr_zero(n: int) -> int:
    """
    Return the count of trailing zero bits in n.

    Returns 64 for n=0, matching C++ std::countr_zero<uint64_t> behavior.
    """
    if n == 0:
        return 64
    count = 0
    while not (n & 1):
        count += 1
        n >>= 1
    return count

def _bit_width(n: int) -> int:
    """
    Return the number of bits needed to represent n.

    Returns 0 for n=0, matching C++ std::bit_width behavior.
    """
    return n.bit_length()

def _sha256d(left: bytes, right: bytes) -> bytes:
    """
    Compute SHA256d of concatenated inputs.

    This is the standard Bitcoin merged node hash: SHA256(SHA256(left || right)).
    """
    return hashlib.sha256(hashlib.sha256(left + right).digest()).digest()

class MMRAccumulator:
    """
    Client-side MMR accumulator for Simplified Header Verification.

    Maintains the minimal state needed to verify Merkle proofs and extend
    the MMR: just the leaf count and peak hashes. Storage is O(log n) for
    n leaves.

    Uses Bitcoin-style double-SHA256 hashing and supports Bitcoin's Merkle
    tree construction where unpaired nodes are duplicated.

    Attributes:
        leaf_count: Number of leaves in the MMR.
        peak_count: Number of peaks (equals popcount of leaf_count).
        peaks: List of peak hashes, ordered tallest to shortest.
    """

    __slots__ = ('_leaf_count', '_peaks')

    def __init__(
        self,
        leaf_count: int = 0,
        peaks: Optional[List[bytes]] = None
    ) -> None:
        """
        Initialize accumulator with given state.

        Args:
            leaf_count: Number of leaves. Must be non-negative.
            peaks: Peak hashes ordered tallest to shortest. Length must
                equal popcount(leaf_count). Each peak must be 32 bytes.

        Raises:
            ValueError: If leaf_count is negative, peak count doesn't
                match popcount(leaf_count), or any peak is not 32 bytes.
        """
        if peaks is None:
            peaks = []

        if leaf_count < 0:
            raise ValueError(f"leaf_count must be non-negative, got {leaf_count}")

        expected_peak_count = _popcount(leaf_count)
        if len(peaks) != expected_peak_count:
            raise ValueError(
                f"leaf_count {leaf_count} requires {expected_peak_count} peaks, "
                f"got {len(peaks)}"
            )

        for i, peak in enumerate(peaks):
            if not isinstance(peak, (bytes, bytearray)) or len(peak) != 32:
                raise ValueError(f"peak[{i}] must be 32 bytes")

        self._leaf_count = leaf_count
        self._peaks: List[bytes] = [bytes(p) for p in peaks]

    @property
    def leaf_count(self) -> int:
        """Return the number of leaves in the accumulator."""
        return self._leaf_count

    @property
    def peak_count(self) -> int:
        """Return the number of peaks stored."""
        return len(self._peaks)

    @property
    def peaks(self) -> List[bytes]:
        """Return a copy of the peaks, ordered tallest to shortest."""
        return list(self._peaks)

    def is_empty(self) -> bool:
        """Return True if the accumulator contains no leaves."""
        return self._leaf_count == 0

    def clear(self) -> None:
        """Reset the accumulator to its initial empty state."""
        self._leaf_count = 0
        self._peaks.clear()

    def extend(self, leaf: bytes) -> None:
        """
        Append a new leaf to the accumulator.

        The number of merges equals the trailing 1-bits in the current
        leaf count. For example, with leaf_count=11 (binary 1011), there
        are two trailing 1-bits, so two merges occur before appending.

        Args:
            leaf: The 32-byte hash of the new leaf (typically a block hash).

        Raises:
            ValueError: If leaf is not 32 bytes.
        """
        if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != 32:
            raise ValueError(f"leaf must be 32 bytes, got {len(leaf) if isinstance(leaf, (bytes, bytearray)) else type(leaf)}")

        merge_count = _countr_one(self._leaf_count)
        current = bytes(leaf)

        for _ in range(merge_count):
            current = _sha256d(self._peaks.pop(), current)

        self._peaks.append(current)
        self._leaf_count += 1

    def get_root(self) -> bytes:
        """
        Compute the Bitcoin-style Merkle root.

        Bags peaks from smallest to largest, duplicating nodes as needed
        to match heights before merging. This produces the same root as
        Bitcoin's Merkle tree construction where unpaired nodes are
        duplicated.

        Returns:
            32 zero bytes if empty, the single peak if only one exists,
            otherwise the bagged root hash.
        """
        if self._leaf_count == 0:
            return bytes(32)

        if len(self._peaks) == 1:
            return self._peaks[0]

        # Start with the smallest peak (rightmost in tree, last in array).
        current = self._peaks[-1]
        remaining = self._leaf_count
        height = _countr_zero(remaining)

        # Work backwards through progressively larger peaks.
        for i in range(len(self._peaks) - 1, 0, -1):
            # Clear lowest set bit to find next peak's height.
            remaining &= remaining - 1
            next_height = _countr_zero(remaining)

            # Duplicate until heights match (Bitcoin-style balancing).
            while height < next_height:
                current = _sha256d(current, current)
                height += 1

            # Merge with next larger peak.
            current = _sha256d(self._peaks[i - 1], current)
            height += 1

        return current

    def verify_proof_to_peak(
        self,
        leaf_index: int,
        leaf: bytes,
        siblings: List[bytes]
    ) -> bool:
        """
        Verify an inclusion proof against the appropriate peak.

        The proof length must equal the height of the mountain containing
        the leaf. The proof may be empty when the leaf is a lone peak
        (occurs when leaf_index == leaf_count - 1 and leaf_count is odd).

        No CVE-2012-2459 check is needed: proof-to-peak verifies against
        trusted accumulator state, which has 1-to-1 mapping with leaf
        sequence, even if there are duplicate leaves.

        Args:
            leaf_index: Zero-based position of the leaf being proven.
            leaf: The 32-byte leaf hash being proven.
            siblings: Sibling hashes from leaf level upward to peak.

        Returns:
            True if the computed path matches the expected peak.
            False if inputs are malformed or proof is invalid.
        """
        # Input validation.
        if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != 32:
            return False
        for sibling in siblings:
            if not isinstance(sibling, (bytes, bytearray)) or len(sibling) != 32:
                return False

        # Malformed proof check.
        if leaf_index < 0 or leaf_index >= self._leaf_count:
            return False

        # Find which mountain (peak) covers this leaf by iterating through
        # mountains left to right. Each mountain's size is a power of two
        # determined by the highest set bit in the remaining leaf count.
        remaining = self._leaf_count
        mountain_start = 0
        mountain_height = 0
        peak_index = 0

        while remaining > 0:
            mountain_height = _bit_width(remaining) - 1
            mountain_size = 1 << mountain_height

            if leaf_index < mountain_start + mountain_size:
                break

            mountain_start += mountain_size
            remaining -= mountain_size
            peak_index += 1

        # Malformed proof check.
        if len(siblings) != mountain_height:
            return False

        # Compute path to peak. Path computation uses leaf_index directly
        # because only the lowest mountain_height bits matter for orientation,
        # and these bits are identical to the local offset within the mountain.
        current = leaf
        idx = leaf_index

        for sibling in siblings:
            if idx & 1:
                current = _sha256d(sibling, current)
            else:
                current = _sha256d(current, sibling)
            idx >>= 1

        return current == self._peaks[peak_index]

    def verify_proof_to_root(
        self,
        leaf_index: int,
        leaf: bytes,
        siblings: List[bytes]
    ) -> bool:
        """
        Verify an inclusion proof against the current root.

        The proof contains the full path from leaf to root, including
        duplicated siblings from the bagging process. The proof length
        is always bit_width(leaf_count - 1), which equals the height of
        the bagged tree. The proof is empty only when leaf_count == 1.

        Args:
            leaf_index: Zero-based position of the leaf being proven.
            leaf: The 32-byte leaf hash being proven.
            siblings: Sibling hashes from leaf level upward to root.

        Returns:
            True if the computed path matches get_root().
            False if inputs are malformed or proof is invalid.
        """
        # Input validation.
        if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != 32:
            return False
        for sibling in siblings:
            if not isinstance(sibling, (bytes, bytearray)) or len(sibling) != 32:
                return False

        # Malformed proof check.
        if leaf_index < 0 or leaf_index >= self._leaf_count:
            return False

        # Malformed proof check && trivial verification if well formed.
        if self._leaf_count == 1:
            return len(siblings) == 0 and leaf == self._peaks[0]

        # Malformed proof check.
        expected_length = _bit_width(self._leaf_count - 1)
        if len(siblings) != expected_length:
            return False

        # Compute path to root with CVE-2012-2459 protection.
        # The attack exploits bagging ambiguity: multiple MMR states can produce
        # the same root, allowing forged proofs for phantom positions. We detect
        # this by rejecting left-sibling duplicates, which only occur in forged
        # proofs (legitimate duplicates from bagging appear as right siblings).
        current = leaf
        idx = leaf_index

        for sibling in siblings:
            if (idx & 1) and sibling == current:
                return False
            if idx & 1:
                current = _sha256d(sibling, current)
            else:
                current = _sha256d(current, sibling)
            idx >>= 1

        return current == self.get_root()

    @classmethod
    def bootstrap_from_proof(
        cls,
        leaf_count: int,
        last_leaf: bytes,
        siblings: List[bytes]
    ) -> Optional[MMRAccumulator]:
        """
        Initialize an accumulator from a proof-to-root for the last leaf.

        The proof contains all MMR peaks as siblings along the path,
        interleaved with duplicates from the bagging process. This allows
        a client to bootstrap from just the last leaf and its proof.

        Args:
            leaf_count: Total number of leaves in the MMR.
            last_leaf: The 32-byte hash of the last leaf (at index leaf_count - 1).
            siblings: Proof-to-root siblings for the last leaf.

        Returns:
            MMRAccumulator with extracted peaks, or None if inputs are
            malformed or proof structure is invalid.
        """
        # Input validation.
        if not isinstance(last_leaf, (bytes, bytearray)) or len(last_leaf) != 32:
            return None
        for sibling in siblings:
            if not isinstance(sibling, (bytes, bytearray)) or len(sibling) != 32:
                return None

        # Edge cases.
        if leaf_count < 0:
            return None

        if leaf_count == 0:
            if len(siblings) != 0:
                return None
            return cls(0, [])

        # Trivial verification and initialization.
        if leaf_count == 1:
            if len(siblings) != 0:
                return None
            return cls(1, [bytes(last_leaf)])

        # Malformed proof check.
        expected_length = _bit_width(leaf_count - 1)
        if len(siblings) != expected_length:
            return None

        peak_count = _popcount(leaf_count)
        peaks: List[Optional[bytes]] = [None] * peak_count

        remaining = leaf_count
        proof_idx = 0
        peak_idx = peak_count
        current_height = 0

        # Track path computation for extracting the root as the only peak
        # when leaf count is power of two.
        computed = bytes(last_leaf)
        idx = leaf_count - 1

        # We must guard against CVE-2012-2459 throughout the whole path
        # (path segments inside & outside MMR structure) because MMR
        # structure is determined from leaf_count, and it cannot be trusted.

        while remaining > 0:
            peak_height = _countr_zero(remaining)

            # Advance through proof to reach peak height.
            while current_height < peak_height:
                sibling = siblings[proof_idx]

                # CVE-2012-2459 (proof-to-peak segment).
                if (idx & 1) and sibling == computed:
                    return None

                if idx & 1:
                    computed = _sha256d(sibling, computed)
                else:
                    computed = _sha256d(computed, sibling)
                idx >>= 1
                proof_idx += 1
                current_height += 1

            peak_idx -= 1

            if peak_height == 0 and peak_idx == peak_count - 1:
                # Smallest peak is the last_leaf itself.
                peaks[peak_idx] = bytes(last_leaf)
            elif proof_idx < len(siblings):
                # Next sibling in proof is this peak.
                peaks[peak_idx] = bytes(siblings[proof_idx])

                # CVE-2012-2459 (proof-to-root segment).
                if (idx & 1) and siblings[proof_idx] == computed:
                    return None

                if idx & 1:
                    computed = _sha256d(siblings[proof_idx], computed)
                else:
                    computed = _sha256d(computed, siblings[proof_idx])
                idx >>= 1
                proof_idx += 1
                current_height += 1
            else:
                # Exhausted proof; computed value is the final peak (root).
                peaks[peak_idx] = computed

            remaining &= remaining - 1

        return cls(leaf_count, peaks)  # type: ignore[arg-type]

    def serialize(self) -> bytes:
        """
        Serialize the accumulator for storage or transmission.

        Format: 8-byte little-endian leaf_count followed by concatenated
        32-byte peak hashes (tallest to shortest).

        Returns:
            Serialized bytes that can be restored with deserialize().
        """
        result = bytearray(self._leaf_count.to_bytes(8, 'little'))
        for peak in self._peaks:
            result.extend(peak)
        return bytes(result)

    @classmethod
    def deserialize(cls, data: bytes) -> MMRAccumulator:
        """
        Restore an accumulator from serialized bytes.

        Args:
            data: Bytes previously produced by serialize().

        Returns:
            Restored MMRAccumulator instance.

        Raises:
            ValueError: If data length doesn't match expected size for
                the encoded leaf_count.
        """
        if len(data) < 8:
            raise ValueError(f"need at least 8 bytes, got {len(data)}")

        leaf_count = int.from_bytes(data[:8], 'little')
        peak_count = _popcount(leaf_count)
        expected_length = 8 + 32 * peak_count

        if len(data) != expected_length:
            raise ValueError(f"expected {expected_length} bytes, got {len(data)}")

        peaks = [data[8 + 32 * i : 8 + 32 * (i + 1)] for i in range(peak_count)]
        return cls(leaf_count, peaks)

    def __eq__(self, other: object) -> bool:
        """Return True if both accumulators have identical state."""
        if not isinstance(other, MMRAccumulator):
            return NotImplemented
        return (
            self._leaf_count == other._leaf_count
            and self._peaks == other._peaks
        )

    def __repr__(self) -> str:
        """Return detailed string representation for debugging."""
        if not self._peaks:
            return "MMRAccumulator(leaf_count=0, peaks=[])"
        peak_previews = [p.hex()[:16] + '...' for p in self._peaks]
        return f"MMRAccumulator(leaf_count={self._leaf_count}, peaks={peak_previews})"

    def __str__(self) -> str:
        """Return concise string representation."""
        return f"MMRAccumulator({self._leaf_count} leaves, {len(self._peaks)} peaks)"
