# Copyright (c) 2026 bitcoincashautist
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
MMRAccumulator Test Suite

Test vectors are loaded from ../../test_vectors/mmr_test_vectors.json

MMRAccumulator (client-side):
  - __init__: rewind, bootstrap_from_last_leaf, test_cve_2012_2459
  - is_empty/clear: accumulator_empty, accumulator_clear
  - extend: root_matches_merkle, two_peaks, rewind, bootstrap_from_last_leaf,
            single_leaf, accumulator_clear, test_cve_2012_2459
  - get_root: accumulator_empty, root_matches_merkle, root_is_peak_power_of_two,
              two_peaks, bootstrap_from_last_leaf, bootstrap_from_proof,
              bootstrap_from_proof_edge_cases, single_leaf, accumulator_clear,
              test_cve_2012_2459
  - peaks: accumulator_empty, root_is_peak_power_of_two, two_peaks, rewind,
           bootstrap_from_proof, bootstrap_from_proof_edge_cases, single_leaf,
           accumulator_clear, test_cve_2012_2459
  - leaf_count: accumulator_empty, root_matches_merkle, two_peaks, rewind, single_leaf,
                bootstrap_from_proof, bootstrap_from_proof_edge_cases, accumulator_clear,
                test_cve_2012_2459
  - peak_count: accumulator_empty, single_leaf, bootstrap_from_proof_edge_cases,
                accumulator_clear
  - is_empty: accumulator_empty, accumulator_clear, bootstrap_from_proof_edge_cases
  - verify_proof_to_peak: accumulator_empty, proof_to_peak, single_leaf,
                          verify_proof_out_of_bounds, verify_proof_wrong_sibling_count,
                          test_cve_2012_2459
  - verify_proof_to_root: accumulator_empty, proof_to_root, single_leaf,
                          verify_proof_out_of_bounds, verify_proof_wrong_sibling_count,
                          test_cve_2012_2459
  - bootstrap_from_proof: bootstrap_from_proof, bootstrap_from_proof_edge_cases,
                          test_cve_2012_2459
  - __eq__: rewind, bootstrap_from_proof, bootstrap_from_proof_edge_cases,
            test_cve_2012_2459
  - Rewind pattern: rewind

Error handling:
  - Out of bounds leaf_index: accumulator_empty, verify_proof_out_of_bounds
  - Wrong proof length: verify_proof_wrong_sibling_count, bootstrap_from_proof_edge_cases
  - Invalid proof for leaf_count: bootstrap_from_proof_edge_cases

Security:
  - CVE-2012-2459 (duplicate subtree attack): test_cve_2012_2459
"""

import json
import pytest
from pathlib import Path
from typing import List

from mmr_accumulator import MMRAccumulator

# ============================================================================
# Helpers
# ============================================================================

def _bit_width(n: int) -> int:
    """
    Return the number of bits needed to represent n.

    Returns 0 for n=0, matching C++ std::bit_width behavior.
    """
    return n.bit_length()

# ============================================================================
# Test Vector Loading
# ============================================================================

VECTORS_PATH = Path(__file__).parent.parent.parent / "test_vectors" / "mmr_test_vectors.json"

ZERO_HASH = bytes(32)

def hex_to_hash_reversed(hex_str: str) -> bytes:
    """Convert a hex string to bytes, reversing for Bitcoin's internal byte order."""
    return bytes.fromhex(hex_str)[::-1]

def hash_to_hex_reversed(hash_bytes: bytes) -> str:
    """Convert bytes to hex string, reversing for Bitcoin's display order."""
    return hash_bytes[::-1].hex()

@pytest.fixture(scope="module")
def vectors():
    """Load test vectors from JSON file."""
    with open(VECTORS_PATH) as f:
        return json.load(f)

@pytest.fixture(scope="module")
def hashes(vectors) -> List[bytes]:
    """Get the first 16 header hashes from test vectors."""
    return [hex_to_hash_reversed(h) for h in vectors["header_segments"]["first_16"]["header_hashes"]]

@pytest.fixture(scope="module")
def forged_hashes(vectors) -> List[bytes]:
    """Get the forged 16 header hashes from test vectors."""
    return [hex_to_hash_reversed(h) for h in vectors["header_segments"]["first_16_forged"]["header_hashes"]]

def build_accumulator(leaves: List[bytes]) -> MMRAccumulator:
    """Build an accumulator from a list of leaf hashes."""
    acc = MMRAccumulator()
    for leaf in leaves:
        acc.extend(leaf)
    return acc

# ============================================================================
# Tests
# ============================================================================

class TestAccumulatorEmpty:
    """Tests for empty accumulator behavior."""

    def test_initial_state(self):
        """Empty accumulator should have correct initial state."""
        acc = MMRAccumulator()
        assert acc.is_empty() is True
        assert acc.leaf_count == 0
        assert acc.peak_count == 0
        assert len(acc.peaks) == 0
        assert acc.get_root() == ZERO_HASH

    def test_reject_proof_verification(self):
        """Empty accumulator should reject all proof verifications."""
        acc = MMRAccumulator()
        assert acc.verify_proof_to_peak(0, ZERO_HASH, []) is False
        assert acc.verify_proof_to_root(0, ZERO_HASH, []) is False

class TestSingleLeaf:
    """Tests for single leaf accumulator."""

    def test_single_leaf(self, hashes):
        """Single leaf accumulator should work correctly."""
        acc = MMRAccumulator()
        acc.extend(hashes[0])

        assert acc.leaf_count == 1
        assert acc.peak_count == 1

        # Single leaf: root equals the leaf itself
        assert acc.get_root() == hashes[0]

        # Single leaf: one peak, which is the leaf
        assert len(acc.peaks) == 1
        assert acc.peaks[0] == hashes[0]

        # Proof to peak: empty (leaf is its own peak)
        assert acc.verify_proof_to_peak(0, hashes[0], []) is True

        # Proof to root: empty (single leaf is root)
        assert acc.verify_proof_to_root(0, hashes[0], []) is True

class TestRootMatchesMerkle:
    """Tests that MMR root matches Bitcoin merkle root."""

    def test_matches_bitcoin_merkle_root(self, vectors):
        """MMR root should match Bitcoin merkle root for blocks with different tx counts."""
        block_keys = ["53066", "57113", "57286"]

        for key in block_keys:
            block = vectors["blocks"][key]
            txids = [hex_to_hash_reversed(tx) for tx in block["tx"]]
            expected_root = hex_to_hash_reversed(block["merkleroot"])

            acc = build_accumulator(txids)

            assert acc.leaf_count == len(txids), f"block {key} leaf count"
            assert acc.get_root() == expected_root, (
                f"block {key} root mismatch: got {hash_to_hex_reversed(acc.get_root())}, "
                f"expected {block['merkleroot']}"
            )

class TestRootIsPeakPowerOfTwo:
    """Tests for power-of-two leaf counts."""

    def test_single_peak_power_of_two(self, vectors):
        """Power of two leaf count should have single peak equal to root."""
        block = vectors["blocks"]["53066"]
        assert len(block["tx"]) == 8

        txids = [hex_to_hash_reversed(tx) for tx in block["tx"]]
        expected_root = hex_to_hash_reversed(block["merkleroot"])

        acc = build_accumulator(txids)

        # Power of two: single peak
        assert len(acc.peaks) == 1
        assert acc.peaks[0] == acc.get_root()
        assert acc.peaks[0] == expected_root

class TestTwoPeaks:
    """Tests for two peaks (10 leaves)."""

    def test_two_peaks(self, vectors):
        """Two peaks should correctly represent 10 leaves."""
        block = vectors["blocks"]["57113"]
        assert len(block["tx"]) == 10

        txids = [hex_to_hash_reversed(tx) for tx in block["tx"]]
        expected_root = hex_to_hash_reversed(block["merkleroot"])

        # Build from first 8 leaves
        acc8 = build_accumulator(txids[:8])
        root8 = acc8.get_root()

        # Build from last 2 leaves (independent accumulator)
        acc2 = build_accumulator(txids[8:10])
        root2 = acc2.get_root()

        # Build from all 10 leaves
        acc10 = build_accumulator(txids)
        root10 = acc10.get_root()

        # Verify peaks match the independently built roots
        assert root8 == acc10.peaks[0]
        assert root2 == acc10.peaks[1]

        # Verify final root matches expected
        assert root10 == expected_root

class TestRewind:
    """Tests for rewind pattern via extend from past state."""

    def test_rewind_pattern(self, vectors):
        """Rewind pattern should work via extend from past state."""
        block = vectors["blocks"]["57286"]
        assert len(block["tx"]) == 11

        txids = [hex_to_hash_reversed(tx) for tx in block["tx"]]

        # Build from first 9 leaves
        acc9 = build_accumulator(txids[:9])

        # Build from all 11 leaves
        acc11 = build_accumulator(txids)

        # Client-side rewind pattern: reconstruct from past state
        candidate = MMRAccumulator(acc9.leaf_count, list(acc9.peaks))
        for leaf in txids[9:11]:
            candidate.extend(leaf)

        assert candidate == acc11

        # Verify peaks match
        assert len(acc9.peaks) == 2  # 9 = b1001: 2 peaks
        assert len(acc11.peaks) == 3  # 11 = b1011: 3 peaks

class TestProofToRoot:
    """Tests for proof-to-root verification."""

    def test_verify_electrum_style_proofs(self, vectors, hashes):
        """Should verify electrum-style proofs to root."""
        proof_keys = [
            "proof_10_0",
            "proof_10_6",
            "proof_10_7",
            "proof_10_8",
            "proof_10_9",
            "proof_10_10",
            "proof_11_11",
            "proof_12_12",
            "proof_15_15",
        ]

        for key in proof_keys:
            tv = vectors["electrum_proofs"][key]
            leaf_count = tv["cp_height"] + 1
            branch = [hex_to_hash_reversed(h) for h in tv["branch"]]
            expected_root = hex_to_hash_reversed(tv["root"])

            # Build accumulator to this leaf count
            acc = build_accumulator(hashes[:leaf_count])

            assert acc.get_root() == expected_root, f"{key}: root mismatch"

            # Verify proof
            assert acc.verify_proof_to_root(tv["height"], hashes[tv["height"]], branch) is True, \
                f"{key}: proof verification failed"

            # Verify invalid proof fails
            if len(branch) > 0:
                bad_proof = list(branch)
                bad_proof[0] = ZERO_HASH
                assert acc.verify_proof_to_root(tv["height"], hashes[tv["height"]], bad_proof) is False, \
                    f"{key}: bad proof should fail"

class TestProofToPeak:
    """Tests for proof-to-peak verification."""

    def test_verify_proofs_to_peak(self, vectors, hashes):
        """Should verify proofs to peak."""
        proof_keys = [
            "proof_10_0",
            "proof_10_6",
            "proof_10_7",
            "proof_10_8",
            "proof_10_9",
            "proof_10_10",
            "proof_11_11",
            "proof_12_12",
            "proof_15_15",
        ]

        for key in proof_keys:
            tv = vectors["electrum_proofs"][key]
            leaf_count = tv["cp_height"] + 1
            branch = [hex_to_hash_reversed(h) for h in tv["branch"]]

            # Build accumulator to this leaf count
            acc = build_accumulator(hashes[:leaf_count])

            # Determine expected mountain height
            remaining = leaf_count
            mountain_start = 0
            mountain_height = 0
            while remaining > 0:
                mountain_height = _bit_width(remaining) - 1
                mountain_size = 1 << mountain_height
                if tv["height"] < mountain_start + mountain_size:
                    break
                mountain_start += mountain_size
                remaining -= mountain_size

            is_lone_peak = tv["height"] == leaf_count - 1 and leaf_count % 2 == 1

            # Extract proof-to-peak from full proof
            peak_proof = [] if is_lone_peak else branch[:mountain_height]

            assert acc.verify_proof_to_peak(tv["height"], hashes[tv["height"]], peak_proof) is True, \
                f"{key}: peak proof verification failed"

            # Verify invalid proof fails
            if len(peak_proof) > 0:
                bad_proof = list(peak_proof)
                bad_proof[0] = ZERO_HASH
                assert acc.verify_proof_to_peak(tv["height"], hashes[tv["height"]], bad_proof) is False, \
                    f"{key}: bad peak proof should fail"

class TestBootstrapFromLastLeaf:
    """Tests for bootstrapping from last leaf proof."""

    def test_bootstrap_and_extend(self, vectors, hashes):
        """Should bootstrap from last leaf proof and extend correctly."""
        tv_10_10 = vectors["electrum_proofs"]["proof_10_10"]
        branch = [hex_to_hash_reversed(h) for h in tv_10_10["branch"]]

        # Branch structure for last-leaf proof when leaf is lone peak
        assert len(branch) == 4
        assert branch[0] == hashes[10]  # self-dup

        # Extract peaks from proof
        peak0 = branch[3]
        peak1 = branch[1]
        peak2 = hashes[10]

        # Construct accumulator from extracted peaks
        acc = MMRAccumulator(11, [peak0, peak1, peak2])
        assert acc.get_root() == hex_to_hash_reversed(tv_10_10["root"])

        # Extend and verify against subsequent proofs
        tv_11_11 = vectors["electrum_proofs"]["proof_11_11"]
        acc.extend(hashes[11])
        assert acc.leaf_count == 12
        assert acc.get_root() == hex_to_hash_reversed(tv_11_11["root"])

        tv_12_12 = vectors["electrum_proofs"]["proof_12_12"]
        acc.extend(hashes[12])
        assert acc.leaf_count == 13
        assert acc.get_root() == hex_to_hash_reversed(tv_12_12["root"])

class TestBootstrapFromProof:
    """Tests for bootstrap_from_proof."""

    def test_bootstrap_matches_reference(self, vectors, hashes):
        """Should bootstrap from proof and match reference accumulator."""
        proof_keys = ["proof_10_10", "proof_11_11", "proof_12_12"]

        for key in proof_keys:
            tv = vectors["electrum_proofs"][key]
            leaf_count = tv["cp_height"] + 1
            branch = [hex_to_hash_reversed(h) for h in tv["branch"]]
            expected_root = hex_to_hash_reversed(tv["root"])

            # Build reference accumulator
            ref_acc = build_accumulator(hashes[:leaf_count])

            # Bootstrap from proof
            bootstrapped = MMRAccumulator.bootstrap_from_proof(
                leaf_count,
                hashes[leaf_count - 1],
                branch
            )

            assert bootstrapped is not None, f"{key}: bootstrap failed"
            assert bootstrapped.leaf_count == leaf_count, f"{key}: leaf count mismatch"
            assert bootstrapped.get_root() == expected_root, f"{key}: root mismatch"
            assert bootstrapped == ref_acc, f"{key}: state mismatch"

            # Verify peaks match
            assert bootstrapped.peaks == ref_acc.peaks, f"{key}: peaks mismatch"

            # Extend and verify sync
            if leaf_count < len(hashes):
                ref_acc.extend(hashes[leaf_count])
                bootstrapped.extend(hashes[leaf_count])
                assert bootstrapped == ref_acc, f"{key}: extended state mismatch"

class TestBootstrapFromProofEdgeCases:
    """Tests for bootstrap_from_proof edge cases."""

    def test_empty_accumulator(self):
        """Should handle empty accumulator."""
        result = MMRAccumulator.bootstrap_from_proof(0, ZERO_HASH, [])
        assert result is not None
        assert result.leaf_count == 0
        assert result.is_empty() is True
        assert result.get_root() == ZERO_HASH

    def test_single_leaf(self, hashes):
        """Should handle single leaf."""
        result = MMRAccumulator.bootstrap_from_proof(1, hashes[0], [])
        assert result is not None
        assert result.leaf_count == 1
        assert result.peak_count == 1
        assert result.get_root() == hashes[0]

    def test_reject_invalid_cases(self, hashes):
        """Should reject invalid cases."""
        # leaf_count=2 requires non-empty proof
        assert MMRAccumulator.bootstrap_from_proof(2, hashes[1], []) is None

        # leaf_count=0 shouldn't have proof
        assert MMRAccumulator.bootstrap_from_proof(0, ZERO_HASH, [hashes[0]]) is None

        # leaf_count=1 shouldn't have proof
        assert MMRAccumulator.bootstrap_from_proof(1, hashes[0], [hashes[1]]) is None

    def test_reject_wrong_proof_length(self, vectors, hashes):
        """Should reject wrong proof length."""
        tv = vectors["electrum_proofs"]["proof_10_10"]
        branch = [hex_to_hash_reversed(h) for h in tv["branch"]]

        short_proof = branch[:-1]
        assert MMRAccumulator.bootstrap_from_proof(11, hashes[10], short_proof) is None

        long_proof = branch + [ZERO_HASH]
        assert MMRAccumulator.bootstrap_from_proof(11, hashes[10], long_proof) is None

    def test_power_of_two(self, hashes):
        """Should handle power of two (8 leaves)."""
        acc8 = build_accumulator(hashes[:8])
        assert acc8.leaf_count == 8
        assert acc8.peak_count == 1

        # The proof for last leaf (index 7) in 8-leaf tree needs 3 siblings
        # Since we can't generate proofs without server MMR, we verify the structure
        assert len(acc8.peaks) == 1
        assert acc8.peaks[0] == acc8.get_root()

class TestAccumulatorClear:
    """Tests for accumulator clear."""

    def test_clear_to_empty(self, hashes):
        """Should clear accumulator to empty state."""
        acc = build_accumulator(hashes[:5])
        assert acc.leaf_count == 5
        assert acc.is_empty() is False

        acc.clear()

        assert acc.is_empty() is True
        assert acc.leaf_count == 0
        assert acc.peak_count == 0
        assert len(acc.peaks) == 0
        assert acc.get_root() == ZERO_HASH

        # Extend after clear
        acc.extend(hashes[0])
        assert acc.leaf_count == 1
        assert acc.get_root() == hashes[0]

class TestVerifyProofOutOfBounds:
    """Tests for out of bounds leaf index."""

    def test_reject_out_of_bounds(self, hashes):
        """Should reject proofs with out of bounds leaf index."""
        acc = build_accumulator(hashes[:8])

        assert acc.verify_proof_to_peak(8, hashes[0], []) is False
        assert acc.verify_proof_to_root(8, hashes[0], []) is False
        assert acc.verify_proof_to_peak(1000, hashes[0], []) is False
        assert acc.verify_proof_to_root(1000, hashes[0], []) is False
        assert acc.verify_proof_to_peak(18446744073709551615, hashes[0], []) is False
        assert acc.verify_proof_to_root(18446744073709551615, hashes[0], []) is False

class TestVerifyProofWrongSiblingCount:
    """Tests for wrong sibling count."""

    def test_reject_wrong_sibling_count(self, vectors, hashes):
        """Should reject proofs with wrong sibling count."""
        acc = build_accumulator(hashes[:8])

        # For 8 leaves (power of 2), proof for index 0 needs 3 siblings
        tv = vectors["electrum_proofs"]["proof_10_0"]
        branch = [hex_to_hash_reversed(h) for h in tv["branch"]]
        valid_peak_proof = branch[:3]  # First 3 for 8-leaf subtree

        # Short proof
        short_proof = valid_peak_proof[:-1]
        assert acc.verify_proof_to_peak(0, hashes[0], short_proof) is False
        assert acc.verify_proof_to_root(0, hashes[0], short_proof) is False

        # Long proof
        long_proof = valid_peak_proof + [ZERO_HASH]
        assert acc.verify_proof_to_peak(0, hashes[0], long_proof) is False
        assert acc.verify_proof_to_root(0, hashes[0], long_proof) is False

        # Empty proof (should fail for non-trivial tree)
        assert acc.verify_proof_to_peak(0, hashes[0], []) is False
        assert acc.verify_proof_to_root(0, hashes[0], []) is False

class TestCVE_2012_2459:
    """Tests for CVE-2012-2459 duplicate subtree attack."""

    def test_cve_defense(self, vectors, hashes, forged_hashes):
        """Should demonstrate and defend against CVE-2012-2459 attack."""
        cve = vectors["cve_2012_2459"]
        expected_root = hex_to_hash_reversed(cve["root"])

        assert len(hashes) == 16
        assert len(forged_hashes) == 16
        assert cve["real_leaf_count"] == 11
        assert cve["forged_leaf_count"] == 16

        # Verify forged hashes match expected duplicates
        for mapping in cve["forged_proof_mappings"]:
            assert forged_hashes[mapping["forged_index"]] == forged_hashes[mapping["real_index"]], \
                f"forged[{mapping['forged_index']}] should equal forged[{mapping['real_index']}]"

        # =========================================================================
        # Setup
        # =========================================================================

        acc11 = build_accumulator(hashes[:11])
        acc16 = build_accumulator(hashes[:16])
        acc_forged16 = build_accumulator(forged_hashes[:16])

        # Core attack premise: same root for different leaf counts
        assert acc11.get_root() == expected_root
        assert acc_forged16.get_root() == expected_root

        # =========================================================================
        # Test 1: verify_proof_to_root rejects forged proofs
        # =========================================================================

        for mapping in cve["forged_proof_mappings"]:
            tv = vectors["electrum_proofs"][mapping["proof_key"]]
            forged_proof = [hex_to_hash_reversed(h) for h in tv["branch"]]

            # Forged proof should be rejected (CVE-2012-2459 protection)
            assert acc16.verify_proof_to_root(
                mapping["forged_index"],
                forged_hashes[mapping["forged_index"]],
                forged_proof
            ) is False, f"forged proof for index {mapping['forged_index']} should be rejected"

            # Legitimate proof for real index should pass
            real_tv = vectors["electrum_proofs"][mapping["proof_key"]]
            real_proof = [hex_to_hash_reversed(h) for h in real_tv["branch"]]
            real_acc = build_accumulator(hashes[:real_tv["cp_height"] + 1])

            assert real_acc.verify_proof_to_root(
                real_tv["height"],
                hashes[real_tv["height"]],
                real_proof
            ) is True, f"real proof for index {real_tv['height']} should pass"

        # =========================================================================
        # Test 2: verify_proof_to_peak behavior
        # =========================================================================

        # Build forged accumulator with 15 leaves
        acc_forged15 = build_accumulator(forged_hashes[:15])
        assert acc_forged15.leaf_count == 15

        # Different peaks, same root (attack premise)
        assert acc11.peaks != acc_forged15.peaks
        assert acc11.get_root() == acc_forged15.get_root()

        # =========================================================================
        # Test 3: bootstrap_from_proof rejects forged proofs
        # =========================================================================

        tv_10_10 = vectors["electrum_proofs"]["proof_10_10"]
        proof_10_in_11 = [hex_to_hash_reversed(h) for h in tv_10_10["branch"]]

        bootstrap_11 = MMRAccumulator.bootstrap_from_proof(11, hashes[10], proof_10_in_11)
        assert bootstrap_11 is not None
        assert bootstrap_11 == acc11

        # Same proof used as forged proof for index 15 in 16-leaf tree should be rejected
        # because forged_hashes[15] == hashes[10] (the duplicate)
        bootstrap_forged = MMRAccumulator.bootstrap_from_proof(16, forged_hashes[15], proof_10_in_11)
        assert bootstrap_forged is None, "forged bootstrap should be rejected"

        # Real proof for leaf 15 in real 16-leaf tree should work
        tv_15_15 = vectors["electrum_proofs"]["proof_15_15"]
        proof_15_real = [hex_to_hash_reversed(h) for h in tv_15_15["branch"]]
        bootstrap_16 = MMRAccumulator.bootstrap_from_proof(16, hashes[15], proof_15_real)
        assert bootstrap_16 is not None
        assert bootstrap_16 == acc16

class TestInputValidation:
    """Tests for input validation."""

    def test_reject_invalid_hash_lengths_in_verification(self, hashes):
        """Should reject invalid hash lengths in verification."""
        acc = build_accumulator(hashes[:8])
        short_hash = bytes(31)
        long_hash = bytes(33)

        assert acc.verify_proof_to_peak(0, short_hash, []) is False
        assert acc.verify_proof_to_peak(0, long_hash, []) is False
        assert acc.verify_proof_to_root(0, short_hash, []) is False
        assert acc.verify_proof_to_root(0, long_hash, []) is False

        # Invalid sibling length
        assert acc.verify_proof_to_peak(0, hashes[0], [short_hash]) is False
        assert acc.verify_proof_to_root(0, hashes[0], [short_hash]) is False

    def test_reject_invalid_hash_lengths_in_bootstrap(self, hashes):
        """Should reject invalid hash lengths in bootstrap."""
        short_hash = bytes(31)
        assert MMRAccumulator.bootstrap_from_proof(1, short_hash, []) is None
        assert MMRAccumulator.bootstrap_from_proof(2, hashes[0], [short_hash]) is None

    def test_throw_on_invalid_input_to_init(self, hashes):
        """Should raise on invalid input to __init__."""
        with pytest.raises(ValueError, match="non-negative"):
            MMRAccumulator(-1, [])
        with pytest.raises(ValueError, match="requires 2 peaks"):
            MMRAccumulator(3, [hashes[0]])
        with pytest.raises(ValueError, match="32 bytes"):
            MMRAccumulator(1, [bytes(31)])

    def test_throw_on_invalid_input_to_extend(self, hashes):
        """Should raise on invalid input to extend."""
        acc = MMRAccumulator()
        with pytest.raises(ValueError, match="32 bytes"):
            acc.extend(bytes(31))

class TestNegativeLeafIndex:
    """Tests for negative leaf index."""

    def test_reject_negative_indices(self, hashes):
        """Should reject negative leaf indices."""
        acc = build_accumulator(hashes[:8])
        assert acc.verify_proof_to_peak(-1, hashes[0], []) is False
        assert acc.verify_proof_to_root(-1, hashes[0], []) is False

class TestSerialization:
    """Tests for serialization/deserialization."""

    def test_roundtrip(self, hashes):
        """Serialize and deserialize should produce equal accumulator."""
        acc = build_accumulator(hashes[:11])
        serialized = acc.serialize()
        restored = MMRAccumulator.deserialize(serialized)

        assert restored == acc
        assert restored.leaf_count == acc.leaf_count
        assert restored.peaks == acc.peaks
        assert restored.get_root() == acc.get_root()

    def test_empty_roundtrip(self):
        """Empty accumulator should roundtrip correctly."""
        acc = MMRAccumulator()
        serialized = acc.serialize()
        restored = MMRAccumulator.deserialize(serialized)

        assert restored == acc
        assert restored.is_empty() is True

    def test_deserialize_invalid_length(self):
        """Should reject data with invalid length."""
        with pytest.raises(ValueError, match="at least 8 bytes"):
            MMRAccumulator.deserialize(bytes(7))

        # Valid header but wrong peak count
        data = (11).to_bytes(8, 'little') + bytes(32)  # 11 needs 3 peaks, not 1
        with pytest.raises(ValueError, match="expected"):
            MMRAccumulator.deserialize(data)

class TestEquality:
    """Tests for equality comparison."""

    def test_equal_accumulators(self, hashes):
        """Equal accumulators should compare equal."""
        acc1 = build_accumulator(hashes[:8])
        acc2 = build_accumulator(hashes[:8])
        assert acc1 == acc2

    def test_different_leaf_count(self, hashes):
        """Different leaf counts should not be equal."""
        acc1 = build_accumulator(hashes[:8])
        acc2 = build_accumulator(hashes[:9])
        assert acc1 != acc2

    def test_different_peaks(self, hashes):
        """Different peaks should not be equal."""
        acc1 = build_accumulator(hashes[:8])
        acc2 = MMRAccumulator(8, [bytes(32)])  # Same count, different peak
        assert acc1 != acc2

    def test_not_equal_to_other_types(self, hashes):
        """Should not be equal to other types."""
        acc = build_accumulator(hashes[:8])
        assert (acc == "not an accumulator") is False
        assert (acc == 42) is False
        assert (acc == None) is False
