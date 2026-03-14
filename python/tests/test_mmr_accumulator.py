# Copyright (c) 2026 bitcoincashautist
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
MMR Accumulator Test Suite

Tests mirror the C++ test suite structure:

MMRAccumulator:
  - Constructor: test_constructor_validation
  - Extend: test_root_matches_merkle, test_two_peaks, test_single_leaf,
            test_eleven_leaves, test_power_of_two_leaves
  - GetRoot: test_accumulator_empty, test_root_matches_merkle,
             test_root_is_peak_power_of_two, test_two_peaks, test_single_leaf,
             test_root_with_three_leaves
  - GetPeaks: test_accumulator_empty, test_root_is_peak_power_of_two,
              test_two_peaks, test_single_leaf, test_eleven_leaves
  - VerifyProofToPeak: test_accumulator_empty, test_proof_to_peak,
                       test_verify_proof_to_peak_*, test_proof_wrong_length
  - VerifyProofToRoot: test_accumulator_empty, test_proof_to_root,
                       test_verify_proof_to_root_*
  - BootstrapFromProof: test_bootstrap_from_proof, test_bootstrap_from_proof_edge_cases
  - Equality: test_equality_*
  - Serialization: test_serialize_*
  - Other: test_clear, test_repr, test_str
"""

from __future__ import annotations

import unittest
import hashlib
from typing import Dict, List, Tuple

from mmr_accumulator import MMRAccumulator
from mmr_accumulator.mmr_accumulator import (
    _sha256d,
    _popcount,
    _countr_one,
    _countr_zero,
    _bit_width,
)

def make_leaf(n: int) -> bytes:
    """Create a deterministic 32-byte leaf hash from an integer."""
    return hashlib.sha256(n.to_bytes(8, 'little')).digest()

# =============================================================================
# Test Vectors from C++ tests
# =============================================================================

# Block with 8 transactions: b1000
BLOCK_53066: Dict[str, object] = {
    "merkleroot": "271eafea9cfeb730c6fae8c39da387b37967646d26224a10878e04f3f6212fbe",
    "tx": [
        "e0598db6abb41bf57ee0019c23520121565d2217eb9ae91d2114199fec5ac41d",
        "1001d10ddf64509c1548125ca3120f32355e8af588fe6724aa5dc033e699a617",
        "3cd17728f2e9152cc908976701a28e910838a86fe5b745af74bd5b373aff6e1d",
        "7d8514357058d8b1a08d51bbca54329b7dbafc5c2e792f99c38e67297fda2c28",
        "32a83b09394f17131074360c6628147bfb3eaf0f57000bc416da7bce140c74dd",
        "4e3a183b09d35e5adeed6d12c880b46486db3f25869c939269770268a7bd5298",
        "8fb3751403381c11979f8b0d9fac7b121ad49561c6a07645e58da7d5ab5bf8f8",
        "c429d280b4f74e016c358d8bb3a909889ee23b058c26767f14384d9ff8d9b8f4",
    ],
}

# Block with 10 transactions: b1010
BLOCK_57113: Dict[str, object] = {
    "merkleroot": "dd9bfa795a0dfe64975eb03fddf8419e03f48fe6b5a97aa736b2536c035df864",
    "tx": [
        "f24cf73bba7fdc286201060ffe0b433c2c2dfc74110e7f9a7e02a50dae1fee7a",
        "3c2512fc8473ae119beca8556f6be65cb358d3f25e6d063057fa676c1a642c4c",
        "aa397b27bed2a9577df83eb6bbc7d6bdfb108ccfe346d204eb9bc839472a3bb7",
        "bcd3bff748813ad6b5c3137cc6b2f5563700fe858cda6fa534f38cb986f2f1ea",
        "d9a8e7e04aec530604a1f9ed66e302591e7395bb2f7477261949eefaea34de92",
        "26fca71da3aa89507d7eeae052ff326d0a2b76d4228774ddbd78fbaf9aafa67d",
        "90aa27025d52c9032a15db22e44b6f810b2e9dd1639cac461864adf863063c28",
        "9b2857b0e22af35974e5e551dabd0160b0b1a18a02e67c21ea93c5cb35e2217d",
        "5158cb8b66c60c0db90a23f8c7945b8634835b52f1e669a9fb4e883e40a1d82f",
        "8eb65266588615fd7c35f5152748fb63f5668c60017ac82e0213f840a9efb718",
    ],
}

# Block with 11 transactions: b1011
BLOCK_57286: Dict[str, object] = {
    "merkleroot": "23d97ad1b6e828398aff13122e312883c47986e8c8a9d1f4042876fa2e9e1fe4",
    "tx": [
        "e17e4987fb4565e496c4751d44f52aca00eed2387379669f039bf04ae174048b",
        "03a5497d96f8f39cdac8761e7bfa21049816378c6bdf331921c607093ec8474b",
        "2c43eebedbd5529b4c9496f08d31d5d22aa7b061aa5efa6d45f1d8efe611150d",
        "3d2a352ca353760d2d8fc2b10e9944789f1ea0ea2a8ca340fe7a426c1f5008cb",
        "4a225d19c0bf7ed70433a8c9acfb239e160414e1ed0c6733c051111f624dd78b",
        "6227326e6c5035ad1bc5c61c78c27223bfe5694c797bd974cf296e509162777f",
        "9bf4cc2687cb85712e964f23bc48b8a90ede1b1a985e35ee7601af137631c3a2",
        "b0c940c008ff0ee11c1babea4d92da387b563fdbb2b15a5f693567b44575dc36",
        "b6eee3a4f98271224e205fcf56a76fc55bfffcabe1b0121348cbc038601338e2",
        "b7d9686a8310881505e6853d13c4ae31dd52c925e729d3b4975120436e6ca56e",
        "f651523681ff86796635cb0671bf01a5f35c41b1804d3f6cce903257bb41768e",
    ],
}

TEST_BLOCKS = [BLOCK_53066, BLOCK_57113, BLOCK_57286]

# Proof test vectors from Electrum protocol.
# Format: blockchain.block.header response with cp_height parameter.

# cp_height=10, height=0: first leaf in 8-leaf mountain
PROOF_10_0: Dict[str, object] = {
    "branch": [
        "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        "f2a2a2907abb326726a2d6500fe494f63772a941b414236c302e920bc1aa9caf",
        "0e85585b6afb71116ec439b72a25edb8003ef34bc42fb2c88a05249da335774d",
        "6f5faa6cae5ecd9824ff04c4d480fdef63fc7e60ec9e0b3a7fad844187cbbd07",
    ],
    "header": "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
    "root": "8b8f513a34feeb1f2cdac70fcd97042be23ccd64de9d66d36f9407bbc1809f5f",
}

# cp_height=10, height=6: middle of 8-leaf mountain
PROOF_10_6: Dict[str, object] = {
    "branch": [
        "0000000071966c2b1d065fd446b1e485b2c9d9594acd2007ccbd5441cfc89444",
        "f9f17a3c6d02b0920eccb11156df370bf4117fae2233dfee40817586ba981ca5",
        "965ac94082cebbcffe458075651e9cc33ce703ab0115c72d9e8b1a9906b2b636",
        "6f5faa6cae5ecd9824ff04c4d480fdef63fc7e60ec9e0b3a7fad844187cbbd07",
    ],
    "header": "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
    "root": "8b8f513a34feeb1f2cdac70fcd97042be23ccd64de9d66d36f9407bbc1809f5f",
}

# cp_height=10, height=7: last leaf of 8-leaf mountain
PROOF_10_7: Dict[str, object] = {
    "branch": [
        "000000003031a0e73735690c5a1ff2a4be82553b2a12b776fbd3a215dc8f778d",
        "f9f17a3c6d02b0920eccb11156df370bf4117fae2233dfee40817586ba981ca5",
        "965ac94082cebbcffe458075651e9cc33ce703ab0115c72d9e8b1a9906b2b636",
        "6f5faa6cae5ecd9824ff04c4d480fdef63fc7e60ec9e0b3a7fad844187cbbd07",
    ],
    "header": "010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86",
    "root": "8b8f513a34feeb1f2cdac70fcd97042be23ccd64de9d66d36f9407bbc1809f5f",
}

# cp_height=10, height=9: last leaf of 2-leaf mountain
PROOF_10_9: Dict[str, object] = {
    "branch": [
        "00000000408c48f847aa786c2268fc3e6ec2af68e8468a34a28c61b7f1de0dc6",
        "ff221cad72aacdd0a63bf5445c0ef4c50b3a1a64ad504458b72009666f770c31",
        "10a317ca1368c7c35b98df8d356c6246519dd428081d115e16a97573d3eb0d4b",
        "c809e7a698a4b4c474ff6f5f05e88af6d7cb80ddbbe302660dfe6bd1969224a2",
    ],
    "header": "01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53",
    "root": "8b8f513a34feeb1f2cdac70fcd97042be23ccd64de9d66d36f9407bbc1809f5f",
}

# cp_height=10, height=10: last leaf, lone leaf peak (contains all peaks)
PROOF_10_10: Dict[str, object] = {
    "branch": [
        "000000002c05cc2e78923c34df87fd108b22221ac6076c18f3ade378a4d915e9",
        "cd5d21a5bc8ad65c8dc862bd9e6ec38f914ee6499d7e0ad23d7ca9582770b6c2",
        "10a317ca1368c7c35b98df8d356c6246519dd428081d115e16a97573d3eb0d4b",
        "c809e7a698a4b4c474ff6f5f05e88af6d7cb80ddbbe302660dfe6bd1969224a2",
    ],
    "header": "010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6649ffff001d1e2de565",
    "root": "8b8f513a34feeb1f2cdac70fcd97042be23ccd64de9d66d36f9407bbc1809f5f",
}

# cp_height=11, height=11: last leaf, even count (contains all peaks)
PROOF_11_11: Dict[str, object] = {
    "branch": [
        "000000002c05cc2e78923c34df87fd108b22221ac6076c18f3ade378a4d915e9",
        "cd5d21a5bc8ad65c8dc862bd9e6ec38f914ee6499d7e0ad23d7ca9582770b6c2",
        "e9106987dc15c9ea710feeed3c2b3252cbfe21925803696ea52aa7b50a0f1085",
        "c809e7a698a4b4c474ff6f5f05e88af6d7cb80ddbbe302660dfe6bd1969224a2",
    ],
    "header": "01000000e915d9a478e3adf3186c07c61a22228b10fd87df343c92782ecc052c000000006e06373c80de397406dc3d19c90d71d230058d28293614ea58d6a57f8f5d32f8b8ce6649ffff001d173807f8",
    "root": "b05152646ed9384d234ae37e034db54e1ff65314200edd9617c53cd72a2e706d",
}

# cp_height=12, height=12: last leaf, odd count (contains all peaks)
PROOF_12_12: Dict[str, object] = {
    "branch": [
        "0000000027c2488e2510d1acf4369787784fa20ee084c258b58d9fbd43802b5e",
        "83b532d4707c4a8464dcf40bb814a1d9d7dc2bdd0b693d8a949fd53b61dcaa61",
        "e9106987dc15c9ea710feeed3c2b3252cbfe21925803696ea52aa7b50a0f1085",
        "c809e7a698a4b4c474ff6f5f05e88af6d7cb80ddbbe302660dfe6bd1969224a2",
    ],
    "header": "010000007330d7adf261c69891e6ab08367d957e74d4044bc5d9cd06d656be9700000000b8c8754fabb0ffeb04ca263a1368c39c059ca0d4af3151b876f27e197ebb963bc8d06649ffff001d3f596a0c",
    "root": "15288b27a233994b809901c91af1bd27992b20b26cf187b4eb72d6a2858ff5f0",
}

PROOF_TEST_CASES: List[Tuple[int, int, Dict[str, object]]] = [
    (10, 0, PROOF_10_0),
    (10, 6, PROOF_10_6),
    (10, 7, PROOF_10_7),
    (10, 9, PROOF_10_9),
    (10, 10, PROOF_10_10),
    (11, 11, PROOF_11_11),
    (12, 12, PROOF_12_12),
]

# Last-leaf proof test cases for bootstrap testing
BOOTSTRAP_TEST_CASES: List[Tuple[int, int, Dict[str, object]]] = [
    (10, 10, PROOF_10_10),  # 11 leaves (b1011), 3 peaks
    (11, 11, PROOF_11_11),  # 12 leaves (b1100), 2 peaks
    (12, 12, PROOF_12_12),  # 13 leaves (b1101), 3 peaks
]

# First 13 block hashes (heights 0-12) for building test MMR
BLOCK_HASHES_HEX: List[str] = [
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
    "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd",
    "0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449",
    "000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485",
    "000000009b7262315dbf071787ad3656097b892abffd1f95a1a022f896f533fc",
    "000000003031a0e73735690c5a1ff2a4be82553b2a12b776fbd3a215dc8f778d",
    "0000000071966c2b1d065fd446b1e485b2c9d9594acd2007ccbd5441cfc89444",
    "00000000408c48f847aa786c2268fc3e6ec2af68e8468a34a28c61b7f1de0dc6",
    "000000008d9dc510f23c2657fc4f67bea30078cc05a90eb89e84cc475c080805",
    "000000002c05cc2e78923c34df87fd108b22221ac6076c18f3ade378a4d915e9",
    "0000000097be56d606cdd9c54b04d4747e957d3608abe69198c661f2add73073",
    "0000000027c2488e2510d1acf4369787784fa20ee084c258b58d9fbd43802b5e",
]

# =============================================================================
# Helper functions for test vectors
# =============================================================================

def hex_to_hash(hex_str: str) -> bytes:
    """Convert hex string to 32-byte hash (reversed for Bitcoin internal byte order)."""
    return bytes.fromhex(hex_str)[::-1]

def parse_block_test_vector(block: Dict[str, object]) -> Tuple[List[bytes], bytes]:
    """Parse block test vector, return (txids, merkle_root)."""
    tx_list = block["tx"]
    assert isinstance(tx_list, list)
    txids = [hex_to_hash(tx) for tx in tx_list]
    merkleroot = block["merkleroot"]
    assert isinstance(merkleroot, str)
    root = hex_to_hash(merkleroot)
    return txids, root

def parse_proof_test_vector(proof: Dict[str, object]) -> Tuple[bytes, bytes, List[bytes]]:
    """Parse proof test vector, return (leaf_hash, root, branch)."""
    header_hex = proof["header"]
    assert isinstance(header_hex, str)
    header = bytes.fromhex(header_hex)
    leaf = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    root_hex = proof["root"]
    assert isinstance(root_hex, str)
    root = hex_to_hash(root_hex)
    branch_list = proof["branch"]
    assert isinstance(branch_list, list)
    branch = [hex_to_hash(h) for h in branch_list]
    return leaf, root, branch

def load_block_hashes() -> List[bytes]:
    """Load the first 13 block hashes."""
    return [hex_to_hash(h) for h in BLOCK_HASHES_HEX]

def build_proof_for_last_leaf(hashes: List[bytes], leaf_count: int) -> List[bytes]:
    """
    Build a proof-to-root for the last leaf by building an MMR and manually
    constructing the proof. This is used for testing bootstrap with power-of-two
    leaf counts where we don't have Electrum test vectors.
    """
    if leaf_count <= 1:
        return []

    # Build the full tree structure to extract siblings
    # For simplicity, we compute all intermediate nodes level by level
    levels: List[List[bytes]] = [hashes[:leaf_count]]

    while len(levels[-1]) > 1:
        current = levels[-1]
        next_level: List[bytes] = []
        i = 0
        while i < len(current):
            if i + 1 < len(current):
                next_level.append(_sha256d(current[i], current[i + 1]))
            else:
                # Odd node - duplicate it (Bitcoin style)
                next_level.append(_sha256d(current[i], current[i]))
            i += 2
        levels.append(next_level)

    # Extract proof for last leaf
    proof: List[bytes] = []
    idx = leaf_count - 1
    for level in levels[:-1]:
        if idx & 1:
            # We're on the right, sibling is on the left
            proof.append(level[idx - 1])
        else:
            # We're on the left, sibling is on the right (or self if odd)
            if idx + 1 < len(level):
                proof.append(level[idx + 1])
            else:
                proof.append(level[idx])  # self-dup
        idx //= 2

    return proof

# =============================================================================
# Helper Function Tests
# =============================================================================

class TestHelperFunctions(unittest.TestCase):
    """Tests for internal helper functions."""

    def test_popcount(self) -> None:
        self.assertEqual(_popcount(0), 0)
        self.assertEqual(_popcount(1), 1)
        self.assertEqual(_popcount(11), 3)  # 1011
        self.assertEqual(_popcount(255), 8)
        self.assertEqual(_popcount(256), 1)

    def test_countr_one(self) -> None:
        self.assertEqual(_countr_one(0), 0)
        self.assertEqual(_countr_one(1), 1)
        self.assertEqual(_countr_one(3), 2)  # 11
        self.assertEqual(_countr_one(7), 3)  # 111
        self.assertEqual(_countr_one(11), 2)  # 1011
        self.assertEqual(_countr_one(8), 0)  # 1000

    def test_countr_zero(self) -> None:
        self.assertEqual(_countr_zero(0), 64)  # Matches C++ uint64_t behavior
        self.assertEqual(_countr_zero(1), 0)
        self.assertEqual(_countr_zero(2), 1)
        self.assertEqual(_countr_zero(4), 2)
        self.assertEqual(_countr_zero(8), 3)
        self.assertEqual(_countr_zero(12), 2)  # 1100

    def test_bit_width(self) -> None:
        self.assertEqual(_bit_width(0), 0)
        self.assertEqual(_bit_width(1), 1)
        self.assertEqual(_bit_width(2), 2)
        self.assertEqual(_bit_width(3), 2)
        self.assertEqual(_bit_width(8), 4)
        self.assertEqual(_bit_width(11), 4)

# =============================================================================
# Basic Accumulator Tests
# =============================================================================

class TestMMRAccumulatorEmpty(unittest.TestCase):
    """Tests for empty accumulator state."""

    def test_accumulator_empty(self) -> None:
        acc = MMRAccumulator()

        self.assertTrue(acc.is_empty())
        self.assertEqual(acc.leaf_count, 0)
        self.assertEqual(acc.peak_count, 0)
        self.assertEqual(acc.peaks, [])
        self.assertEqual(acc.get_root(), bytes(32))

        # Proof verification fails for empty accumulator
        self.assertFalse(acc.verify_proof_to_peak(0, bytes(32), []))
        self.assertFalse(acc.verify_proof_to_root(0, bytes(32), []))

class TestMMRAccumulatorSingleLeaf(unittest.TestCase):
    """Tests for single-leaf accumulator."""

    def test_single_leaf(self) -> None:
        hashes = load_block_hashes()
        acc = MMRAccumulator()
        acc.extend(hashes[0])

        self.assertEqual(acc.leaf_count, 1)
        self.assertEqual(acc.peak_count, 1)
        self.assertFalse(acc.is_empty())

        # Single leaf: root equals the leaf itself
        self.assertEqual(acc.get_root(), hashes[0])

        # Single leaf: one peak, which is the leaf
        self.assertEqual(acc.peaks, [hashes[0]])

        # Proof to peak: empty (leaf is its own peak)
        self.assertTrue(acc.verify_proof_to_peak(0, hashes[0], []))

        # Proof to root: empty (single leaf is root)
        self.assertTrue(acc.verify_proof_to_root(0, hashes[0], []))

        # Wrong leaf should fail
        self.assertFalse(acc.verify_proof_to_peak(0, make_leaf(999), []))
        self.assertFalse(acc.verify_proof_to_root(0, make_leaf(999), []))

# =============================================================================
# Root Computation Tests
# =============================================================================

class TestMMRAccumulatorRootMatchesMerkle(unittest.TestCase):
    """Tests that MMR root matches Bitcoin Merkle root for block transactions."""

    def test_root_matches_merkle(self) -> None:
        for block in TEST_BLOCKS:
            with self.subTest(tx_count=len(block["tx"])):  # type: ignore[arg-type]
                txids, expected_root = parse_block_test_vector(block)

                acc = MMRAccumulator()
                for txid in txids:
                    acc.extend(txid)

                self.assertEqual(acc.leaf_count, len(txids))
                self.assertEqual(acc.get_root(), expected_root)

class TestMMRAccumulatorRootIsPeakPowerOfTwo(unittest.TestCase):
    """Tests that power-of-two leaf count results in single peak equal to root."""

    def test_root_is_peak_power_of_two(self) -> None:
        txids, expected_root = parse_block_test_vector(BLOCK_53066)
        self.assertEqual(len(txids), 8)  # Power of two

        acc = MMRAccumulator()
        for txid in txids:
            acc.extend(txid)

        # Power of two: single peak
        self.assertEqual(acc.peak_count, 1)
        self.assertEqual(acc.peaks[0], acc.get_root())
        self.assertEqual(acc.peaks[0], expected_root)

class TestMMRAccumulatorTwoPeaks(unittest.TestCase):
    """Tests two-peak accumulator with manual bagging verification."""

    def test_two_peaks(self) -> None:
        txids, expected_root = parse_block_test_vector(BLOCK_57113)
        self.assertEqual(len(txids), 10)  # b1010: two peaks

        # Build from first 8 leaves
        acc8 = MMRAccumulator()
        for txid in txids[:8]:
            acc8.extend(txid)
        root8 = acc8.get_root()

        # Build from last 2 leaves (independent MMR)
        acc2 = MMRAccumulator()
        for txid in txids[8:10]:
            acc2.extend(txid)
        root2 = acc2.get_root()

        # Build from all 10 leaves
        acc10 = MMRAccumulator()
        for txid in txids:
            acc10.extend(txid)

        self.assertEqual(acc10.leaf_count, 10)
        self.assertEqual(acc10.peak_count, 2)

        # Verify peaks match independently built roots
        self.assertEqual(acc10.peaks[0], root8)
        self.assertEqual(acc10.peaks[1], root2)

        # Manual bagging:
        # root8 is height 3, root2 is height 1
        # Duplicate root2 twice to reach height 3, then merge
        dup1 = _sha256d(root2, root2)  # height 2
        dup2 = _sha256d(dup1, dup1)  # height 3
        manual_root = _sha256d(root8, dup2)  # height 4

        self.assertEqual(acc10.get_root(), manual_root)
        self.assertEqual(acc10.get_root(), expected_root)

class TestMMRAccumulatorRootWithThreeLeaves(unittest.TestCase):
    """Tests root computation with three leaves (two peaks, heights 1 and 0)."""

    def test_root_with_three_leaves(self) -> None:
        leaves = [make_leaf(i) for i in range(3)]

        acc = MMRAccumulator()
        for leaf in leaves:
            acc.extend(leaf)

        self.assertEqual(acc.leaf_count, 3)
        self.assertEqual(acc.peak_count, 2)

        # Peak 0: hash(leaf0, leaf1) at height 1
        # Peak 1: leaf2 at height 0
        peak0 = _sha256d(leaves[0], leaves[1])
        peak1 = leaves[2]

        self.assertEqual(acc.peaks, [peak0, peak1])

        # Root: duplicate peak1 to height 1, then merge
        h = _sha256d(peak1, peak1)
        expected_root = _sha256d(peak0, h)

        self.assertEqual(acc.get_root(), expected_root)

class TestMMRAccumulatorElevenLeaves(unittest.TestCase):
    """Tests the example from the docstring: 11 leaves (b1011)."""

    def test_eleven_leaves(self) -> None:
        leaves = [make_leaf(i) for i in range(11)]

        acc = MMRAccumulator()
        for leaf in leaves:
            acc.extend(leaf)

        self.assertEqual(acc.leaf_count, 11)
        self.assertEqual(acc.peak_count, 3)  # popcount(11) = 3

        # Build expected peaks manually
        # Height-3 peak covering leaves 0-7
        h1_0 = _sha256d(leaves[0], leaves[1])
        h1_1 = _sha256d(leaves[2], leaves[3])
        h1_2 = _sha256d(leaves[4], leaves[5])
        h1_3 = _sha256d(leaves[6], leaves[7])
        h2_0 = _sha256d(h1_0, h1_1)
        h2_1 = _sha256d(h1_2, h1_3)
        peak0 = _sha256d(h2_0, h2_1)

        # Height-1 peak covering leaves 8-9
        peak1 = _sha256d(leaves[8], leaves[9])

        # Height-0 peak: leaf 10
        peak2 = leaves[10]

        self.assertEqual(acc.peaks, [peak0, peak1, peak2])

class TestMMRAccumulatorPowerOfTwoLeaves(unittest.TestCase):
    """Tests that 2^n leaves results in single peak."""

    def test_power_of_two_leaves(self) -> None:
        for n in [1, 2, 4, 8, 16]:
            with self.subTest(n=n):
                acc = MMRAccumulator()
                for i in range(n):
                    acc.extend(make_leaf(i))

                self.assertEqual(acc.leaf_count, n)
                self.assertEqual(acc.peak_count, 1)

# =============================================================================
# Proof-to-Peak Tests
# =============================================================================

class TestMMRAccumulatorProofToPeak(unittest.TestCase):
    """Tests for verify_proof_to_peak with Electrum test vectors."""

    def test_proof_to_peak(self) -> None:
        hashes = load_block_hashes()
        self.assertEqual(len(hashes), 13)

        # Build full accumulator
        acc = MMRAccumulator()
        for h in hashes:
            acc.extend(h)

        for cp_height, height, proof_data in PROOF_TEST_CASES:
            with self.subTest(cp_height=cp_height, height=height):
                leaf_count = cp_height + 1

                # Build accumulator to this leaf count
                acc_at = MMRAccumulator()
                for i in range(leaf_count):
                    acc_at.extend(hashes[i])

                # Determine expected mountain height for this leaf
                remaining = leaf_count
                mountain_start = 0
                mountain_height = 0
                while remaining > 0:
                    mountain_height = _bit_width(remaining) - 1
                    mountain_size = 1 << mountain_height
                    if height < mountain_start + mountain_size:
                        break
                    mountain_start += mountain_size
                    remaining -= mountain_size

                # Check if this leaf is a lone peak
                is_lone_peak = (height == leaf_count - 1) and (leaf_count & 1)

                _, _, branch = parse_proof_test_vector(proof_data)

                if is_lone_peak:
                    # Leaf is its own peak; proof is empty
                    self.assertEqual(mountain_height, 0)
                    self.assertTrue(acc_at.verify_proof_to_peak(height, hashes[height], []))
                else:
                    # Proof to peak should have mountain_height elements
                    proof_to_peak = branch[:mountain_height]
                    self.assertTrue(
                        acc_at.verify_proof_to_peak(height, hashes[height], proof_to_peak)
                    )

                    # Invalid proof should fail
                    if proof_to_peak:
                        bad_proof = [bytes(32)] + proof_to_peak[1:]
                        self.assertFalse(
                            acc_at.verify_proof_to_peak(height, hashes[height], bad_proof)
                        )

class TestMMRAccumulatorProofToPeakBasic(unittest.TestCase):
    """Basic tests for verify_proof_to_peak."""

    def test_verify_proof_to_peak_two_leaves(self) -> None:
        acc = MMRAccumulator()
        leaf0 = make_leaf(0)
        leaf1 = make_leaf(1)
        acc.extend(leaf0)
        acc.extend(leaf1)

        # Proof for leaf0: sibling is leaf1
        self.assertTrue(acc.verify_proof_to_peak(0, leaf0, [leaf1]))

        # Proof for leaf1: sibling is leaf0
        self.assertTrue(acc.verify_proof_to_peak(1, leaf1, [leaf0]))

        # Wrong sibling should fail
        self.assertFalse(acc.verify_proof_to_peak(0, leaf0, [make_leaf(999)]))

    def test_verify_proof_to_peak_four_leaves(self) -> None:
        acc = MMRAccumulator()
        leaves = [make_leaf(i) for i in range(4)]
        for leaf in leaves:
            acc.extend(leaf)

        h01 = _sha256d(leaves[0], leaves[1])
        h23 = _sha256d(leaves[2], leaves[3])

        # Proof for leaf 0: [leaf1, h23]
        self.assertTrue(acc.verify_proof_to_peak(0, leaves[0], [leaves[1], h23]))

        # Proof for leaf 2: [leaf3, h01]
        self.assertTrue(acc.verify_proof_to_peak(2, leaves[2], [leaves[3], h01]))

        # Proof for leaf 3: [leaf2, h01]
        self.assertTrue(acc.verify_proof_to_peak(3, leaves[3], [leaves[2], h01]))

    def test_verify_proof_out_of_range(self) -> None:
        acc = MMRAccumulator()
        acc.extend(make_leaf(0))

        self.assertFalse(acc.verify_proof_to_peak(1, make_leaf(0), []))
        self.assertFalse(acc.verify_proof_to_peak(100, make_leaf(0), []))
        self.assertFalse(acc.verify_proof_to_peak(-1, make_leaf(0), []))

    def test_verify_proof_wrong_length(self) -> None:
        acc = MMRAccumulator()
        leaves = [make_leaf(i) for i in range(4)]
        for leaf in leaves:
            acc.extend(leaf)

        h23 = _sha256d(leaves[2], leaves[3])

        # Proof should have 2 siblings for 4-leaf tree
        self.assertFalse(acc.verify_proof_to_peak(0, leaves[0], []))
        self.assertFalse(acc.verify_proof_to_peak(0, leaves[0], [leaves[1]]))
        self.assertFalse(
            acc.verify_proof_to_peak(0, leaves[0], [leaves[1], h23, make_leaf(0)])
        )

# =============================================================================
# Proof-to-Root Tests
# =============================================================================

class TestMMRAccumulatorProofToRoot(unittest.TestCase):
    """Tests for verify_proof_to_root with Electrum test vectors."""

    def test_proof_to_root(self) -> None:
        hashes = load_block_hashes()
        self.assertEqual(len(hashes), 13)

        for cp_height, height, proof_data in PROOF_TEST_CASES:
            with self.subTest(cp_height=cp_height, height=height):
                leaf, expected_root, branch = parse_proof_test_vector(proof_data)
                leaf_count = cp_height + 1

                # Build accumulator to this leaf count
                acc = MMRAccumulator()
                for i in range(leaf_count):
                    acc.extend(hashes[i])

                # Verify root matches
                self.assertEqual(acc.get_root(), expected_root)

                # Verify proof
                self.assertTrue(acc.verify_proof_to_root(height, hashes[height], branch))

                # Invalid proof should fail
                if branch:
                    bad_proof = [bytes(32)] + branch[1:]
                    self.assertFalse(acc.verify_proof_to_root(height, hashes[height], bad_proof))

class TestMMRAccumulatorProofToRootBasic(unittest.TestCase):
    """Basic tests for verify_proof_to_root."""

    def test_verify_proof_to_root_single_leaf(self) -> None:
        acc = MMRAccumulator()
        leaf = make_leaf(0)
        acc.extend(leaf)

        self.assertTrue(acc.verify_proof_to_root(0, leaf, []))
        self.assertFalse(acc.verify_proof_to_root(0, make_leaf(999), []))

    def test_verify_proof_to_root_two_leaves(self) -> None:
        acc = MMRAccumulator()
        leaf0 = make_leaf(0)
        leaf1 = make_leaf(1)
        acc.extend(leaf0)
        acc.extend(leaf1)

        self.assertTrue(acc.verify_proof_to_root(0, leaf0, [leaf1]))
        self.assertTrue(acc.verify_proof_to_root(1, leaf1, [leaf0]))

    def test_verify_proof_to_root_three_leaves(self) -> None:
        """Test proof-to-root with bagging (multiple peaks)."""
        acc = MMRAccumulator()
        leaves = [make_leaf(i) for i in range(3)]
        for leaf in leaves:
            acc.extend(leaf)

        h01 = _sha256d(leaves[0], leaves[1])
        dup2 = _sha256d(leaves[2], leaves[2])

        # Proof for leaf0: [leaf1, dup2]
        self.assertTrue(acc.verify_proof_to_root(0, leaves[0], [leaves[1], dup2]))

        # Proof for leaf2 (lone peak): [self-dup, peak0]
        self.assertTrue(acc.verify_proof_to_root(2, leaves[2], [leaves[2], h01]))

    def test_verify_proof_to_root_out_of_range(self) -> None:
        acc = MMRAccumulator()
        acc.extend(make_leaf(0))

        self.assertFalse(acc.verify_proof_to_root(1, make_leaf(0), []))
        self.assertFalse(acc.verify_proof_to_root(-1, make_leaf(0), []))

# =============================================================================
# Bootstrap from Proof Tests
# =============================================================================

class TestMMRAccumulatorBootstrapFromProof(unittest.TestCase):
    """Tests for bootstrap_from_proof with Electrum test vectors."""

    def test_bootstrap_from_proof(self) -> None:
        hashes = load_block_hashes()
        self.assertEqual(len(hashes), 13)

        for cp_height, height, proof_data in BOOTSTRAP_TEST_CASES:
            with self.subTest(leaf_count=cp_height + 1):
                _, expected_root, branch = parse_proof_test_vector(proof_data)
                leaf_count = cp_height + 1

                # Build reference accumulator by extending
                ref_acc = MMRAccumulator()
                for i in range(leaf_count):
                    ref_acc.extend(hashes[i])

                # Bootstrap from last leaf proof
                bootstrapped = MMRAccumulator.bootstrap_from_proof(
                    leaf_count,
                    hashes[leaf_count - 1],
                    branch
                )

                self.assertIsNotNone(bootstrapped)
                self.assertEqual(bootstrapped.leaf_count, leaf_count)
                self.assertEqual(bootstrapped.get_root(), expected_root)
                self.assertEqual(bootstrapped, ref_acc)

                # Verify peaks match
                self.assertEqual(bootstrapped.peaks, ref_acc.peaks)

                # Extend bootstrapped accumulator and verify it stays in sync
                if leaf_count < len(hashes):
                    ref_extended = MMRAccumulator(ref_acc.leaf_count, ref_acc.peaks)
                    boot_extended = MMRAccumulator(bootstrapped.leaf_count, bootstrapped.peaks)

                    ref_extended.extend(hashes[leaf_count])
                    boot_extended.extend(hashes[leaf_count])

                    self.assertEqual(boot_extended, ref_extended)

class TestMMRAccumulatorBootstrapFromProofEdgeCases(unittest.TestCase):
    """Tests for bootstrap_from_proof edge cases and error handling."""

    def test_bootstrap_empty_accumulator(self) -> None:
        """Empty accumulator (0 leaves)."""
        result = MMRAccumulator.bootstrap_from_proof(0, bytes(32), [])
        self.assertIsNotNone(result)
        self.assertEqual(result.leaf_count, 0)
        self.assertTrue(result.is_empty())
        self.assertEqual(result.get_root(), bytes(32))

    def test_bootstrap_single_leaf(self) -> None:
        """Single leaf accumulator (1 leaf, empty proof)."""
        hashes = load_block_hashes()
        result = MMRAccumulator.bootstrap_from_proof(1, hashes[0], [])
        self.assertIsNotNone(result)
        self.assertEqual(result.leaf_count, 1)
        self.assertEqual(result.peak_count, 1)
        self.assertEqual(result.get_root(), hashes[0])
        self.assertEqual(result.peaks[0], hashes[0])

    def test_bootstrap_invalid_empty_proof_for_multiple_leaves(self) -> None:
        """Invalid: empty proof for leaf_count > 1."""
        hashes = load_block_hashes()
        result = MMRAccumulator.bootstrap_from_proof(2, hashes[1], [])
        self.assertIsNone(result)

    def test_bootstrap_invalid_nonempty_proof_for_zero_leaves(self) -> None:
        """Invalid: non-empty proof for leaf_count == 0."""
        hashes = load_block_hashes()
        result = MMRAccumulator.bootstrap_from_proof(0, bytes(32), [hashes[0]])
        self.assertIsNone(result)

    def test_bootstrap_invalid_nonempty_proof_for_single_leaf(self) -> None:
        """Invalid: non-empty proof for leaf_count == 1."""
        hashes = load_block_hashes()
        result = MMRAccumulator.bootstrap_from_proof(1, hashes[0], [hashes[1]])
        self.assertIsNone(result)

    def test_bootstrap_invalid_proof_too_short(self) -> None:
        """Invalid: proof too short."""
        _, _, branch = parse_proof_test_vector(PROOF_10_10)
        hashes = load_block_hashes()

        short_proof = branch[:-1]
        result = MMRAccumulator.bootstrap_from_proof(11, hashes[10], short_proof)
        self.assertIsNone(result)

    def test_bootstrap_invalid_proof_too_long(self) -> None:
        """Invalid: proof too long."""
        _, _, branch = parse_proof_test_vector(PROOF_10_10)
        hashes = load_block_hashes()

        long_proof = branch + [bytes(32)]
        result = MMRAccumulator.bootstrap_from_proof(11, hashes[10], long_proof)
        self.assertIsNone(result)

    def test_bootstrap_power_of_two(self) -> None:
        """Power of two: 8 leaves (b1000), single peak."""
        hashes = load_block_hashes()

        # Build reference accumulator
        ref_acc = MMRAccumulator()
        for i in range(8):
            ref_acc.extend(hashes[i])

        # Generate proof for last leaf (index 7)
        # For 8 leaves, proof length = bit_width(7) = 3
        proof = build_proof_for_last_leaf(hashes, 8)
        self.assertEqual(len(proof), 3)

        result = MMRAccumulator.bootstrap_from_proof(8, hashes[7], proof)
        self.assertIsNotNone(result)
        self.assertEqual(result.leaf_count, 8)
        self.assertEqual(result.peak_count, 1)
        self.assertEqual(result, ref_acc)

    def test_bootstrap_two_leaves(self) -> None:
        """Two leaves: simplest multi-leaf case."""
        hashes = load_block_hashes()

        ref_acc = MMRAccumulator()
        ref_acc.extend(hashes[0])
        ref_acc.extend(hashes[1])

        # Proof for leaf 1: just leaf 0 as sibling
        proof = [hashes[0]]

        result = MMRAccumulator.bootstrap_from_proof(2, hashes[1], proof)
        self.assertIsNotNone(result)
        self.assertEqual(result.leaf_count, 2)
        self.assertEqual(result.peak_count, 1)
        self.assertEqual(result, ref_acc)

    def test_bootstrap_four_leaves(self) -> None:
        """Four leaves: power of two, single peak."""
        hashes = load_block_hashes()

        ref_acc = MMRAccumulator()
        for i in range(4):
            ref_acc.extend(hashes[i])

        proof = build_proof_for_last_leaf(hashes, 4)
        self.assertEqual(len(proof), 2)

        result = MMRAccumulator.bootstrap_from_proof(4, hashes[3], proof)
        self.assertIsNotNone(result)
        self.assertEqual(result.leaf_count, 4)
        self.assertEqual(result.peak_count, 1)
        self.assertEqual(result, ref_acc)

# =============================================================================
# Serialization Tests
# =============================================================================

class TestMMRAccumulatorSerialization(unittest.TestCase):
    """Tests for serialize/deserialize."""

    def test_serialize_empty(self) -> None:
        acc = MMRAccumulator()
        data = acc.serialize()
        restored = MMRAccumulator.deserialize(data)
        self.assertEqual(acc, restored)

    def test_serialize_with_leaves(self) -> None:
        acc = MMRAccumulator()
        for i in range(11):
            acc.extend(make_leaf(i))

        data = acc.serialize()
        restored = MMRAccumulator.deserialize(data)

        self.assertEqual(acc.leaf_count, restored.leaf_count)
        self.assertEqual(acc.peaks, restored.peaks)
        self.assertEqual(acc.get_root(), restored.get_root())
        self.assertEqual(acc, restored)

    def test_serialize_format(self) -> None:
        """Verify serialization format: 8-byte LE leaf_count + peaks."""
        acc = MMRAccumulator()
        for i in range(3):
            acc.extend(make_leaf(i))

        data = acc.serialize()

        # 8 bytes for leaf_count + 2 peaks * 32 bytes each
        self.assertEqual(len(data), 8 + 2 * 32)

        # First 8 bytes are little-endian leaf_count
        self.assertEqual(int.from_bytes(data[:8], 'little'), 3)

    def test_deserialize_invalid_data(self) -> None:
        # Too short
        with self.assertRaises(ValueError):
            MMRAccumulator.deserialize(b'\x00' * 5)

        # Peak count mismatch (leaf_count=1 needs 1 peak = 32 bytes)
        bad_data = (1).to_bytes(8, 'little') + b'\x00' * 5
        with self.assertRaises(ValueError):
            MMRAccumulator.deserialize(bad_data)

        # Peak count mismatch (leaf_count=3 needs 2 peaks = 64 bytes)
        bad_data = (3).to_bytes(8, 'little') + b'\x00' * 32
        with self.assertRaises(ValueError):
            MMRAccumulator.deserialize(bad_data)

# =============================================================================
# Constructor Validation Tests
# =============================================================================

class TestMMRAccumulatorConstructor(unittest.TestCase):
    """Tests for constructor validation."""

    def test_constructor_default(self) -> None:
        acc = MMRAccumulator()
        self.assertEqual(acc.leaf_count, 0)
        self.assertEqual(acc.peaks, [])

    def test_constructor_with_state(self) -> None:
        peaks = [make_leaf(0)]
        acc = MMRAccumulator(1, peaks)
        self.assertEqual(acc.leaf_count, 1)
        self.assertEqual(acc.peaks, peaks)

    def test_constructor_negative_leaf_count(self) -> None:
        with self.assertRaises(ValueError):
            MMRAccumulator(-1)

    def test_constructor_peak_count_mismatch(self) -> None:
        # leaf_count=1 needs 1 peak
        with self.assertRaises(ValueError):
            MMRAccumulator(1, [])

        # leaf_count=3 needs 2 peaks
        with self.assertRaises(ValueError):
            MMRAccumulator(3, [make_leaf(0)])

        # leaf_count=0 needs 0 peaks
        with self.assertRaises(ValueError):
            MMRAccumulator(0, [make_leaf(0)])

# =============================================================================
# Equality Tests
# =============================================================================

class TestMMRAccumulatorEquality(unittest.TestCase):
    """Tests for equality operators."""

    def test_equality_same(self) -> None:
        acc1 = MMRAccumulator()
        acc2 = MMRAccumulator()

        for i in range(5):
            leaf = make_leaf(i)
            acc1.extend(leaf)
            acc2.extend(leaf)

        self.assertEqual(acc1, acc2)
        self.assertFalse(acc1 != acc2)

    def test_equality_different_count(self) -> None:
        acc1 = MMRAccumulator()
        acc2 = MMRAccumulator()

        acc1.extend(make_leaf(0))
        acc2.extend(make_leaf(0))
        acc2.extend(make_leaf(1))

        self.assertNotEqual(acc1, acc2)

    def test_equality_different_content(self) -> None:
        acc1 = MMRAccumulator()
        acc2 = MMRAccumulator()

        acc1.extend(make_leaf(0))
        acc2.extend(make_leaf(999))

        self.assertNotEqual(acc1, acc2)

    def test_equality_not_implemented(self) -> None:
        acc = MMRAccumulator()
        self.assertNotEqual(acc, "not an accumulator")
        self.assertNotEqual(acc, 42)
        self.assertNotEqual(acc, None)

# =============================================================================
# Other Method Tests
# =============================================================================

class TestMMRAccumulatorOtherMethods(unittest.TestCase):
    """Tests for clear and other utility methods."""

    def test_clear(self) -> None:
        acc = MMRAccumulator()
        for i in range(5):
            acc.extend(make_leaf(i))

        self.assertEqual(acc.leaf_count, 5)

        acc.clear()

        self.assertEqual(acc.leaf_count, 0)
        self.assertTrue(acc.is_empty())
        self.assertEqual(acc.peaks, [])
        self.assertEqual(acc.get_root(), bytes(32))

class TestMMRAccumulatorRepr(unittest.TestCase):
    """Tests for string representations."""

    def test_repr_empty(self) -> None:
        acc = MMRAccumulator()
        r = repr(acc)
        self.assertIn('leaf_count=0', r)
        self.assertIn('peaks=[]', r)

    def test_repr_with_leaves(self) -> None:
        acc = MMRAccumulator()
        acc.extend(make_leaf(0))
        r = repr(acc)
        self.assertIn('leaf_count=1', r)

    def test_str(self) -> None:
        acc = MMRAccumulator()
        for i in range(11):
            acc.extend(make_leaf(i))
        s = str(acc)
        self.assertIn('11 leaves', s)
        self.assertIn('3 peaks', s)

# =============================================================================
# Corrupted Proof Tests
# =============================================================================

class TestMMRAccumulatorCorruptedProofs(unittest.TestCase):
    """Tests that corrupted proofs are rejected."""

    def test_corrupted_sibling_proof_to_peak(self) -> None:
        acc = MMRAccumulator()
        leaves = [make_leaf(i) for i in range(4)]
        for leaf in leaves:
            acc.extend(leaf)

        h23 = _sha256d(leaves[2], leaves[3])

        # Valid proof
        self.assertTrue(acc.verify_proof_to_peak(0, leaves[0], [leaves[1], h23]))

        # Corrupted first sibling
        self.assertFalse(acc.verify_proof_to_peak(0, leaves[0], [bytes(32), h23]))

        # Corrupted second sibling
        self.assertFalse(acc.verify_proof_to_peak(0, leaves[0], [leaves[1], bytes(32)]))

    def test_corrupted_sibling_proof_to_root(self) -> None:
        acc = MMRAccumulator()
        leaves = [make_leaf(i) for i in range(4)]
        for leaf in leaves:
            acc.extend(leaf)

        h23 = _sha256d(leaves[2], leaves[3])

        # Valid proof (same as proof-to-peak for power-of-two)
        self.assertTrue(acc.verify_proof_to_root(0, leaves[0], [leaves[1], h23]))

        # Corrupted first sibling
        self.assertFalse(acc.verify_proof_to_root(0, leaves[0], [bytes(32), h23]))

        # Corrupted second sibling
        self.assertFalse(acc.verify_proof_to_root(0, leaves[0], [leaves[1], bytes(32)]))

if __name__ == '__main__':
    unittest.main()
