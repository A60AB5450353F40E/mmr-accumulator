// test/mmr-accumulator.test.ts

// Copyright (c) 2026 bitcoincashautist
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * MMRAccumulator Test Suite
 *
 * Tests cover:
 *   - empty(): initial state, proof rejection
 *   - extend(): single leaf, root computation, peak structure
 *   - build(): equivalence to sequential extend, empty input, single leaf
 *   - batchExtend(): extending existing state, empty batch
 *   - getRoot(): empty state, merkle root matching, power-of-two optimization, peak bagging
 *   - getMountain(): peak identification for proof verification
 *   - verifyProofToPeak(): proof verification against peaks
 *   - verifyProofToRoot(): proof verification against root
 *   - bootstrapFromProof(): peak extraction, edge cases (empty, single, power-of-two)
 *   - create(): peak count validation, negative leaf count rejection
 *   - clone(): immutability guarantee
 *   - serialize()/deserialize(): round-trip, empty state, invalid data rejection
 *   - Bit helpers: popcount, countTrailingOnes, countTrailingZeros, bitWidth
 *   - Hex utilities: hashToHex, hexToHash, round-trip
 *   - leaf(): block hash computation, header length validation
 *   - Rewind pattern: state verification via extension
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { hash256 } from "@bitauth/libauth";

import * as MMR from "../src/mmr-accumulator.js";
import type { AccumulatorState } from "../src/mmr-accumulator.js";
type Hash = Uint8Array;

// ============================================================================
// Test vectors
// ============================================================================

// Block with 8 transactions: b1000
const BLOCK_53066 = {
    merkleroot: "271eafea9cfeb730c6fae8c39da387b37967646d26224a10878e04f3f6212fbe",
    tx: [
        "e0598db6abb41bf57ee0019c23520121565d2217eb9ae91d2114199fec5ac41d",
        "1001d10ddf64509c1548125ca3120f32355e8af588fe6724aa5dc033e699a617",
        "3cd17728f2e9152cc908976701a28e910838a86fe5b745af74bd5b373aff6e1d",
        "7d8514357058d8b1a08d51bbca54329b7dbafc5c2e792f99c38e67297fda2c28",
        "32a83b09394f17131074360c6628147bfb3eaf0f57000bc416da7bce140c74dd",
        "4e3a183b09d35e5adeed6d12c880b46486db3f25869c939269770268a7bd5298",
        "8fb3751403381c11979f8b0d9fac7b121ad49561c6a07645e58da7d5ab5bf8f8",
        "c429d280b4f74e016c358d8bb3a909889ee23b058c26767f14384d9ff8d9b8f4",
    ],
};

// Block with 10 transactions: b1010
const BLOCK_57113 = {
    merkleroot: "dd9bfa795a0dfe64975eb03fddf8419e03f48fe6b5a97aa736b2536c035df864",
    tx: [
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
};

// Block with 11 transactions: b1011
const BLOCK_57286 = {
    merkleroot: "23d97ad1b6e828398aff13122e312883c47986e8c8a9d1f4042876fa2e9e1fe4",
    tx: [
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
};

const TEST_BLOCKS = [BLOCK_53066, BLOCK_57113, BLOCK_57286];

// Proof test vectors from Electrum protocol
// Format: blockchain.block.header response with cp_height parameter

// cp_height=10, height=0: first leaf in 8-leaf mountain
const PROOF_10_0 = {
    branch: [
        "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        "f2a2a2907abb326726a2d6500fe494f63772a941b414236c302e920bc1aa9caf",
        "0e85585b6afb71116ec439b72a25edb8003ef34bc42fb2c88a05249da335774d",
        "6f5faa6cae5ecd9824ff04c4d480fdef63fc7e60ec9e0b3a7fad844187cbbd07",
    ],
    header: "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
    root: "8b8f513a34feeb1f2cdac70fcd97042be23ccd64de9d66d36f9407bbc1809f5f",
};

// cp_height=10, height=6: middle of 8-leaf mountain
const PROOF_10_6 = {
    branch: [
        "0000000071966c2b1d065fd446b1e485b2c9d9594acd2007ccbd5441cfc89444",
        "f9f17a3c6d02b0920eccb11156df370bf4117fae2233dfee40817586ba981ca5",
        "965ac94082cebbcffe458075651e9cc33ce703ab0115c72d9e8b1a9906b2b636",
        "6f5faa6cae5ecd9824ff04c4d480fdef63fc7e60ec9e0b3a7fad844187cbbd07",
    ],
    header: "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
    root: "8b8f513a34feeb1f2cdac70fcd97042be23ccd64de9d66d36f9407bbc1809f5f",
};

// cp_height=10, height=7: last leaf of 8-leaf mountain
const PROOF_10_7 = {
    branch: [
        "000000003031a0e73735690c5a1ff2a4be82553b2a12b776fbd3a215dc8f778d",
        "f9f17a3c6d02b0920eccb11156df370bf4117fae2233dfee40817586ba981ca5",
        "965ac94082cebbcffe458075651e9cc33ce703ab0115c72d9e8b1a9906b2b636",
        "6f5faa6cae5ecd9824ff04c4d480fdef63fc7e60ec9e0b3a7fad844187cbbd07",
    ],
    header: "010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86",
    root: "8b8f513a34feeb1f2cdac70fcd97042be23ccd64de9d66d36f9407bbc1809f5f",
};

// cp_height=10, height=9: last leaf of 2-leaf mountain
const PROOF_10_9 = {
    branch: [
        "00000000408c48f847aa786c2268fc3e6ec2af68e8468a34a28c61b7f1de0dc6",
        "ff221cad72aacdd0a63bf5445c0ef4c50b3a1a64ad504458b72009666f770c31",
        "10a317ca1368c7c35b98df8d356c6246519dd428081d115e16a97573d3eb0d4b",
        "c809e7a698a4b4c474ff6f5f05e88af6d7cb80ddbbe302660dfe6bd1969224a2",
    ],
    header: "01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53",
    root: "8b8f513a34feeb1f2cdac70fcd97042be23ccd64de9d66d36f9407bbc1809f5f",
};

// cp_height=10, height=10: last leaf, lone leaf peak (contains all peaks)
const PROOF_10_10 = {
    branch: [
        "000000002c05cc2e78923c34df87fd108b22221ac6076c18f3ade378a4d915e9",
        "cd5d21a5bc8ad65c8dc862bd9e6ec38f914ee6499d7e0ad23d7ca9582770b6c2",
        "10a317ca1368c7c35b98df8d356c6246519dd428081d115e16a97573d3eb0d4b",
        "c809e7a698a4b4c474ff6f5f05e88af6d7cb80ddbbe302660dfe6bd1969224a2",
    ],
    header: "010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6649ffff001d1e2de565",
    root: "8b8f513a34feeb1f2cdac70fcd97042be23ccd64de9d66d36f9407bbc1809f5f",
};

// cp_height=11, height=11: last leaf, even count (contains all peaks)
const PROOF_11_11 = {
    branch: [
        "000000002c05cc2e78923c34df87fd108b22221ac6076c18f3ade378a4d915e9",
        "cd5d21a5bc8ad65c8dc862bd9e6ec38f914ee6499d7e0ad23d7ca9582770b6c2",
        "e9106987dc15c9ea710feeed3c2b3252cbfe21925803696ea52aa7b50a0f1085",
        "c809e7a698a4b4c474ff6f5f05e88af6d7cb80ddbbe302660dfe6bd1969224a2",
    ],
    header: "01000000e915d9a478e3adf3186c07c61a22228b10fd87df343c92782ecc052c000000006e06373c80de397406dc3d19c90d71d230058d28293614ea58d6a57f8f5d32f8b8ce6649ffff001d173807f8",
    root: "b05152646ed9384d234ae37e034db54e1ff65314200edd9617c53cd72a2e706d",
};

// cp_height=12, height=12: last leaf, odd count (contains all peaks)
const PROOF_12_12 = {
    branch: [
        "0000000027c2488e2510d1acf4369787784fa20ee084c258b58d9fbd43802b5e",
        "83b532d4707c4a8464dcf40bb814a1d9d7dc2bdd0b693d8a949fd53b61dcaa61",
        "e9106987dc15c9ea710feeed3c2b3252cbfe21925803696ea52aa7b50a0f1085",
        "c809e7a698a4b4c474ff6f5f05e88af6d7cb80ddbbe302660dfe6bd1969224a2",
    ],
    header: "010000007330d7adf261c69891e6ab08367d957e74d4044bc5d9cd06d656be9700000000b8c8754fabb0ffeb04ca263a1368c39c059ca0d4af3151b876f27e197ebb963bc8d06649ffff001d3f596a0c",
    root: "15288b27a233994b809901c91af1bd27992b20b26cf187b4eb72d6a2858ff5f0",
};

// First 13 block hashes (heights 0-12) for building test MMR
const BLOCK_HASHES = [
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
];

// ============================================================================
// Helper functions
// ============================================================================

/**
 * Convert hex string to Uint8Array (32 bytes).
 * Bitcoin hashes are displayed in reverse byte order, so we reverse.
 */
function hexToBytes(hex: string): Hash {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        bytes[31 - i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

/**
 * Convert Uint8Array to hex string (reversed for Bitcoin display).
 */
function bytesToHex(bytes: Uint8Array): string {
    let hex = "";
    for (let i = 31; i >= 0; i--) {
        hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
}

interface BlockTestVector {
    txids: Hash[];
    root: Hash;
}

/**
 * Parse block test vector.
 */
function parseBlockTestVector(block: { merkleroot: string; tx: string[] }): BlockTestVector {
    return {
        txids: block.tx.map(hexToBytes),
        root: hexToBytes(block.merkleroot),
    };
}

interface ProofTestVector {
    cpHeight: number;
    height: number;
    root: Hash;
    leaf: Hash;
    branch: Hash[];
}

/**
 * Parse proof test vector.
 */
function parseProofTestVector(
    cpHeight: number,
    height: number,
    proof: { branch: string[]; header: string; root: string }
): ProofTestVector {
    // Parse header and compute leaf hash (sha256d of 80-byte header)
    const headerHex = proof.header;
    const header = new Uint8Array(80);
    for (let i = 0; i < 80; i++) {
        header[i] = parseInt(headerHex.substring(i * 2, i * 2 + 2), 16);
    }

    // Compute sha256d of header using libauth
    const leaf = hash256(header);

    return {
        cpHeight,
        height,
        root: hexToBytes(proof.root),
        leaf,
        branch: proof.branch.map(hexToBytes),
    };
}

/**
 * Load block hashes as Hash[].
 */
function loadBlockHashes(): Hash[] {
    return BLOCK_HASHES.map(hexToBytes);
}

/**
 * Assert two Uint8Array are equal.
 */
function assertHashEquals(actual: Uint8Array, expected: Uint8Array, message?: string): void {
    assert.ok(
        MMR.hashEquals(actual, expected),
        message || `Expected ${bytesToHex(expected)}, got ${bytesToHex(actual)}`
    );
}

// ============================================================================
// Tests
// ============================================================================

describe("MMRAccumulator", () => {
    describe("empty accumulator", () => {
        it("has correct initial state", () => {
            const acc = MMR.empty();

            assert.strictEqual(acc.leafCount, 0n);
            assert.strictEqual(MMR.peakCount(acc), 0);
            assert.strictEqual(acc.peaks.length, 0);
            assert.ok(MMR.isEmpty(acc));

            const root = MMR.getRoot(acc);
            assertHashEquals(root, new Uint8Array(32));
        });

        it("rejects proof verification", () => {
            const acc = MMR.empty();

            const result1 = MMR.verifyProofToPeak(acc, 0n, new Uint8Array(32), []);
            assert.strictEqual(result1, false);

            const result2 = MMR.verifyProofToRoot(acc, 0n, new Uint8Array(32), []);
            assert.strictEqual(result2, false);
        });
    });

    describe("single leaf", () => {
        it("has correct state and root", () => {
            const hashes = loadBlockHashes();
            let acc = MMR.empty();
            acc = MMR.extend(acc, hashes[0]);

            assert.strictEqual(acc.leafCount, 1n);
            assert.strictEqual(MMR.peakCount(acc), 1);

            // Single leaf: root equals the leaf itself
            const root = MMR.getRoot(acc);
            assertHashEquals(root, hashes[0]);

            // Single peak is the leaf
            assertHashEquals(acc.peaks[0], hashes[0]);
        });

        it("verifies empty proofs", () => {
            const hashes = loadBlockHashes();
            let acc = MMR.empty();
            acc = MMR.extend(acc, hashes[0]);

            // Proof to peak: empty (leaf is its own peak)
            const peakResult = MMR.verifyProofToPeak(acc, 0n, hashes[0], []);
            assert.strictEqual(peakResult, true);

            // Proof to root: empty (single leaf is root)
            const rootResult = MMR.verifyProofToRoot(acc, 0n, hashes[0], []);
            assert.strictEqual(rootResult, true);
        });
    });

    describe("root matches merkle", () => {
        for (const block of TEST_BLOCKS) {
            it(`matches merkle root for block with ${block.tx.length} txs`, () => {
                const tv = parseBlockTestVector(block);

                let acc = MMR.empty();
                for (const txid of tv.txids) {
                    acc = MMR.extend(acc, txid);
                }

                assert.strictEqual(acc.leafCount, BigInt(tv.txids.length));

                const root = MMR.getRoot(acc);
                assertHashEquals(root, tv.root);
            });
        }
    });

    describe("root is peak for power of two", () => {
        it("has single peak equal to root for 8 leaves", () => {
            const tv = parseBlockTestVector(BLOCK_53066);
            assert.strictEqual(tv.txids.length, 8); // Power of two

            let acc = MMR.empty();
            for (const txid of tv.txids) {
                acc = MMR.extend(acc, txid);
            }

            // Power of two: single peak
            assert.strictEqual(MMR.peakCount(acc), 1);

            const root = MMR.getRoot(acc);
            assertHashEquals(acc.peaks[0], root);
            assertHashEquals(acc.peaks[0], tv.root);
        });
    });

    describe("two peaks", () => {
        it("has correct peak structure for 10 leaves", () => {
            const tv = parseBlockTestVector(BLOCK_57113);
            assert.strictEqual(tv.txids.length, 10); // b1010: two peaks

            // Build from first 8 leaves
            let acc8 = MMR.empty();
            for (let i = 0; i < 8; i++) {
                acc8 = MMR.extend(acc8, tv.txids[i]);
            }
            const root8 = MMR.getRoot(acc8);

            // Build from last 2 leaves (independent)
            let acc2 = MMR.empty();
            for (let i = 8; i < 10; i++) {
                acc2 = MMR.extend(acc2, tv.txids[i]);
            }
            const root2 = MMR.getRoot(acc2);

            // Build from all 10 leaves
            let acc10 = MMR.empty();
            for (const txid of tv.txids) {
                acc10 = MMR.extend(acc10, txid);
            }
            const root10 = MMR.getRoot(acc10);

            // Verify peaks match independently built roots
            assertHashEquals(acc10.peaks[0], root8);
            assertHashEquals(acc10.peaks[1], root2);

            // Manually bag peaks Bitcoin-style:
            // root8 is height 3, root2 is height 1
            // Duplicate root2 twice to reach height 3, then hash with root8
            const dup1 = MMR.merge(root2, root2); // height 2
            const dup2 = MMR.merge(dup1, dup1); // height 3
            const manualRoot = MMR.merge(root8, dup2); // height 4

            assertHashEquals(manualRoot, root10);
            assertHashEquals(root10, tv.root);
        });
    });

    describe("build", () => {
        it("produces same result as sequential extend", () => {
            const hashes = loadBlockHashes();

            // Build using build()
            const builtAcc = MMR.build(hashes);

            // Build using sequential extend
            let extendedAcc = MMR.empty();
            for (const hash of hashes) {
                extendedAcc = MMR.extend(extendedAcc, hash);
            }

            assert.ok(MMR.stateEquals(builtAcc, extendedAcc));
            assert.strictEqual(builtAcc.leafCount, BigInt(hashes.length));
        });

        it("handles empty input", () => {
            const acc = MMR.build([]);

            assert.ok(MMR.stateEquals(acc, MMR.empty()));
            assert.strictEqual(acc.leafCount, 0n);
            assert.strictEqual(acc.peaks.length, 0);
        });

        it("handles single leaf", () => {
            const hashes = loadBlockHashes();
            const acc = MMR.build([hashes[0]]);

            assert.strictEqual(acc.leafCount, 1n);
            assert.strictEqual(acc.peaks.length, 1);
            assertHashEquals(acc.peaks[0], hashes[0]);
        });
    });

    describe("batchExtend", () => {
        it("extends existing state efficiently", () => {
            const hashes = loadBlockHashes();

            // Build first 5 leaves one at a time
            let acc = MMR.empty();
            for (let i = 0; i < 5; i++) {
                acc = MMR.extend(acc, hashes[i]);
            }

            // Batch extend with remaining leaves
            const batchAcc = MMR.batchExtend(acc, hashes.slice(5));

            // Compare to building all at once
            const fullAcc = MMR.build(hashes);

            assert.ok(MMR.stateEquals(batchAcc, fullAcc));
        });

        it("handles empty batch", () => {
            const hashes = loadBlockHashes();
            const acc = MMR.build(hashes.slice(0, 5));

            const result = MMR.batchExtend(acc, []);

            assert.ok(MMR.stateEquals(result, acc));
            // Verify it's a copy, not the same reference
            assert.notStrictEqual(result, acc);
            assert.notStrictEqual(result.peaks, acc.peaks);
        });
    });

    describe("rewind pattern", () => {
        it("can verify past state by extending", () => {
            const tv = parseBlockTestVector(BLOCK_57286);
            assert.strictEqual(tv.txids.length, 11);

            // Build from first 9 leaves
            let acc9 = MMR.empty();
            for (let i = 0; i < 9; i++) {
                acc9 = MMR.extend(acc9, tv.txids[i]);
            }

            // Build from all 11 leaves
            let acc11 = MMR.empty();
            for (const txid of tv.txids) {
                acc11 = MMR.extend(acc11, txid);
            }

            // Client-side rewind pattern: build candidate from claimed past state,
            // extend with intervening leaves, compare to trusted current state
            let candidate = MMR.create(acc9.leafCount, acc9.peaks);
            candidate = MMR.extend(candidate, tv.txids[9]);
            candidate = MMR.extend(candidate, tv.txids[10]);

            assert.ok(MMR.stateEquals(candidate, acc11));
        });
    });

    describe("proof to root", () => {
        const testCases = [
            { cpHeight: 10, height: 0, proof: PROOF_10_0 },
            { cpHeight: 10, height: 6, proof: PROOF_10_6 },
            { cpHeight: 10, height: 7, proof: PROOF_10_7 },
            { cpHeight: 10, height: 9, proof: PROOF_10_9 },
            { cpHeight: 10, height: 10, proof: PROOF_10_10 },
            { cpHeight: 11, height: 11, proof: PROOF_11_11 },
            { cpHeight: 12, height: 12, proof: PROOF_12_12 },
        ];

        for (const { cpHeight, height, proof } of testCases) {
            it(`verifies proof for cp_height=${cpHeight}, height=${height}`, () => {
                const hashes = loadBlockHashes();
                const tv = parseProofTestVector(cpHeight, height, proof);
                const leafCount = BigInt(cpHeight + 1);

                // Build accumulator to this leaf count
                let acc = MMR.empty();
                for (let i = 0n; i < leafCount; i++) {
                    acc = MMR.extend(acc, hashes[Number(i)]);
                }

                // Verify root matches
                const root = MMR.getRoot(acc);
                assertHashEquals(root, tv.root);

                // Verify proof
                const result = MMR.verifyProofToRoot(acc, BigInt(height), hashes[height], tv.branch);
                assert.strictEqual(result, true);

                // Verify invalid proof fails
                if (tv.branch.length > 0) {
                    const badBranch = [...tv.branch];
                    badBranch[0] = new Uint8Array(32);
                    const badResult = MMR.verifyProofToRoot(
                        acc,
                        BigInt(height),
                        hashes[height],
                        badBranch
                    );
                    assert.strictEqual(badResult, false);
                }
            });
        }
    });

    describe("proof to peak", () => {
        const testCases = [
            { cpHeight: 10, height: 0, proof: PROOF_10_0 },
            { cpHeight: 10, height: 6, proof: PROOF_10_6 },
            { cpHeight: 10, height: 7, proof: PROOF_10_7 },
            { cpHeight: 10, height: 9, proof: PROOF_10_9 },
            { cpHeight: 10, height: 10, proof: PROOF_10_10 },
            { cpHeight: 11, height: 11, proof: PROOF_11_11 },
            { cpHeight: 12, height: 12, proof: PROOF_12_12 },
        ];

        for (const { cpHeight, height, proof } of testCases) {
            it(`verifies proof for cp_height=${cpHeight}, height=${height}`, () => {
                const hashes = loadBlockHashes();
                const tv = parseProofTestVector(cpHeight, height, proof);
                const leafCount = BigInt(cpHeight + 1);

                // Build accumulator to this leaf count
                let acc = MMR.empty();
                for (let i = 0n; i < leafCount; i++) {
                    acc = MMR.extend(acc, hashes[Number(i)]);
                }

                // Compute mountain height for a leaf at `height` (leaf index) given `leafCount`
                let remaining = leafCount;
                let mountainStart = 0n;
                let mountainHeight = 0;
                let peakIndex = 0;

                while (remaining > 0n) {
                    mountainHeight = MMR.bitWidth(remaining) - 1;
                    const mountainSize = 1n << BigInt(mountainHeight);

                    if (BigInt(height) < mountainStart + mountainSize) {
                        break;
                    }

                    mountainStart += mountainSize;
                    remaining -= mountainSize;
                    peakIndex++;
                }

                // Check if lone peak
                const isLonePeak = height + 1 === Number(leafCount) && Number(leafCount) & 1;

                // Proof to peak should have mountainHeight elements (or 0 for lone peak)
                const proofToPeak = isLonePeak ? [] : tv.branch.slice(0, mountainHeight);

                // Verify proof
                const result = MMR.verifyProofToPeak(acc, BigInt(height), hashes[height], proofToPeak);
                assert.strictEqual(result, true);

                // Verify invalid proof fails (only if non-empty)
                if (proofToPeak.length > 0) {
                    const badProof = [...proofToPeak];
                    badProof[0] = new Uint8Array(32);
                    const badResult = MMR.verifyProofToPeak(
                        acc,
                        BigInt(height),
                        hashes[height],
                        badProof
                    );
                    assert.strictEqual(badResult, false);
                }
            });
        }
    });

    describe("bootstrap from last leaf", () => {
        it("extracts peaks and extends correctly", () => {
            const hashes = loadBlockHashes();

            // Parse 10_10 test vector: 11 leaves, 3 peaks
            const tv1010 = parseProofTestVector(10, 10, PROOF_10_10);

            // Extract peaks from proof
            // Branch: [self-dup, peak1, dup, peak0]
            const peak0 = tv1010.branch[3];
            const peak1 = tv1010.branch[1];
            const peak2 = hashes[10]; // lone leaf

            // Construct accumulator from extracted peaks
            const acc = MMR.create(11n, [peak0, peak1, peak2]);
            const root = MMR.getRoot(acc);
            assertHashEquals(root, tv1010.root);

            // Extend with header 11
            const tv1111 = parseProofTestVector(11, 11, PROOF_11_11);
            const acc2 = MMR.extend(acc, hashes[11]);
            const root2 = MMR.getRoot(acc2);
            assertHashEquals(root2, tv1111.root);

            // Extend with header 12
            const tv1212 = parseProofTestVector(12, 12, PROOF_12_12);
            const acc3 = MMR.extend(acc2, hashes[12]);
            const root3 = MMR.getRoot(acc3);
            assertHashEquals(root3, tv1212.root);
        });
    });

    describe("bootstrap from proof", () => {
        const testCases = [
            { cpHeight: 10, height: 10, proof: PROOF_10_10 }, // 11 leaves, 3 peaks
            { cpHeight: 11, height: 11, proof: PROOF_11_11 }, // 12 leaves, 2 peaks
            { cpHeight: 12, height: 12, proof: PROOF_12_12 }, // 13 leaves, 3 peaks
        ];

        for (const { cpHeight, height, proof } of testCases) {
            it(`bootstraps correctly for leaf_count=${cpHeight + 1}`, () => {
                const hashes = loadBlockHashes();
                const tv = parseProofTestVector(cpHeight, height, proof);
                const leafCount = BigInt(cpHeight + 1);

                // Build reference by extending
                let refAcc = MMR.empty();
                for (let i = 0n; i < leafCount; i++) {
                    refAcc = MMR.extend(refAcc, hashes[Number(i)]);
                }

                // Bootstrap from last leaf proof
                const bootstrapped = MMR.bootstrapFromProof(
                    leafCount,
                    hashes[Number(leafCount) - 1],
                    tv.branch
                );

                assert.ok(bootstrapped !== null);
                assert.strictEqual(bootstrapped.leafCount, leafCount);

                const bootRoot = MMR.getRoot(bootstrapped);
                assertHashEquals(bootRoot, tv.root);

                assert.ok(MMR.stateEquals(bootstrapped, refAcc));

                // Verify peaks match
                assert.strictEqual(bootstrapped.peaks.length, refAcc.peaks.length);
                for (let i = 0; i < bootstrapped.peaks.length; i++) {
                    assertHashEquals(bootstrapped.peaks[i], refAcc.peaks[i]);
                }

                // Extend and verify stays in sync
                if (Number(leafCount) < hashes.length) {
                    const refExtended = MMR.extend(refAcc, hashes[Number(leafCount)]);
                    const bootExtended = MMR.extend(bootstrapped, hashes[Number(leafCount)]);
                    assert.ok(MMR.stateEquals(bootExtended, refExtended));
                }
            });
        }
    });

    describe("bootstrap from proof edge cases", () => {
        it("handles empty accumulator", () => {
            const result = MMR.bootstrapFromProof(0n, new Uint8Array(32), []);
            assert.ok(result !== null);
            assert.strictEqual(result.leafCount, 0n);
            assert.ok(MMR.isEmpty(result));

            const root = MMR.getRoot(result);
            assertHashEquals(root, new Uint8Array(32));
        });

        it("handles single leaf", () => {
            const hashes = loadBlockHashes();
            const result = MMR.bootstrapFromProof(1n, hashes[0], []);

            assert.ok(result !== null);
            assert.strictEqual(result.leafCount, 1n);
            assert.strictEqual(MMR.peakCount(result), 1);

            const root = MMR.getRoot(result);
            assertHashEquals(root, hashes[0]);
            assertHashEquals(result.peaks[0], hashes[0]);
        });

        it("rejects empty proof for leaf_count > 1", () => {
            const hashes = loadBlockHashes();
            const result = MMR.bootstrapFromProof(2n, hashes[1], []);
            assert.strictEqual(result, null);
        });

        it("rejects non-empty proof for leaf_count == 0", () => {
            const hashes = loadBlockHashes();
            const result = MMR.bootstrapFromProof(0n, new Uint8Array(32), [hashes[0]]);
            assert.strictEqual(result, null);
        });

        it("rejects non-empty proof for leaf_count == 1", () => {
            const hashes = loadBlockHashes();
            const result = MMR.bootstrapFromProof(1n, hashes[0], [hashes[1]]);
            assert.strictEqual(result, null);
        });

        it("rejects wrong proof length", () => {
            const hashes = loadBlockHashes();
            const tv = parseProofTestVector(10, 10, PROOF_10_10);

            // Too short
            const shortProof = tv.branch.slice(0, -1);
            const resultShort = MMR.bootstrapFromProof(11n, hashes[10], shortProof);
            assert.strictEqual(resultShort, null);

            // Too long
            const longProof = [...tv.branch, new Uint8Array(32)];
            const resultLong = MMR.bootstrapFromProof(11n, hashes[10], longProof);
            assert.strictEqual(resultLong, null);
        });

        it("handles power of two (8 leaves)", () => {
            const hashes = loadBlockHashes();

            // Build reference
            let refAcc = MMR.empty();
            for (let i = 0; i < 8; i++) {
                refAcc = MMR.extend(refAcc, hashes[i]);
            }

            // For 8 leaves, we need to generate the proof
            // Proof length = bit_width(7) = 3
            // This requires computing intermediate nodes

            // Build the tree manually to get the proof
            // Level 0 (leaves): h0, h1, h2, h3, h4, h5, h6, h7
            // Level 1: H(h0,h1), H(h2,h3), H(h4,h5), H(h6,h7)
            // Level 2: H(L1[0],L1[1]), H(L1[2],L1[3])
            // Level 3: H(L2[0],L2[1]) = root

            const l1_0 = MMR.merge(hashes[0], hashes[1]);
            const l1_1 = MMR.merge(hashes[2], hashes[3]);
            const l1_2 = MMR.merge(hashes[4], hashes[5]);

            const l2_0 = MMR.merge(l1_0, l1_1);

            // Proof for leaf 7: [h6, L1[2], L2[0]]
            const proof = [hashes[6], l1_2, l2_0];

            const result = MMR.bootstrapFromProof(8n, hashes[7], proof);
            assert.ok(result !== null);
            assert.strictEqual(result.leafCount, 8n);
            assert.strictEqual(MMR.peakCount(result), 1);
            assert.ok(MMR.stateEquals(result, refAcc));
        });
    });

    describe("serialization", () => {
        it("round-trips correctly", () => {
            const hashes = loadBlockHashes();

            let acc: AccumulatorState = MMR.empty();
            for (let i = 0; i < 11; i++) {
                acc = MMR.extend(acc, hashes[i]);
            }

            const serialized = MMR.serialize(acc);
            const restored = MMR.deserialize(serialized);

            assert.ok(MMR.stateEquals(acc, restored));
        });

        it("handles empty accumulator", () => {
            const acc = MMR.empty();
            const serialized = MMR.serialize(acc);
            const restored = MMR.deserialize(serialized);

            assert.ok(MMR.stateEquals(acc, restored));
            assert.strictEqual(serialized.length, 8);
        });

        it("rejects invalid data", () => {
            // Too short
            assert.throws(() => MMR.deserialize(new Uint8Array(4)));

            // Wrong length for leaf count
            const badData = new Uint8Array(8 + 16); // 11 leaves needs 3*32 bytes
            badData[0] = 11; // leaf_count = 11
            assert.throws(() => MMR.deserialize(badData));
        });
    });

    describe("state creation", () => {
        it("validates peak count", () => {
            const hashes = loadBlockHashes();

            // leaf_count=11 requires 3 peaks
            assert.throws(() => MMR.create(11n, [hashes[0]]));
            assert.throws(() => MMR.create(11n, [hashes[0], hashes[1]]));

            // Should not throw
            MMR.create(11n, [hashes[0], hashes[1], hashes[2]]);
        });

        it("rejects negative leaf count", () => {
            assert.throws(() => MMR.create(-1n, []));
        });

        it("clones state immutably", () => {
            const hashes = loadBlockHashes();
            const original = MMR.create(1n, [hashes[0]]);
            const cloned = MMR.clone(original);

            // Modify clone's peaks array element
            (cloned.peaks as Hash[])[0] = new Uint8Array(32);

            // Original unchanged
            assertHashEquals(original.peaks[0], hashes[0]);
        });
    });

    describe("bit helpers", () => {
        it("popcount works correctly", () => {
            assert.strictEqual(MMR.popcount(0n), 0);
            assert.strictEqual(MMR.popcount(1n), 1);
            assert.strictEqual(MMR.popcount(7n), 3);
            assert.strictEqual(MMR.popcount(8n), 1);
            assert.strictEqual(MMR.popcount(11n), 3);
            assert.strictEqual(MMR.popcount(255n), 8);
        });

        it("countTrailingOnes works correctly", () => {
            assert.strictEqual(MMR.countTrailingOnes(0n), 0);
            assert.strictEqual(MMR.countTrailingOnes(1n), 1);
            assert.strictEqual(MMR.countTrailingOnes(3n), 2);
            assert.strictEqual(MMR.countTrailingOnes(7n), 3);
            assert.strictEqual(MMR.countTrailingOnes(8n), 0);
            assert.strictEqual(MMR.countTrailingOnes(11n), 2);
        });

        it("countTrailingZeros works correctly", () => {
            assert.strictEqual(MMR.countTrailingZeros(0n), 64);
            assert.strictEqual(MMR.countTrailingZeros(1n), 0);
            assert.strictEqual(MMR.countTrailingZeros(2n), 1);
            assert.strictEqual(MMR.countTrailingZeros(4n), 2);
            assert.strictEqual(MMR.countTrailingZeros(8n), 3);
            assert.strictEqual(MMR.countTrailingZeros(12n), 2);
        });

        it("bitWidth works correctly", () => {
            assert.strictEqual(MMR.bitWidth(0n), 0);
            assert.strictEqual(MMR.bitWidth(1n), 1);
            assert.strictEqual(MMR.bitWidth(2n), 2);
            assert.strictEqual(MMR.bitWidth(3n), 2);
            assert.strictEqual(MMR.bitWidth(4n), 3);
            assert.strictEqual(MMR.bitWidth(7n), 3);
            assert.strictEqual(MMR.bitWidth(8n), 4);
        });
    });

    describe("hex conversion utilities", () => {
        it("hashToHex converts correctly", () => {
            const bytes = new Uint8Array(32);
            bytes[0] = 0xab;
            bytes[1] = 0xcd;
            bytes[31] = 0xef;

            const hex = MMR.hashToHex(bytes);
            assert.strictEqual(hex.length, 64);
            assert.strictEqual(hex.substring(0, 4), "abcd");
            assert.strictEqual(hex.substring(62, 64), "ef");
        });

        it("hexToHash converts correctly", () => {
            const hex = "abcd" + "0".repeat(58) + "ef";
            const bytes = MMR.hexToHash(hex);

            assert.strictEqual(bytes.length, 32);
            assert.strictEqual(bytes[0], 0xab);
            assert.strictEqual(bytes[1], 0xcd);
            assert.strictEqual(bytes[31], 0xef);
        });

        it("round-trips correctly", () => {
            const original = new Uint8Array(32);
            for (let i = 0; i < 32; i++) {
                original[i] = i * 8;
            }

            const hex = MMR.hashToHex(original);
            const restored = MMR.hexToHash(hex);

            assertHashEquals(restored, original);
        });

        it("rejects invalid hex length", () => {
            assert.throws(() => MMR.hexToHash("abcd"));
            assert.throws(() => MMR.hexToHash("0".repeat(63)));
            assert.throws(() => MMR.hexToHash("0".repeat(65)));
        });
    });

    describe("leaf function", () => {
        it("computes correct block hash", () => {
            // Use genesis block header from PROOF_10_0
            const headerHex = PROOF_10_0.header;
            const header = new Uint8Array(80);
            for (let i = 0; i < 80; i++) {
                header[i] = parseInt(headerHex.substring(i * 2, i * 2 + 2), 16);
            }

            const leafHash = MMR.leaf(header);
            const expected = loadBlockHashes()[0]; // Genesis block hash

            assertHashEquals(leafHash, expected);
        });

        it("rejects wrong header length", () => {
            assert.throws(() => MMR.leaf(new Uint8Array(79)));
            assert.throws(() => MMR.leaf(new Uint8Array(81)));
        });
    });
});
