# Merkle Mountain Range Accumulator

A Merkle Mountain Range (MMR) accumulator for Simplified Header Verification (SHV) clients on Bitcoin Cash.

## Overview

This library implements an append-only cryptographic accumulator that maintains only O(log n) state while supporting:

- **Efficient extension**: Add new block headers with ~2 hash operations on average.
- **Inclusion proofs**: Verify a block header is in the accumulator.
- **Bootstrap from proof**: Initialize from a single proof-to-root for the last leaf.
- **Bitcoin-compatible roots**: Produces identical Merkle roots to Bitcoin's block transaction trees.

## Implementations

| Language | Path | Package |
|----------|------|---------|
| TypeScript | [ts/](ts/) | `@0353F40E/mmr-accumulator-ts` |
| Python | [python/](python/) | `mmr-accumulator` |

## How It Works

Every Bitcoin Merkle tree contains an MMR structure, which is the subset of nodes arranged in complete binary subtrees.
If leaves are only appended, then the whole MMR structure becomes append-only: new leaves result in new nodes being added on top of existing ones.
Only the "peaks" of previous state need to be known in order to compute the new nodes.
The accumulator stores only the "peaks" of complete binary subtrees in the MMR. For n leaves, there are at most log₂(n) peaks, corresponding to the set bits in n.
From those peaks, Merkle root can be computed by constructing the auxiliary subtree which "bags the peaks" into a single root node.
Proofs can be verified against a peak or against the root.

The leaf count determines the exact structure, and leaf index determines the exact path for the proof.
When leaf count is represented in binary, the 1s represent mountain peaks and sizes.
When leaf index is represented in binary, the bits indicate left/right orienation of the sibling: lowest bit for lowest level.
The proof for the last leaf will pass through all the peaks, making bootstrapping from proof possible.

```text
Example with 11 leaves (binary 1011):

                             **root**
                     __________/  \_________
                    /                       \
                  [14]                       c          Height 3
               _ /   \ _                    / \
             /           \                 /   \
            6             13              b     b'      Height 2
          /    \        /    \         /      \
         2      5      9      12     [17]      a        Height 1
        / \    / \    / \    /  \    /  \     /  \
       0   1  3   4  7   8  10  11  15  16  [18]  18'   Height 0 (leaf nodes)
       ----------------------------------------------------------------------
       0   1  2   3  4   5   6   7   8   9   10         Leaf index

    Note: nodes marked with ' are duplicates; lowercase letters mark the auxiliary subtree; [] mark MMR peaks.

Peaks: [14], [17], [18]
State: { leafCount: 11, peaks: [peak0, peak1, peak2] }
```

### Security Notes

**Duplicate Leaf Ambiguity (CVE-2012-2459).**
Bitcoin's Merkle tree has a known ambiguity: duplicating the last leaf when the count is odd means different leaf sequences can produce identical roots.
This could allow a server to prove a leaf at position n-1 as if it existed at position n (the duplicated phantom position), or vice versa.
The ambiguity affects only the last two leaf positions when the count is odd.
A client can detect this by checking whether the lowest sibling in the proof equals the leaf being proven; if so, the proof is for a duplicated position.
For header commitments, the attack is further limited because headers form a hash chain: a duplicated header would need to satisfy both positions' chain linkage requirements, which is infeasible.
Therefore, a simple sanity check (lowest sibling != leaf) suffices.

**Domain Separation (CVE-2017-12842).**
Bitcoin's Merkle tree construction lacks domain separation between leaf and internal nodes, which can allow second preimage attacks in some contexts.
This does not apply to header commitments because all leaves are exactly 80 bytes (the fixed header size), while internal nodes are 64 bytes (two concatenated 32-byte hashes).
The length difference provides implicit domain separation.

### Operations

**extend(state, leaf)**: Append a leaf, merging peaks as needed:

```
leafCount = 11 (1011) → 12 (1100)
Trailing ones in 11 = 2, so merge 2 peaks with new leaf
```

**getRoot(state)**: Compute Bitcoin-style Merkle root by bagging peaks with duplication to balance heights.

**verifyProofToPeak(state, index, leaf, siblings)**: Verify inclusion against the covering peak.

**verifyProofToRoot(state, index, leaf, siblings)**: Verify inclusion against the root.

**bootstrapFromProof(leafCount, lastLeaf, siblings)**: Extract all peaks from a proof-to-root for the last leaf.

## Use Cases

### Light Client Sync

1. Obtain a trusted root (e.g., from multiple servers or embedded checkpoint).
2. Bootstrap accumulator from proof-to-root for last header.
3. Verify new headers by extending and checking work and chain linkage, then extend the accumulator to latest state.

### Trustless Root Verification

1. Build accumulator by extending with each block hash since genesis.
2. Compare final root against known checkpoint.
3. State size remains O(log n) regardless of chain length.

### Spot-verification of Headers

Verify any past header against the trusted or independently verified checkpoint.

## Specification

See "CHIP-2026-02: Simplified Header Verification for Bitcoin Cash" [SHV Client Specification](https://gitlab.com/0353F40E/mmr#shv-client-specification) section for the complete protocol specification.

## License

MIT License.
See [LICENSE](LICENSE) for details.
