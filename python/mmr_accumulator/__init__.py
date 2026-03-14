# Copyright (c) 2026 bitcoincashautist
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
MMR Accumulator for Simplified Header Verification (SHV) clients.

This package provides a client-side MMR (Merkle Mountain Range) accumulator
that maintains only O(log n) state while supporting proof verification and
extension operations.

Example usage::

    >>> from mmr_accumulator import MMRAccumulator
    >>> acc = MMRAccumulator()
    >>> acc.extend(block_hash)
    >>> root = acc.get_root()
"""

from .mmr_accumulator import MMRAccumulator

__all__ = ['MMRAccumulator']

__version__ = '1.0.0'
__author__ = 'bitcoincashautist'
