// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

/// @title NonceManager
library NonceManager {
    error InvalidNonce();

    function getNonce(mapping(uint192 => uint256) storage nonceSequenceNumber, uint192 key)
        internal
        view
        returns (uint256 nonce)
    {
        return nonceSequenceNumber[key] | (uint256(key) << 64);
    }

    function validateAndUpdateNonce(uint256 nonce, mapping(uint192 => uint256) storage nonceSequenceNumber) internal {
        uint192 key = uint192(nonce >> 64);
        uint64 seq = uint64(nonce);
        if (!(nonceSequenceNumber[key]++ == seq)) {
            revert InvalidNonce();
        }
    }
}
