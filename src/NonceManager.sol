// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {INonceManager} from "./interfaces/INonceManager.sol";

/// @title NonceManager
/// @notice A contract that manages nonces to prevent replay attacks
contract NonceManager is INonceManager {
    mapping(uint256 key => uint256 seq) nonceSequenceNumber;

    /// @dev Must be overridden by the implementation
    function _onlyThis() internal view virtual {}

    /// @inheritdoc INonceManager
    function getNonce(uint256 key) external view override returns (uint256 nonce) {
        return nonceSequenceNumber[key] | (key << 64);
    }

    /// @inheritdoc INonceManager
    function invalidateNonce(uint256 newNonce) external override {
        _onlyThis();
        uint192 key = uint192(newNonce >> 64);
        uint64 currentSeq = uint64(nonceSequenceNumber[key]);
        uint64 targetSeq = uint64(newNonce);
        if (targetSeq <= currentSeq) revert InvalidNonce();
        // Limit the amount of nonces that can be invalidated in one transaction.
        unchecked {
            uint64 delta = targetSeq - currentSeq;
            if (delta > type(uint16).max) revert ExcessiveInvalidation();
        }
        nonceSequenceNumber[key] = targetSeq;
        emit NonceInvalidated(newNonce);
    }

    /// @notice Validates that the provided nonce is valid and increments the sequence number
    /// @param nonce A 256-bit value where:
    ///             - Upper 192 bits: the sequence key
    ///             - Lower 64 bits: must match the expected sequence number for the key
    /// @dev If valid, increments the sequence number for future nonce validations
    function _useNonce(uint256 nonce) internal {
        uint192 key = uint192(nonce >> 64);
        uint64 seq = uint64(nonce);
        if (!(nonceSequenceNumber[key]++ == seq)) {
            revert InvalidNonce();
        }
    }
}
