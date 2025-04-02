// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {INonceManager} from "./interfaces/INonceManager.sol";
import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./libraries/MinimalDelegationStorage.sol";

/// @title NonceManager
/// @notice A contract that manages nonces to prevent replay attacks
abstract contract NonceManager is INonceManager {
    /// @inheritdoc INonceManager
    function getNonce(uint256 key) public view virtual returns (uint256 nonce);

    /// @inheritdoc INonceManager
    function invalidateNonce(uint256 nonce) public virtual;

    /// @notice Validates that the provided nonce is valid and increments the sequence number
    /// @param nonce A 256-bit value where:
    ///             - Upper 192 bits: the sequence key
    ///             - Lower 64 bits: must match the expected sequence number for the key
    /// @dev If valid, increments the sequence number for future nonce validations
    function _useNonce(uint256 nonce) internal {
        uint192 key = uint192(nonce >> 64);
        uint64 seq = uint64(nonce);
        if (!(MinimalDelegationStorageLib.get().nonceSequenceNumber[key]++ == seq)) {
            revert InvalidNonce();
        }
    }

    /// @notice Invalidates all sequence numbers for a given key up to but not including the provided sequence number in the nonce
    /// @param newNonce A 256-bit value where:
    ///             - Upper 192 bits: the sequence key
    ///             - Lower 64 bits: the new sequence number to set for the key
    /// @dev Can't invalidate > 2**16 nonces per transaction.
    function _invalidateNonce(uint256 newNonce) internal {
        uint192 key = uint192(newNonce >> 64);
        uint64 currentSeq = uint64(MinimalDelegationStorageLib.get().nonceSequenceNumber[key]);
        uint64 targetSeq = uint64(newNonce);
        if (targetSeq <= currentSeq) revert InvalidNonce();
        // Limit the amount of nonces that can be invalidated in one transaction.
        unchecked {
            uint64 delta = targetSeq - currentSeq;
            if (delta > type(uint16).max) revert ExcessiveInvalidation();
        }
        MinimalDelegationStorageLib.get().nonceSequenceNumber[key] = targetSeq;
    }
}
