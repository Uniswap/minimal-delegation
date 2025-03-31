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

    /// @dev Increments the sequence for the key in nonce (i.e. upper 192 bits).
    /// This invalidates the nonces for the key, up to (inclusive) `uint64(nonce)`.
    function _invalidateNonce(uint256 nonce) internal {
        uint192 key = uint192(nonce >> 64);
        uint256 currentSeq = MinimalDelegationStorageLib.get().nonceSequenceNumber[key];
        uint64 targetSeq = uint64(nonce);
        if (targetSeq < currentSeq) revert InvalidNonce();
        MinimalDelegationStorageLib.get().nonceSequenceNumber[key] =
            targetSeq < type(uint64).max - 1 ? targetSeq + 1 : type(uint64).max;
    }
}
