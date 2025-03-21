// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {INonceManager} from "./interfaces/INonceManager.sol";
import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./libraries/MinimalDelegationStorage.sol";

/// @title NonceManager
/// @notice A contract that manages nonces to prevent replay attacks
abstract contract NonceManager is INonceManager {
    /// @inheritdoc INonceManager
    function getNonce(uint192 key) public view returns (uint256 nonce) {
        return MinimalDelegationStorageLib.get().nonceSequenceNumber[key] | (uint256(key) << 64);
    }

    /// @inheritdoc INonceManager
    function validateAndUpdateNonce(uint256 nonce) public {
        uint192 key = uint192(nonce >> 64);
        uint64 seq = uint64(nonce);
        if (!(MinimalDelegationStorageLib.get().nonceSequenceNumber[key]++ == seq)) {
            revert InvalidNonce();
        }
    }
}
