// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

type AccountKeyHash is bytes32;

library AccountKeyHashLib {
    /// @notice Rehash a key hash with the sender's account address
    function wrap(bytes32 keyHash) internal view returns (AccountKeyHash) {
        return AccountKeyHash.wrap(keccak256(abi.encode(msg.sender, keyHash)));
    }
}
