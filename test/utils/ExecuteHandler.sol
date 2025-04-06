// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Call} from "../../src/libraries/CallLib.sol";
import {TestKeyManager, TestKey} from "./TestKeyManager.sol";

/// @dev Helper contract for testing execute
abstract contract ExecuteHandler {
    using TestKeyManager for TestKey;

    bytes32 internal constant BATCHED_CALL = 0x0100000000000000000000000000000000000000000000000000000000000000;
    bytes32 internal constant BATCHED_CAN_REVERT_CALL =
        0x0101000000000000000000000000000000000000000000000000000000000000;
    bytes32 internal constant BATCHED_CALL_SUPPORTS_OPDATA =
        0x0100000000007821000100000000000000000000000000000000000000000000;
    bytes32 internal constant BATCHED_CALL_SUPPORTS_OPDATA_AND_CAN_REVERT =
        0x0101000000007821000100000000000000000000000000000000000000000000;

    uint256 internal constant DEFAULT_NONCE = 0;
    bytes32 internal constant ROOT_KEY_HASH = bytes32(0);

    /// @notice Sign calls and pack them for internal verification path
    function _signAndPack(bytes32 digest, TestKey memory key, uint256 nonce) internal view returns (bytes memory) {
        bytes32 keyHash = key.toKeyHash();
        return _signAndPack(digest, key, nonce, keyHash);
    }

    /// @dev If the signing key is the root EOA, pass bytes32(0) for keyHash
    function _signAndPack(bytes32 digest, TestKey memory key, uint256 nonce, bytes32 keyHash)
        internal
        view
        returns (bytes memory packedSignature)
    {
        bytes memory signature = _sign(digest, key);
        packedSignature = abi.encode(nonce, abi.encode(keyHash, signature));
    }

    /// @notice Base function for signing calls
    /// @dev Assume that the digest is either:
    /// - SignedCalls if using internal verification
    /// - Wrapped if using 1271
    /// - The userOpHash if using ERC-4337
    function _sign(bytes32 digest, TestKey memory key) internal view returns (bytes memory signature) {
        signature = key.sign(digest);
    }
}
