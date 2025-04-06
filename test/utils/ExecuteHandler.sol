// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {SignedCalls} from "../../src/libraries/SignedCallsLib.sol";
import {DelegationHandler} from "./DelegationHandler.sol";
import {Call} from "../../src/libraries/CallLib.sol";
import {TestKeyManager, TestKey} from "./TestKeyManager.sol";
import {SignedCalls, SignedCallsLib} from "../../src/libraries/SignedCallsLib.sol";

/// @dev Helper contract for testing execute
contract ExecuteHandler is DelegationHandler {
    using TestKeyManager for TestKey;
    using SignedCallsLib for SignedCalls;

    bytes32 internal constant BATCHED_CALL = 0x0100000000000000000000000000000000000000000000000000000000000000;
    bytes32 internal constant BATCHED_CAN_REVERT_CALL =
        0x0101000000000000000000000000000000000000000000000000000000000000;
    bytes32 internal constant BATCHED_CALL_SUPPORTS_OPDATA =
        0x0100000000007821000100000000000000000000000000000000000000000000;
    bytes32 internal constant BATCHED_CALL_SUPPORTS_OPDATA_AND_CAN_REVERT =
        0x0101000000007821000100000000000000000000000000000000000000000000;

    uint256 internal constant DEFAULT_NONCE = 0;

    /// @notice Checks if the signing key is the root EOA
    function _signingKeyIsRootEOA(TestKey memory key) internal view returns (bool) {
        return vm.addr(key.privateKey) == address(signerAccount);
    }

    /// Helper function to get the next available nonce
    function _buildNextValidNonce(uint256 key) internal view returns (uint256 nonce, uint64 seq) {
        seq = uint64(signerAccount.getSeq(key));
        nonce = key << 64 | seq;
    }

    function _hash(Call[] memory calls, uint256 nonce) internal view returns (bytes32 digest) {
        SignedCalls memory signedCalls = SignedCalls({calls: calls, nonce: nonce});
        return signerAccount.hashTypedData(signedCalls.hash());
    }

    function _sign(Call[] memory calls) internal view returns (bytes memory signature) {
        signature = _sign(calls, signerTestKey, DEFAULT_NONCE);
    }

    function _sign(Call[] memory calls, uint256 nonce) internal view returns (bytes memory signature) {
        signature = _sign(calls, signerTestKey, nonce);
    }

    function _sign(Call[] memory calls, TestKey memory key) internal view returns (bytes memory signature) {
        signature = _sign(calls, key, DEFAULT_NONCE);
    }

    /// base function for signing calls
    function _sign(Call[] memory calls, TestKey memory key, uint256 nonce)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 digest = _hash(calls, nonce);
        signature = key.sign(digest);
    }

    /// @dev low level function for testing invalid signatures
    /// digest can be anything so we do not pack it with nonce here
    function _signWithDigest(bytes32 digest, TestKey memory key) internal view returns (bytes memory signature) {
        signature = key.sign(digest);
    }

    function _signAndPack(Call[] memory calls) internal view returns (bytes memory packedSignature) {
        packedSignature = _signAndPack(calls, signerTestKey, DEFAULT_NONCE);
    }

    function _signAndPack(Call[] memory calls, TestKey memory key)
        internal
        view
        returns (bytes memory packedSignature)
    {
        packedSignature = _signAndPack(calls, key, DEFAULT_NONCE);
    }

    /// @notice Base function for signing calls and packing them
    /// @dev If the signing key is the root EOA, the key hash is set to 0
    function _signAndPack(Call[] memory calls, TestKey memory key, uint256 nonce)
        internal
        view
        returns (bytes memory packedSignature)
    {
        bytes32 keyHash = _signingKeyIsRootEOA(key) ? bytes32(0) : key.toKeyHash();
        bytes memory signature = _sign(calls, key, nonce);
        packedSignature = abi.encode(nonce, abi.encode(keyHash, signature));
    }

    /// @dev low level function for testing invalid packed signatures
    function _signAndPackWithDigest(bytes32 digest, TestKey memory key, uint256 nonce)
        internal
        view
        returns (bytes memory packedSignature)
    {
        bytes32 keyHash = key.toKeyHash();
        bytes memory signature = _signWithDigest(digest, key);
        packedSignature = abi.encode(nonce, abi.encode(keyHash, signature));
    }
}
