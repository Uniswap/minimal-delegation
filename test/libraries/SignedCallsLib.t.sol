// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {Call, CallLib} from "../../src/libraries/CallLib.sol";
import {SignedCalls, SignedCallsLib} from "../../src/libraries/SignedCallsLib.sol";
import {SignedCallBuilder} from "../utils/SignedCallBuilder.sol";

contract SignedCallsLibTest is Test {
    using SignedCallBuilder for SignedCalls;
    using CallLib for Call[];

    /// @notice Test to catch accidental changes to the typehash
    function test_constant_execution_data_typehash() public pure {
        bytes32 expectedTypeHash = keccak256(
            "SignedCalls(Call[] calls,uint256 nonce,bytes32 keyHash,bool shouldRevert,bytes hookData)Call(address to,uint256 value,bytes data)"
        );
        assertEq(SignedCallsLib.SIGNED_CALLS_TYPEHASH, expectedTypeHash);
    }

    function test_hash_with_nonce_fuzz(Call[] memory calls, uint256 nonce, bytes32 keyHash, bool shouldRevert, bytes memory hookData)
        public
        pure
    {
        SignedCalls memory signedCalls = SignedCallBuilder.init().withCalls(calls).withNonce(nonce).withKeyHash(keyHash)
            .withShouldRevert(shouldRevert).withHookData(hookData);
        bytes32 actualHash = SignedCallsLib.hash(signedCalls);

        bytes32 expectedHash =
            keccak256(abi.encode(SignedCallsLib.SIGNED_CALLS_TYPEHASH, calls.hash(), nonce, keyHash, shouldRevert, hookData));
        assertEq(actualHash, expectedHash);
    }
}
