// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Call} from "../../src/libraries/CallLib.sol";
import {SignedCalls} from "../../src/libraries/SignedCallsLib.sol";
import {CallUtils} from "./CallUtils.sol";

library SignedCallBuilder {
    using CallUtils for Call[];

    function init() internal pure returns (SignedCalls memory) {
        return SignedCalls({calls: CallUtils.initArray(), keyHash: bytes32(0), nonce: 0, shouldRevert: true, hookData: bytes("")});
    }

    function withCalls(SignedCalls memory signedCalls, Call[] memory calls)
        internal
        pure
        returns (SignedCalls memory)
    {
        return SignedCalls({
            calls: calls,
            keyHash: signedCalls.keyHash,
            nonce: signedCalls.nonce,
            shouldRevert: signedCalls.shouldRevert,
            hookData: signedCalls.hookData
        });
    }

    function withKeyHash(SignedCalls memory signedCalls, bytes32 keyHash) internal pure returns (SignedCalls memory) {
        return SignedCalls({
            calls: signedCalls.calls,
            keyHash: keyHash,
            nonce: signedCalls.nonce,
            shouldRevert: signedCalls.shouldRevert,
            hookData: signedCalls.hookData
        });
    }

    function withNonce(SignedCalls memory signedCalls, uint256 nonce) internal pure returns (SignedCalls memory) {
        return SignedCalls({
            calls: signedCalls.calls,
            keyHash: signedCalls.keyHash,
            nonce: nonce,
            shouldRevert: signedCalls.shouldRevert,
            hookData: signedCalls.hookData
        });
    }

    function withShouldRevert(SignedCalls memory signedCalls, bool shouldRevert)
        internal
        pure
        returns (SignedCalls memory)
    {
        return SignedCalls({
            calls: signedCalls.calls,
            keyHash: signedCalls.keyHash,
            nonce: signedCalls.nonce,
            shouldRevert: shouldRevert,
            hookData: signedCalls.hookData
        });
    }

    function withHookData(SignedCalls memory signedCalls, bytes memory hookData) internal pure returns (SignedCalls memory) {
        return SignedCalls({
            calls: signedCalls.calls,
            keyHash: signedCalls.keyHash,
            nonce: signedCalls.nonce,
            shouldRevert: signedCalls.shouldRevert,
            hookData: hookData
        });
    }
}
