// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CallLib, Call} from "./CallLib.sol";

struct SignedCalls {
    Call[] calls;
    uint256 nonce;
    bytes32 keyHash;
    bool shouldRevert;
    bytes hookData;
}

library SignedCallsLib {
    using CallLib for Call[];

    bytes internal constant SIGNED_CALLS_TYPE =
        "SignedCalls(Call[] calls,uint256 nonce,bytes32 keyHash,bool shouldRevert,bytes hookData)Call(address to,uint256 value,bytes data)";

    /// @dev The typehash for the SignedCalls struct
    bytes32 internal constant SIGNED_CALLS_TYPEHASH = keccak256(SIGNED_CALLS_TYPE);

    /// @notice Hashes an Execute struct.
    function hash(SignedCalls memory signedCalls) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                SIGNED_CALLS_TYPEHASH,
                signedCalls.calls.hash(),
                signedCalls.nonce,
                signedCalls.keyHash,
                signedCalls.shouldRevert,
                signedCalls.hookData
            )
        );
    }
}
