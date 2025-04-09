// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CallLib, Call} from "./CallLib.sol";

struct SignedCalls {
    Call[] calls;
    uint256 nonce;
    bool shouldRevert;
    bytes32 keyHash;
    // Not hashed
    bytes signature;
}

library SignedCallsLib {
    using CallLib for Call[];

    bytes internal constant SIGNED_CALLS_TYPE =
        "SignedCalls(Call[] calls,uint256 nonce,bool shouldRevert,bytes32 keyHash)Call(address to,uint256 value,bytes data)";

    /// @dev The typehash for the SignedCalls struct
    bytes32 internal constant SIGNED_CALLS_TYPEHASH = keccak256(SIGNED_CALLS_TYPE);

    /// @notice Hashes an Execute struct.
    function hash(SignedCalls memory signedCalls) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                SIGNED_CALLS_TYPEHASH,
                signedCalls.calls.hash(),
                signedCalls.nonce,
                signedCalls.shouldRevert,
                signedCalls.keyHash
            )
        );
    }
}
