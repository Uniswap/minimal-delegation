// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CallLib, Call} from "./CallLib.sol";

// TODO: Define nonce
struct ExecutionData {
    Call[] calls;
    uint256 nonce;
}

library ExecutionDataLib {
    using CallLib for Call[];
    /// TODO: Sign add nonce.

    bytes internal constant EXECUTE_TYPE =
        "Execute(Call[] calls,uint256 nonce)Call(address to,uint256 value,bytes data)";

    /// @dev The typehash for the Execute struct
    bytes32 internal constant EXECUTE_TYPEHASH = keccak256(EXECUTE_TYPE);

    /// @notice Hashes an Execute struct.
    function hash(ExecutionData memory execute) internal pure returns (bytes32) {
        return keccak256(abi.encode(EXECUTE_TYPEHASH, execute.calls.hash(), execute.nonce));
    }
}
