// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

using ModeDecoder for bytes32;

library ModeDecoder {
    // Mode layout adhering to ERC-7579
    // 1 byte           | 1 byte    | 4 bytes       | 4 bytes       | 22 bytes
    // CALL_TYPE        | EXEC_TYPE | UNUSED        | MODE_SELECTOR | MODE_PAYLOAD

    // Only need to check the first 2 bytes, and the last 4 bytes of the first 10 bytes (the CALL_TYPE, EXECUTION_TYPE, and MODE_SELECTOR)
    bytes32 constant MASK_UNUSED = 0xffff00000000ffffffff00000000000000000000000000000000000000000000;
    bytes32 constant BATCHED_CALL = 0x0100000000000000000000000000000000000000000000000000000000000000;

    // Supported modes:
    // 0x01           | 0x00      | unused        | 0x00000000   | unused
    // - A batched call that reverts on failure, specifying mode selector 0x00000000 means no other data is present
    function isBatchedCall(bytes32 mode) internal pure returns (bool) {
        return (mode & MASK_UNUSED) == BATCHED_CALL;
    }
}
