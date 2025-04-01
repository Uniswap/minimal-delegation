// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {IHook} from "src/interfaces/IHook.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

contract MockValidationHook is IHook {
    // Per ERC1271 spec
    bytes4 private constant _1271_MAGIC_VALUE = 0x1626ba7e;
    // Per ERC4337 spec
    uint256 internal constant SIG_VALIDATION_SUCCEEDED = 0;

    function isValidSignature(bytes32, bytes calldata) external view virtual returns (bytes4) {
        return _1271_MAGIC_VALUE;
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external view virtual returns (uint256) {
        return SIG_VALIDATION_SUCCEEDED;
    }

    function verifySignature(bytes32, bytes calldata) external view virtual returns (bool) {
        return true;
    }
}
