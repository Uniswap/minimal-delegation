// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IHook} from "../../interfaces/IHook.sol";

contract BaseNoopHook is IHook {
    function verifySignature(bytes32, bytes calldata) external view virtual returns (bool) {
        revert("Not implemented");
    }
    
    function validateUserOp(PackedUserOperation calldata, bytes32) external view virtual returns (uint256) {
        revert("Not implemented");
    }

    function isValidSignature(bytes32, bytes calldata) external view virtual returns (bytes4) {
        revert("Not implemented");
    }

    function preExecutionHook(bytes32, address, bytes calldata) external view virtual returns (bytes memory) {
        revert("Not implemented");
    }

    function postExecutionHook(bytes32, bytes calldata) external view virtual {
        revert("Not implemented");
    }
}
    