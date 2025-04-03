// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IHook} from "../interfaces/IHook.sol";

/// @author Inspired by https://github.com/Uniswap/v4-core/blob/main/src/libraries/Hooks.sol
library HooksLib {
    uint160 internal constant VERIFY_SIGNATURE_FLAG = 1 << 0;
    uint160 internal constant VALIDATE_USER_OP_FLAG = 1 << 1;
    uint160 internal constant IS_VALID_SIGNATURE_FLAG = 1 << 2;
    uint160 internal constant BEFORE_EXECUTE_FLAG = 1 << 3;
    uint160 internal constant AFTER_EXECUTE_FLAG = 1 << 4;

    function hasPermission(IHook self, uint160 flag) internal pure returns (bool) {
        return uint160(address(self)) & flag != 0;
    }
}
