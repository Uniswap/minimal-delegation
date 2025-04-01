// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./MinimalDelegationStorage.sol";
import {IHook} from "../interfaces/IHook.sol";

enum HookFlags {
    VERIFY_SIGNATURE, // 1 << 0
    VALIDATE_USER_OP, // 1 << 1
    IS_VALID_SIGNATURE, // 1 << 2
    BEFORE_EXECUTE, // 1 << 3
    AFTER_EXECUTE // 1 << 4

}

// HookId combines an address with flags: address << 160 | flags
type HookId is uint256;

library HookLib {
    using MinimalDelegationStorageLib for MinimalDelegationStorage;

    /// @dev Get the hook for a given keyHash and flag
    function get(bytes32 keyHash, HookFlags flag) internal view returns (IHook) {
        HookId id = MinimalDelegationStorageLib.get().keyExtraStorage[keyHash].hook;
        return hasFlag(id, flag) ? IHook(parseAddress(id)) : IHook(address(0));
    }

    /// @dev Set the hook for a given key hash
    function set(bytes32 keyHash, HookId id) internal {
        MinimalDelegationStorageLib.get().keyExtraStorage[keyHash].hook = id;
    }

    /// @dev Parse the address from a hook id
    function parseAddress(HookId id) internal pure returns (address) {
        return address(uint160(HookId.unwrap(id) >> 160));
    }

    function hasFlag(HookId id, HookFlags flag) internal pure returns (bool) {
        return (HookId.unwrap(id) & (1 << uint8(flag))) != 0;
    }
}
