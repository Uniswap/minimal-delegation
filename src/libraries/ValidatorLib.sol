// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./MinimalDelegationStorage.sol";
import {IValidator} from "../interfaces/IValidator.sol";

enum ValidatorFlags {
    VERIFY_SIGNATURE, // 1 << 0
    VALIDATE_USER_OP, // 1 << 1
    IS_VALID_SIGNATURE // 1 << 2

}

// ValidatorId combines an address with flags: address << 160 | flags
type ValidatorId is uint256;

library ValidatorLib {
    using MinimalDelegationStorageLib for MinimalDelegationStorage;

    /// @dev Get the validator for a given key hash and flag
    function get(bytes32 keyHash, ValidatorFlags flag) internal view returns (IValidator) {
        ValidatorId id = MinimalDelegationStorageLib.get().keyExtraStorage[keyHash].validator;
        return hasFlag(id, flag) ? IValidator(parseAddress(id)) : IValidator(address(0));
    }

    /// @dev Set the validator for a given key hash
    function set(bytes32 keyHash, ValidatorId id) internal {
        MinimalDelegationStorageLib.get().keyExtraStorage[keyHash].validator = id;
    }

    /// @dev Create a validator id from an address and flags
    function create(address validator, ValidatorFlags flag) internal pure returns (ValidatorId) {
        return ValidatorId.wrap(uint256(uint160(validator)) << 160 | uint256(1 << uint8(flag)));
    }

    /// @dev Parse the address from a validator id
    function parseAddress(ValidatorId id) internal pure returns (address) {
        return address(uint160(ValidatorId.unwrap(id) >> 160));
    }

    function hasFlag(ValidatorId id, ValidatorFlags flag) internal pure returns (bool) {
        return (ValidatorId.unwrap(id) & (1 << uint8(flag))) != 0;
    }
}
