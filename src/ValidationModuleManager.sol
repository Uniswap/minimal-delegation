// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./libraries/MinimalDelegationStorage.sol";
import {IValidator} from "./interfaces/IValidator.sol";

abstract contract ValidationModuleManager {
    using MinimalDelegationStorageLib for MinimalDelegationStorage;

    function _getValidator(bytes32 keyHash) internal view returns (IValidator) {
        return MinimalDelegationStorageLib.get().keyExtraStorage[keyHash].validator;
    }

    /// @dev Must only allow the root key to set validators
    function _setValidator(bytes32 keyHash, IValidator validator) internal {
        MinimalDelegationStorageLib.get().keyExtraStorage[keyHash].validator = validator;
    }
}
