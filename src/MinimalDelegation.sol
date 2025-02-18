// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IMinimalDelegation} from "./interfaces/IMinimalDelegation.sol";
import {Key, KeyLib} from "./lib/KeyLib.sol";
import {MinimalDelegationStorageLib} from "./lib/MinimalDelegationStorageLib.sol";

contract MinimalDelegation {
    using KeyLib for Key;

    function authorize(Key memory key) external returns (bytes32 keyHash) {
        keyHash = key.hash();
        MinimalDelegationStorageLib.setKeyStorage(keyHash, abi.encode(key));
    }
}
