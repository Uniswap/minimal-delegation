// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IMinimalDelegation} from "./interfaces/IMinimalDelegation.sol";

contract MinimalDelegation {
    constructor() {}

    struct MinimalDelegationStorage {
        mapping(bytes32 keyHash => bytes encodedKey) keyStorage;
    }

    // keccak256(abi.encode(uint256(keccak256("Uniswap.MinimalDelegation")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant MINIMAL_DELEGATION_STORAGE_LOCATION =
        0x21f3d48e9724698d61a2dadd352c365013ee5d0f841f7fc54fb8a78301ee0c00;

    function _getMinimalDelegationStorage() private pure returns (MinimalDelegationStorage storage $) {
        assembly {
            $.slot := MINIMAL_DELEGATION_STORAGE_LOCATION
        }
    }
}
