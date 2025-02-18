// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

library MinimalDelegationStorageLib {
    struct MinimalDelegationStorage {
        mapping(bytes32 keyHash => bytes encodedKey) keyStorage;
    }

    bytes32 private constant MINIMAL_DELEGATION_STORAGE_LOCATION =
        0x21f3d48e9724698d61a2dadd352c365013ee5d0f841f7fc54fb8a78301ee0c00;

    function _getMinimalDelegationStorage() private pure returns (MinimalDelegationStorage storage $) {
        assembly {
            $.slot := MINIMAL_DELEGATION_STORAGE_LOCATION
        }
    }

    function getKeyStorage(bytes32 keyHash) internal view returns (bytes memory) {
        return _getMinimalDelegationStorage().keyStorage[keyHash];
    }

    function setKeyStorage(bytes32 keyHash, bytes memory encodedKey) internal {
        _getMinimalDelegationStorage().keyStorage[keyHash] = encodedKey;
    }
}
