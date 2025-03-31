// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Key, KeyLib, KeyType} from "./libraries/KeyLib.sol";
import {CalldataDecoder} from "./libraries/CalldataDecoder.sol";
import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./libraries/MinimalDelegationStorage.sol";
import {IKeyManagement} from "./interfaces/IKeyManagement.sol";

abstract contract BaseValidation is IKeyManagement {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using KeyLib for Key;

    function _onlyThis() internal view virtual {}

    /// @inheritdoc IKeyManagement
    function authorize(Key memory key) external returns (bytes32 keyHash) {
        _onlyThis();
        keyHash = _authorize(key);
        emit Authorized(keyHash, key);
    }

    /// @inheritdoc IKeyManagement
    function revoke(bytes32 keyHash) external {
        _onlyThis();
        _revoke(keyHash);
        emit Revoked(keyHash);
    }

    /// @inheritdoc IKeyManagement
    function keyCount() external view returns (uint256) {
        return MinimalDelegationStorageLib.get().keyHashes.length();
    }

    /// @inheritdoc IKeyManagement
    function keyAt(uint256 i) external view returns (Key memory) {
        return _getKey(MinimalDelegationStorageLib.get().keyHashes.at(i));
    }

    /// @inheritdoc IKeyManagement
    function getKey(bytes32 keyHash) external view returns (Key memory) {
        return _getKey(keyHash);
    }

    function _authorize(Key memory key) internal returns (bytes32 keyHash) {
        keyHash = key.hash();
        MinimalDelegationStorage storage minimalDelegationStorage = MinimalDelegationStorageLib.get();
        // If the keyHash already exists, it does not revert and updates the key instead.
        minimalDelegationStorage.keyStorage[keyHash] = abi.encode(key);
        minimalDelegationStorage.keyHashes.add(keyHash);
    }

    function _revoke(bytes32 keyHash) internal {
        MinimalDelegationStorage storage minimalDelegationStorage = MinimalDelegationStorageLib.get();
        delete minimalDelegationStorage.keyStorage[keyHash];
        if (!minimalDelegationStorage.keyHashes.remove(keyHash)) {
            revert KeyDoesNotExist();
        }
    }

    function _getKey(bytes32 keyHash) internal view returns (Key memory) {
        bytes memory data = MinimalDelegationStorageLib.get().keyStorage[keyHash];
        if (data.length == 0) revert KeyDoesNotExist();
        return abi.decode(data, (Key));
    }

    function _unwrapSignature(bytes calldata wrappedSignature)
        internal
        pure
        returns (bytes32 keyHash, bytes calldata signature)
    {
        (keyHash, signature) = CalldataDecoder.decodeBytes32Bytes(wrappedSignature);
    }

    function verifySignature(bytes32 digest, bytes32 keyHash, bytes calldata signature)
        public
        view
        returns (bool isValid)
    {
        if (signature.length == 64 || signature.length == 65) {
            // The signature is not wrapped, so it can be verified against the root key.
            isValid = ECDSA.recoverCalldata(digest, signature) == address(this);
        } else {
            // The signature is wrapped.
            Key memory key = _getKey(keyHash);
            isValid = key.verify(digest, signature);
        }
    }
}