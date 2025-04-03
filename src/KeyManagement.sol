// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {Key, KeyLib, KeyType} from "./libraries/KeyLib.sol";
import {IKeyManagement} from "./interfaces/IKeyManagement.sol";
import {IHook} from "./interfaces/IHook.sol";

struct KeyExtraStorage {
    IHook hook;
}

/// @dev A base contract for managing keys
contract KeyManagement is IKeyManagement {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using KeyLib for Key;

    EnumerableSetLib.Bytes32Set keyHashes;
    mapping(bytes32 keyHash => bytes encodedKey) keyStorage;
    mapping(bytes32 keyHash => KeyExtraStorage) keyExtraStorage;

    /// @dev Must be overridden by the implementation
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
        return keyHashes.length();
    }

    /// @inheritdoc IKeyManagement
    function keyAt(uint256 i) external view returns (Key memory) {
        return _getKey(keyHashes.at(i));
    }

    /// @inheritdoc IKeyManagement
    function getKey(bytes32 keyHash) external view returns (Key memory) {
        return _getKey(keyHash);
    }

    /// @inheritdoc IKeyManagement
    function setHook(bytes32 keyHash, IHook hook) external {
        _onlyThis();
        _setHook(keyHash, hook);
    }

    function _authorize(Key memory key) internal returns (bytes32 keyHash) {
        keyHash = key.hash();
        // If the keyHash already exists, it does not revert and updates the key instead.
        keyStorage[keyHash] = abi.encode(key);
        keyHashes.add(keyHash);
    }

    function _revoke(bytes32 keyHash) internal {
        delete keyStorage[keyHash];
        if (!keyHashes.remove(keyHash)) {
            revert KeyDoesNotExist();
        }
    }

    function _getKey(bytes32 keyHash) internal view returns (Key memory) {
        if (keyHash == bytes32(0)) return KeyLib.toRootKey();
        bytes memory data = keyStorage[keyHash];
        if (data.length == 0) revert KeyDoesNotExist();
        return abi.decode(data, (Key));
    }

    function _setHook(bytes32 keyHash, IHook hook) internal {
        keyExtraStorage[keyHash].hook = hook;
    }
}
