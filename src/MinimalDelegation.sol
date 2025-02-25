// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IMinimalDelegation} from "./interfaces/IMinimalDelegation.sol";
import {Key, KeyLib} from "./lib/KeyLib.sol";
import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./lib/MinimalDelegationStorageLib.sol";
import {IERC7821, Calls} from "./interfaces/IERC7821.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {IKeyManagement} from "./interfaces/IKeyManagement.sol";

contract MinimalDelegation is IERC7821, IKeyManagement {
    using ModeDecoder for bytes32;
    using KeyLib for Key;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /// @dev The key does not exist.
    error KeyDoesNotExist();

    /// @dev Emitted when a key is authorized.
    event Authorized(bytes32 indexed keyHash, Key key);

    /// @dev Emitted when a key is revoked.
    event Revoked(bytes32 indexed keyHash);

    function execute(bytes32 mode, bytes calldata executionData) external payable override {
        if (mode.isBatchedCall()) {
            Calls[] memory calls = abi.decode(executionData, (Calls[]));
            _authorizeCaller();
            _execute(calls);
        } else {
            revert IERC7821.UnsupportedExecutionMode();
        }
    }

    /// @dev Authorizes the `key`.
    function authorize(Key memory key) external returns (bytes32 keyHash) {
        keyHash = _authorize(key);
        emit Authorized(keyHash, key);
    }

    /// @dev Revokes the key with the `keyHash`.
    function revoke(bytes32 keyHash) external {
        _revoke(keyHash);
        emit Revoked(keyHash);
    }

    /// @dev Returns the number of authorized keys.
    function keyCount() external view returns (uint256) {
        return MinimalDelegationStorageLib.get().keyHashes.length();
    }

    /// @dev Returns the key at the `i`-th position in the key list.
    function keyAt(uint256 i) external view returns (Key memory key) {
        return getKey(MinimalDelegationStorageLib.get().keyHashes.at(i));
    }

    /// @dev Returns the key corresponding to the `keyHash`. Reverts if the key does not exist.
    function getKey(bytes32 keyHash) public view returns (Key memory key) {
        bytes memory data = MinimalDelegationStorageLib.get().keyStorage[keyHash];
        if (data.length == 0) revert KeyDoesNotExist();
        return abi.decode(data, (Key));
    }

    function supportsExecutionMode(bytes32 mode) external pure override returns (bool result) {
        return mode.isBatchedCall();
    }

    function _authorizeCaller() private view {
        if (msg.sender != address(this)) revert IERC7821.Unauthorized();
    }

    // We currently only support calls initiated by the contract itself which means there are no checks needed on the target contract.
    // In the future, other keys can make calls according to their key permissions and those checks will need to be added.
    function _execute(Calls[] memory calls) private {
        for (uint256 i = 0; i < calls.length; i++) {
            Calls memory _call = calls[i];
            address to = _call.to == address(0) ? address(this) : _call.to;
            (bool success,) = to.call{value: _call.value}(_call.data);
            if (!success) revert IERC7821.CallFailed();
        }
    }

    function _authorize(Key memory key) private returns (bytes32 keyHash) {
        keyHash = key.hash();
        MinimalDelegationStorage storage minimalDelegationStorage = MinimalDelegationStorageLib.get();
        minimalDelegationStorage.keyStorage[keyHash] = abi.encode(key);
        minimalDelegationStorage.keyHashes.add(keyHash);
    }

    function _revoke(bytes32 keyHash) private {
        MinimalDelegationStorage storage minimalDelegationStorage = MinimalDelegationStorageLib.get();
        delete minimalDelegationStorage.keyStorage[keyHash];
        if (!minimalDelegationStorage.keyHashes.remove(keyHash)) {
            revert KeyDoesNotExist();
        }
    }
}
