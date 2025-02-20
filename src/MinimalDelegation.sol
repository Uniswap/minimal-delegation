// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IMinimalDelegation} from "./interfaces/IMinimalDelegation.sol";
import {Key, KeyLib} from "./lib/KeyLib.sol";
import {MinimalDelegationStorageLib} from "./lib/MinimalDelegationStorageLib.sol";
import {IERC7821, Calls} from "./interfaces/IERC7821.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";

contract MinimalDelegation is IERC7821 {
    using ModeDecoder for bytes32;
    using KeyLib for Key;

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
        keyHash = key.hash();
        MinimalDelegationStorageLib.get().keyStorage[keyHash] = abi.encode(key);
        emit Authorized(keyHash, key);
    }

    /// @dev Returns the key corresponding to the `keyHash`. Reverts if the key does not exist.
    function getKey(bytes32 keyHash) external view returns (Key memory key) {
        bytes memory data = MinimalDelegationStorageLib.get().keyStorage[keyHash];
        if (data.length == 0) revert KeyDoesNotExist();
        return abi.decode(data, (Key));
    }

    function revoke(bytes32 keyHash) external {
        delete MinimalDelegationStorageLib.get().keyStorage[keyHash];
        emit Revoked(keyHash);
    }

    function supportsExecutionMode(bytes32 mode) external pure override returns (bool result) {
        return mode.isBatchedCall();
    }

    function _authorizeCaller() private view {
        if (msg.sender != address(this)) revert IERC7821.Unauthorized();
    }

    function _execute(Calls[] memory calls) private {
        for (uint256 i = 0; i < calls.length; i++) {
            Calls memory _call = calls[i];
            (bool success,) = _call.to.call{value: _call.value}(_call.data);
            if (!success) revert IERC7821.CallFailed();
        }
    }
}
