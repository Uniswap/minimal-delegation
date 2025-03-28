// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IERC7821} from "./interfaces/IERC7821.sol";
import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./libraries/MinimalDelegationStorage.sol";
import {Call} from "./libraries/CallLib.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";

struct KeyPermissionsStroage {
    EnumerableSetLib.Bytes32Set canExecute;
}
// Registered hooks, etc.

abstract contract GuardedExecutor {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    function setCanExecute(bytes32 keyHash, address to, bytes4 selector, bool can) external virtual {}

    function _setCanExecute(bytes32 keyHash, address to, bytes4 selector, bool can) internal {
        MinimalDelegationStorageLib.get().keyExtraStorage[keyHash].canExecute.update(
            _packCanExecute(to, selector), can, 2048
        );
    }

    function canExecute(bytes32 keyHash, address to, bytes calldata data) public view returns (bool) {
        // EOA keyhash can execute any call.
        if (keyHash == bytes32(0)) return true;
        // TODO: implement this
        return false;
    }

    /// @dev Returns a bytes32 value that contains `to` and `selector`.
    function _packCanExecute(address to, bytes4 selector) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            result := or(shl(96, to), shr(224, selector))
        }
    }

    /// @dev Execute a call, checking if the key has the required permissions and performing any additional pre/post execution logic.
    function _execute(Call calldata _call, bytes32 keyHash) internal returns (bool success, bytes memory output) {
        if(!canExecute(keyHash, _call.to, _call.data)) revert IERC7821.Unauthorized();
        
        return _execute(_call);
    }

    /// @dev Execute a call following ERC7821
    function _execute(Call calldata _call) internal returns (bool success, bytes memory output) {
         address to = _call.to == address(0) ? address(this) : _call.to;
        (success, output) = to.call{value: _call.value}(_call.data);
    }
}
