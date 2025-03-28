// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IERC7821} from "./interfaces/IERC7821.sol";
import {MinimalDelegationStorage, MinimalDelegationStorageLib} from "./libraries/MinimalDelegationStorage.sol";
import {Call} from "./libraries/CallLib.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";

/// @title GuardedExecutor
/// @author modified from https://github.com/ithacaxyz/account/blob/main/src/GuardedExecutor.sol
abstract contract GuardedExecutor {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    ////////////////////////////////////////////////////////////////////////
    // Constants
    ////////////////////////////////////////////////////////////////////////

    /// @dev Represents any key hash.
    bytes32 public constant ANY_KEYHASH = 0x3232323232323232323232323232323232323232323232323232323232323232;

    /// @dev Represents any target address.
    address public constant ANY_TARGET = 0x3232323232323232323232323232323232323232;

    /// @dev Represents any function selector.
    bytes4 public constant ANY_FN_SEL = 0x32323232;

    /// @dev Represents empty calldata.
    /// An empty calldata does not have 4 bytes for a function selector,
    /// and we will use this special value to denote empty calldata.
    bytes4 public constant EMPTY_CALLDATA_FN_SEL = 0xe0e0e0e0;

    /// @dev Override to restrict the caller of this function
    function setCanExecute(bytes32 keyHash, address to, bytes4 selector, bool can) external virtual {}

    function _isSuperAdmin(bytes32 keyHash) internal view returns (bool) {}

    function _setCanExecute(bytes32 keyHash, address to, bytes4 selector, bool can) internal {
        MinimalDelegationStorageLib.get().keyExtraStorage[keyHash].canExecute.update(
            _packCanExecute(to, selector), can, 2048
        );
    }

    /// @dev Returns true if the key has the required permissions to execute the call.
    function canExecute(bytes32 keyHash, address to, bytes calldata data) public view returns (bool) {
        // EOA keyhash can execute any call.
        if (keyHash == bytes32(0)) return true;

        bytes4 fnSel = ANY_FN_SEL;

        // If the calldata has 4 or more bytes, we can assume that the leading 4 bytes
        // denotes the function selector.
        if (data.length >= 4) fnSel = bytes4(LibBytes.loadCalldata(data, 0x00));

        // If the calldata is empty, make sure that the empty calldata has been authorized.
        if (data.length == uint256(0)) fnSel = EMPTY_CALLDATA_FN_SEL;

        // This check is required to ensure that authorizing any function selector
        // or any target will still NOT allow for self execution.
        if (_isSelfExecute(to, fnSel)) return false;

        EnumerableSetLib.Bytes32Set storage c = MinimalDelegationStorageLib.get().keyExtraStorage[keyHash].canExecute;
        if (c.length() != 0) {
            if (c.contains(_packCanExecute(to, fnSel))) return true;
            if (c.contains(_packCanExecute(to, ANY_FN_SEL))) return true;
            if (c.contains(_packCanExecute(ANY_TARGET, fnSel))) return true;
            if (c.contains(_packCanExecute(ANY_TARGET, ANY_FN_SEL))) return true;
        }
        return false;
    }

    /// @dev Returns true if the call is a self-execute call.
    function _isSelfExecute(address to, bytes4 selector) internal view returns (bool) {
        return to == address(this) && selector == IERC7821.execute.selector;
    }

    /// @dev Returns a bytes32 value that contains `to` and `selector`.
    function _packCanExecute(address to, bytes4 selector) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            result := or(shl(96, to), shr(224, selector))
        }
    }

    /// @dev Execute a call, checking if the key has the required permissions and performing any additional pre/post execution logic.
    function _execute(Call calldata _call, bytes32 keyHash) internal returns (bool success, bytes memory output) {
        if (!canExecute(keyHash, _call.to, _call.data)) revert IERC7821.Unauthorized();

        return _execute(_call);
    }

    /// @dev Execute a call following ERC7821
    function _execute(Call calldata _call) internal returns (bool success, bytes memory output) {
        address to = _call.to == address(0) ? address(this) : _call.to;
        (success, output) = to.call{value: _call.value}(_call.data);
    }
}
