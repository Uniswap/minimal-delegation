// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Call} from "./libraries/CallLib.sol";
import {IERC7821} from "./interfaces/IERC7821.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";
import {MinimalDelegationStorageLib} from "./libraries/MinimalDelegationStorage.sol";

abstract contract Executor {
    using ModeDecoder for bytes32;

    error InvalidTarget();
    error InvalidKeyHash();

    bytes32 public constant EOA_KEYHASH = bytes32(0);

    function canExecute(Call memory call, bytes32 keyHash) public view returns (bool) {
        if (keyHash == EOA_KEYHASH) return true;
        return MinimalDelegationStorageLib.get().canExecute[_hash(call.to, keyHash)];
    }

    function setCanExecute(bytes32 keyHash, address target, bool can) public virtual {}

    function _setCanExecute(bytes32 keyHash, address target, bool can) internal {
        if (keyHash == EOA_KEYHASH) revert InvalidKeyHash();
        if (target == address(this)) revert InvalidTarget();
        
        MinimalDelegationStorageLib.get().canExecute[_hash(target, keyHash)] = can;
    }


    function _hash(address target, bytes32 keyHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(keyHash, target));
    }

    // Execute a list of calls as specified by a mode
    function _execute(bytes32 mode, Call[] memory calls, bytes32 keyHash) internal {
        bool shouldRevert = mode.shouldRevert();
        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, bytes memory output) = _execute(calls[i], keyHash);
            // Reverts with the first call that is unsuccessful if the EXEC_TYPE is set to force a revert.
            if (!success && shouldRevert) revert IERC7821.CallFailed(output);
        }
    }

    // Execute a single call
    function _execute(Call memory _call, bytes32 keyHash) private returns (bool success, bytes memory output) {
        if (!canExecute(_call, keyHash)) revert IERC7821.Unauthorized();
        return _execute(_call);
    }

    // Low level call
    function _execute(Call memory _call) private returns (bool success, bytes memory output) {
        address to = _call.to == address(0) ? address(this) : _call.to;
        (success, output) = to.call{value: _call.value}(_call.data);
    }
}
