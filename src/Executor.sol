// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Call} from "./libraries/CallLib.sol";
import {IERC7821} from "./interfaces/IERC7821.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";

abstract contract Executor {
    using ModeDecoder for bytes32;

    function canExecute(Call memory call, bytes32 keyHash) public view returns (bool) {
        if (keyHash == bytes32(0)) return true;
        return false;
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
