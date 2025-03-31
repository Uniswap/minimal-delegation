// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Call, CallLib} from "./libraries/CallLib.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";
import {IERC7821} from "./interfaces/IERC7821.sol";

/// @dev Contains internal dispatching logic, and pre/post execution hooks
abstract contract BaseExecutor {
    using ModeDecoder for bytes32;
    using CallLib for Call[];

    function _preExecutionHook(bytes32 mode, Call calldata call) internal virtual {}
    function _postExecutionHook(bytes32 mode, Call calldata call) internal virtual {}

    function _dispatch(bytes32 mode, Call[] calldata calls) internal {
        bool shouldRevert = mode.shouldRevert();

        for (uint256 i = 0; i < calls.length; i++) {
            Call calldata _call = calls[i];
            _preExecutionHook(mode, _call);
            (bool success, bytes memory output) = _execute(calls[i]);
            _postExecutionHook(mode, _call);
            // Reverts with the first call that is unsuccessful if the EXEC_TYPE is set to force a revert.
            if (!success && shouldRevert) revert IERC7821.CallFailed(output);
        }
    }

    // Execute a single call.
    function _execute(Call calldata _call) private returns (bool success, bytes memory output) {
        address to = _call.to == address(0) ? address(this) : _call.to;
        (success, output) = to.call{value: _call.value}(_call.data);
    }
}
