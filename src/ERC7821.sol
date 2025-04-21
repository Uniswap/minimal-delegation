// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {IERC7821} from "./interfaces/IERC7821.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";

/// @title ERC7821
/// @notice A base contract that implements the ERC7821 interface
/// @dev This contract supports only two of the execution modes defined in the specification. See IERC7821.supportsExecutionMode() for more details.
abstract contract ERC7821 is IERC7821 {
    using ModeDecoder for bytes32;

    /// @inheritdoc IERC7821
    function supportsExecutionMode(bytes32 mode) external pure override returns (bool result) {
        return mode.isBatchedCall();
    }
}
