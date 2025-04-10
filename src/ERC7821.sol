// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {IERC7821} from "./interfaces/IERC7821.sol";
import {ModeDecoder} from "./libraries/ModeDecoder.sol";

abstract contract ERC7821 is IERC7821 {
    using ModeDecoder for bytes32;

    function supportsExecutionMode(bytes32 mode) external pure override returns (bool result) {
        return mode.isBatchedCall();
    }
}
