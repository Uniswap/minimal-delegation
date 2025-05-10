// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ERC7739Utils} from "../../src/libraries/ERC7739Utils.sol";

/// @title MockERC7739Utils
/// @notice Mock contract to test internal library functions
contract MockERC7739Utils {
    function decodeContentsDescr(string calldata contentsDescr)
        public
        pure
        returns (string memory contentsName, string memory contentsType)
    {
        return ERC7739Utils.decodeContentsDescr(contentsDescr);
    }
}
