// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC7914} from "./interfaces/IERC7914.sol";

abstract contract ERC7914 is IERC7914 {

    function approveNative(address spender, uint256 amount) external virtual returns (bool);

    function transferFromNative(address recipient, uint256 amount) public virtual returns (bool);
}