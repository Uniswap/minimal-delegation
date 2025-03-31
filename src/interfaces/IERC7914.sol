// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

interface IERC7914 is IERC165 {
    error AllowanceExceeded();
    event TransferFromNative(address indexed from, address indexed to, uint256 value);
    event ApproveNative(address indexed owner, address indexed spender, uint256 value);

    function transferFromNative(address recipient, uint256 amount) external returns (bool);

    function approveNative(address spender, uint256 amount) external returns (bool);
}