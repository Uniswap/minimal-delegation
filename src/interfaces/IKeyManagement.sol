// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Key} from "../lib/KeyLib.sol";

interface IKeyManagement {
    function authorize(Key memory key) external returns (bytes32 keyHash);
    function revoke(bytes32 keyHash) external;
    function keyCount() external view returns (uint256);
    function keyAt(uint256 i) external view returns (Key memory);
    function getKey(bytes32 keyHash) external view returns (Key memory key);
}
