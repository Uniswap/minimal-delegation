// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

interface IGuardedExecutor {
    function canExecute(bytes32 keyHash, address to, bytes calldata data) external view returns (bool);
    function setCanExecute(bytes32 keyHash, address to, bytes4 selector, bool can) external;
}
