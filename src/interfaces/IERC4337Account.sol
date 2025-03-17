// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";

interface IERC4337Account is IAccount {
    error NotEntryPoint();

    function updateEntryPoint(address entryPoint) external;

    function ENTRY_POINT() external view returns (address);
}
