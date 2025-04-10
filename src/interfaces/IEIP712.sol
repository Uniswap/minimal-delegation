// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";

/// @title IEIP712
interface IEIP712 is IERC5267 {
    function domainSeparator() external view returns (bytes32);
    function hashTypedData(bytes32 hash) external view returns (bytes32);
}
