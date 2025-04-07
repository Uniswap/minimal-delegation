// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {MinimalDelegation} from "./MinimalDelegation.sol";

/// @notice Uses custom storage layout according to ERC7201
/// @custom:storage-location erc7201:Uniswap.MinimalDelegation.1.0.0
/// @dev keccak256(abi.encode(uint256(keccak256("Uniswap.MinimalDelegation.1.0.0")) - 1)) & ~bytes32(uint256(0xff))
contract MinimalDelegationEntry is MinimalDelegation layout at 0xc807f46cbe2302f9a007e47db23c8af6a94680c1d26280fb9582873dbe5c9200 {}
