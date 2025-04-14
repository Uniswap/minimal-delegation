// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {IValidationHook} from "./IValidationHook.sol";
import {IExecutionHook} from "./IExecutionHook.sol";

/// @title IHook
/// @notice Unified interface for validation and execution hooks
/// @dev Hooks may implement both interfaces
interface IHook is IValidationHook, IExecutionHook {}
