// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {IValidationHook} from "./IValidationHook.sol";
import {IExecutionHook} from "./IExecutionHook.sol";

interface IHook is IValidationHook, IExecutionHook {}
