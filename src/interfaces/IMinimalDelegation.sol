// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {IKeyManagement} from "./IKeyManagement.sol";
import {IERC7821} from "./IERC7821.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// A non-upgradeable contract that can be delegated to with a 7702 delegation transaction.
/// This implementation supports:
/// ERC-4337 relayable userOps
/// ERC-7821 batched actions
/// EIP-712 typed data signature verification
/// ERC-7201 compliant storage use
/// ERC-1271 compliant signature verification
/// Alternative key management and verification
interface IMinimalDelegation is IKeyManagement, IAccount, IERC7821, IERC1271 {}
