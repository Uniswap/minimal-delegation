// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {IKeyManagement} from "./IKeyManagement.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {IERC7821} from "./IERC7821.sol";
import {IEIP712} from "./IEIP712.sol";
import {IERC7201} from "./IERC7201.sol";
import {INonceManager} from "./INonceManager.sol";
import {IERC4337Account} from "./IERC4337Account.sol";

/// A non-upgradeable contract that can be delegated to with a 7702 delegation transaction.
/// This implementation supports:
/// ERC-4337 relayable userOps
/// ERC-7821 batched actions
/// EIP-712 typed data signature verification
/// ERC-7201 compliant storage use
/// ERC-1271 compliant signature verification
/// Alternative key management and verification
interface IMinimalDelegation is
    IKeyManagement,
    IERC4337Account,
    IERC7821,
    IERC1271,
    IEIP712,
    IERC5267,
    IERC7201,
    INonceManager
{}
