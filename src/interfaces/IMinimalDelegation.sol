// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {IKeyManagement} from "./IKeyManagement.sol";
import {IERC1271} from "./IERC1271.sol";
import {IERC7821} from "./IERC7821.sol";
import {IEIP712} from "./IEIP712.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {IERC7201} from "./IERC7201.sol";
import {INonceManager} from "./INonceManager.sol";
import {IERC4337Account} from "./IERC4337Account.sol";
import {IERC7914} from "./IERC7914.sol";
import {IMulticall} from "./IMulticall.sol";
import {SignedBatchedCall} from "../libraries/SignedBatchedCallLib.sol";
import {BatchedCall} from "../libraries/BatchedCallLib.sol";
import {Call} from "../libraries/CallLib.sol";

/// A non-upgradeable contract that can be delegated to with a 7702 delegation transaction.
/// This implementation supports:
/// ERC-4337 relayable userOps
/// ERC-7821 batched actions
/// EIP-712 typed data signature verification
/// ERC-7201 compliant storage use
/// ERC-1271 compliant signature verification
/// ERC-7914 transfer from native
/// Alternative key management and verification
interface IMinimalDelegation is
    IKeyManagement,
    IERC4337Account,
    IERC7821,
    IERC1271,
    IEIP712,
    IERC5267,
    IERC7201,
    IERC7914,
    INonceManager,
    IMulticall
{
    error CallFailed(bytes reason);
    error InvalidSignature();

    function execute(BatchedCall memory batchedCall) external payable;
    function execute(SignedBatchedCall memory signedBatchedCall, bytes memory signature) external payable;
}
