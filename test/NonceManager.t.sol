// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {INonceManager} from "../src/interfaces/INonceManager.sol";

contract NonceManagerTest is DelegationHandler {
    function setUp() public {
        setUpDelegation();
    }

    function test_getNonce_succeeds() public view {
        // Start with nonce 0, which has key = 0 and sequence = 0
        uint256 nonce = 0;
        uint192 key = uint192(nonce >> 64); // Extract key (high 192 bits)
        uint64 sequence = uint64(nonce); // Extract sequence (low 64 bits)

        uint256 expectedNonce = (uint256(key) << 64) | sequence;
        assertEq(signerAccount.getNonce(key), expectedNonce);
    }
}
