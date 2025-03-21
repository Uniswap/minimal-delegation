// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {INonceManager} from "../src/interfaces/INonceManager.sol";

contract NonceManagerTest is DelegationHandler {
    function setUp() public {
        setUpDelegation();
    }

    function test_validateAndUpdateNonce_succeeds() public {
        // Start with nonce 0, which has key = 0 and sequence = 0
        uint256 nonce = 0;
        uint192 key = uint192(nonce >> 64); // Extract key (high 192 bits)
        uint64 sequence = uint64(nonce); // Extract sequence (low 64 bits)

        // First validation - sequence should increment from 0 to 1
        signerAccount.validateAndUpdateNonce(nonce);
        uint256 expectedNonce = (uint256(key) << 64) | (sequence + 1);
        assertEq(signerAccount.getNonce(key), expectedNonce);

        // Second validation - sequence should increment from 1 to 2
        nonce = expectedNonce; // Construct full nonce with key and sequence 1
        signerAccount.validateAndUpdateNonce(nonce);
        expectedNonce = (uint256(key) << 64) | (sequence + 2);
        assertEq(signerAccount.getNonce(key), expectedNonce);

        // Third validation - sequence should increment from 2 to 3
        nonce = expectedNonce; // Construct full nonce with key and sequence 2
        signerAccount.validateAndUpdateNonce(nonce);
        expectedNonce = (uint256(key) << 64) | (sequence + 3);
        assertEq(signerAccount.getNonce(key), expectedNonce);
    }

    function test_fuzz_validateAndUpdateNonce(uint192 key) public {
        // Start with sequence 0 for any fuzzed key
        uint64 sequence = 0;
        uint256 nonce = (uint256(key) << 64) | sequence;

        // First validation - sequence should increment by 1
        signerAccount.validateAndUpdateNonce(nonce);
        uint256 expectedNonce = (uint256(key) << 64) | (sequence + 1);
        assertEq(signerAccount.getNonce(key), expectedNonce);

        // Second validation - sequence should increment by 1 again
        nonce = expectedNonce;
        signerAccount.validateAndUpdateNonce(nonce);
        expectedNonce = (uint256(key) << 64) | (sequence + 2);
        assertEq(signerAccount.getNonce(key), expectedNonce);

        // Third validation - sequence should increment by 1 again
        nonce = expectedNonce;
        signerAccount.validateAndUpdateNonce(nonce);
        expectedNonce = (uint256(key) << 64) | (sequence + 3);
        assertEq(signerAccount.getNonce(key), expectedNonce);
    }

    function test_validateAndUpdateNonce_revertsWithInvalidNonce() public {
        // Start with nonce 0, which has key = 0 and sequence = 0
        uint256 nonce = 0;
        uint192 key = uint192(nonce >> 64); // Extract key (high 192 bits)
        uint64 sequence = uint64(nonce); // Extract sequence (low 64 bits)

        // Construct an invalid nonce by using sequence + 1 instead of sequence
        // This simulates trying to use sequence 1 before sequence 0 was used
        nonce = (uint256(key) << 64) | (sequence + 1); // Construct full nonce with key and wrong sequence

        // Should revert since we're using sequence 1 before sequence 0
        vm.expectRevert(INonceManager.InvalidNonce.selector);
        signerAccount.validateAndUpdateNonce(nonce);
    }
}
