// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {INonceManager} from "../src/interfaces/INonceManager.sol";
import {IERC7821} from "../src/interfaces/IERC7821.sol";

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

    function test_invalidateNonce_revertsWithUnauthorized() public {
        uint256 nonce = 0;
        vm.expectRevert(IERC7821.Unauthorized.selector);
        signerAccount.invalidateNonce(nonce);
    }

    function test_invalidateNonce_revertsWithInvalidNonce() public {
        uint256 nonce = 0; // nonce 0 means key = 0, sequence = 0

        // First invalidate nonce 0, which will increment the sequence for key 0 to 1
        vm.startPrank(address(signerAccount));
        signerAccount.invalidateNonce(nonce);

        // At this point:
        // - key 0's sequence is now 1
        // - nonce 0 represents sequence=0 which is now invalid for key=0
        // Trying to invalidate nonce 0 again should revert since its sequence (0)
        // is less than the current sequence (1) for key 0
        vm.expectRevert(INonceManager.InvalidNonce.selector);
        signerAccount.invalidateNonce(nonce);
    }

    function test_invalidateNonce_succeeds() public {
        uint192 key = 0;
        uint64 sequence = type(uint64).max - 2; // Use a high sequence number
        uint256 nonce = (uint256(key) << 64) | sequence;

        vm.startPrank(address(signerAccount));
        signerAccount.invalidateNonce(nonce);

        // The new nonce should have sequence incremented by 1
        uint256 expectedNextNonce = (uint256(key) << 64) | (sequence + 1);
        assertEq(signerAccount.getNonce(key), expectedNextNonce);
    }

    function test_fuzz_invalidateNonce(uint192 key, uint64 sequence) public {
        // Skip sequences that would overflow when incremented
        vm.assume(sequence < type(uint64).max - 1);

        uint256 nonce = (uint256(key) << 64) | sequence;

        vm.startPrank(address(signerAccount));
        signerAccount.invalidateNonce(nonce);

        // The new nonce should have sequence incremented by 1
        uint256 expectedNextNonce = (uint256(key) << 64) | (sequence + 1);
        assertEq(signerAccount.getNonce(key), expectedNextNonce);
    }
}
