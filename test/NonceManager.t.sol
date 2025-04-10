// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {INonceManager} from "../src/interfaces/INonceManager.sol";
import {BaseAuthorization} from "../src/BaseAuthorization.sol";

contract NonceManagerTest is DelegationHandler {
    function setUp() public {
        setUpDelegation();
    }

    function test_getSeq_succeeds() public view {
        // Start with nonce 0, which has key = 0 and sequence = 0
        uint256 nonce = 0;
        uint256 nonceKey = uint192(nonce >> 64); // Extract key (high 192 bits)
        uint256 expectedSeq = uint256(uint64(nonce));
        assertEq(signerAccount.getSeq(nonceKey), expectedSeq);
    }

    function test_invalidateNonce_revertsWithUnauthorized() public {
        uint256 nonce = 0;
        vm.expectRevert(BaseAuthorization.Unauthorized.selector);
        signerAccount.invalidateNonce(nonce);
    }

    function test_invalidateNonce_revertsWithInvalidNonce() public {
        uint256 nonce = 1; // nonce 1 means key = 0, sequence = 1

        // First invalidate up to nonce 1, which will increment the sequence for key 0 from 0 to 1
        vm.startPrank(address(signerAccount));
        signerAccount.invalidateNonce(nonce);

        // At this point:
        // - key 0's sequence is now 1
        // - nonce 1 represents sequence=1 which is now invalid for key=0
        // Trying to invalidate up to nonce 1 again should revert since its sequence (1)
        // is equal to the current sequence (1) for key 0
        vm.expectRevert(INonceManager.InvalidNonce.selector);
        signerAccount.invalidateNonce(nonce);
    }

    function test_invalidateNonce_revertsWithExcessiveInvalidation() public {
        uint256 nonceKey = 0;
        uint64 sequence = uint64(type(uint16).max) + 1; // Use a high sequence number
        uint256 nonce = (uint256(nonceKey) << 64) | sequence;

        vm.startPrank(address(signerAccount));
        vm.expectRevert(INonceManager.ExcessiveInvalidation.selector);
        signerAccount.invalidateNonce(nonce);
    }

    function test_invalidateNonce_succeeds() public {
        uint256 nonceKey = 0;
        uint64 sequence = type(uint16).max;
        uint256 nonce = (uint256(nonceKey) << 64) | sequence;

        vm.startPrank(address(signerAccount));
        signerAccount.invalidateNonce(nonce);

        // The new nonce should have been set with the max sequence number
        assertEq(signerAccount.getSeq(nonceKey), uint256(type(uint16).max));

        // Invalidate the next nonce
        sequence = uint64(sequence * 2);
        nonce = (uint256(nonceKey) << 64) | sequence;

        signerAccount.invalidateNonce(nonce);

        // The new nonce should have been set with the sequence number incremented by 1
        assertEq(signerAccount.getSeq(nonceKey), sequence);
    }

    function test_fuzz_invalidateNonce(uint256 nonceKey, uint16 sequence) public {
        // Skip sequences that would overflow when incremented
        sequence = uint16(_bound(sequence, 1, type(uint16).max));

        uint256 nonce = (uint256(nonceKey) << 64) | sequence;

        vm.startPrank(address(signerAccount));
        signerAccount.invalidateNonce(nonce);

        // The new nonce should have sequence incremented by 1
        assertEq(signerAccount.getSeq(nonceKey), sequence);
    }

    /// GAS TESTS
    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_invalidateNonce_gas() public {
        uint256 nonceKey = 0;
        uint64 sequence = type(uint16).max;
        uint256 nonce = (uint256(nonceKey) << 64) | sequence;

        vm.startPrank(address(signerAccount));
        signerAccount.invalidateNonce(nonce);
        vm.snapshotGasLastCall("invalidateNonce");

        // The new nonce should have been set
        assertEq(signerAccount.getSeq(nonceKey), type(uint16).max);

        // Invalidate the next nonce
        sequence = uint64(sequence * 2);
        nonce = (uint256(nonceKey) << 64) | sequence;

        signerAccount.invalidateNonce(nonce);

        // The new nonce should have been set
        assertEq(signerAccount.getSeq(nonceKey), sequence);
    }
}
