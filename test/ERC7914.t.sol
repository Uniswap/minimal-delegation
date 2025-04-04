// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {IERC7914} from "../src/interfaces/IERC7914.sol";
import {ERC7914} from "../src/ERC7914.sol";
import {IERC7821} from "../src/interfaces/IERC7821.sol";

contract ERC7914Test is DelegationHandler {
    event TransferFromNative(address indexed from, address indexed to, uint256 value);
    event ApproveNative(address indexed owner, address indexed spender, uint256 value);

    address alice = makeAddr("alice");
    address recipient = makeAddr("recipient");

    function setUp() public {
        setUpDelegation();
    }

    function test_approveNative_revertsWithUnauthorized() public {
        vm.expectRevert(IERC7821.Unauthorized.selector);
        signerAccount.approveNative(alice, 1 ether);
    }

    function test_approveNative_succeeds() public {
        vm.expectEmit(true, true, false, true);
        emit ApproveNative(address(signerAccount), alice, 1 ether);
        vm.startPrank(address(signerAccount));
        bool success = signerAccount.approveNative(alice, 1 ether);
        vm.snapshotGasLastCall("approveNative");
        assertTrue(success);
        assertEq(signerAccount.allowance(alice), 1 ether);
    }

    function test_transferFromNative_revertsWithIncorrectSpender() public {
        vm.expectRevert(IERC7914.IncorrectSender.selector);
        signerAccount.transferFromNative(alice, recipient, 1 ether);
    }

    function test_transferFromNative_revertsWithAllowanceExceeded() public {
        vm.prank(address(signerAccount));
        bool success = signerAccount.approveNative(alice, 1 ether);
        assertTrue(success);
        vm.expectRevert(IERC7914.AllowanceExceeded.selector);
        signerAccount.transferFromNative(address(signerAccount), alice, 2 ether);
    }

    function test_transferFromNative_zeroAmount_returnsFalse() public {
        bool success = signerAccount.transferFromNative(address(signerAccount), alice, 0);
        assertEq(success, false);
    }

    function test_transferFromNative_succeeds() public {
        // send eth to signerAccount
        vm.deal(address(signerAccount), 1 ether);
        vm.prank(address(signerAccount));
        bool success = signerAccount.approveNative(alice, 1 ether);
        assertTrue(success);
        uint256 aliceBalanceBefore = alice.balance;
        uint256 signerAccountBalanceBefore = address(signerAccount).balance;
        vm.expectEmit(true, true, false, true);
        emit TransferFromNative(address(signerAccount), alice, 1 ether);
        vm.prank(alice);
        success = signerAccount.transferFromNative(address(signerAccount), alice, 1 ether);
        vm.snapshotGasLastCall("transferFromNative");
        assertTrue(success);
        assertEq(signerAccount.allowance(alice), 0);
        assertEq(alice.balance, aliceBalanceBefore + 1 ether);
        assertEq(address(signerAccount).balance, signerAccountBalanceBefore - 1 ether);
    }

    function test_fuzz_transferFromNative(uint256 balance, uint256 approvedAmount, uint256 transferAmount) public {
        // ensure there are funds in the signerAccount
        vm.deal(address(signerAccount), balance);
        vm.prank(address(signerAccount));
        bool success = signerAccount.approveNative(alice, approvedAmount);
        assertEq(signerAccount.allowance(alice), approvedAmount);
        assertTrue(success);

        uint256 aliceBalanceBefore = alice.balance;
        uint256 signerAccountBalanceBefore = address(signerAccount).balance;

        vm.prank(alice);
        // Check if the transfer amount is greater than the approved amount or the balance of the signerAccount
        // and expect the appropriate revert
        if (transferAmount > approvedAmount) {
            vm.expectRevert(IERC7914.AllowanceExceeded.selector);
        } else if (transferAmount > address(signerAccount).balance) {
            vm.expectRevert(IERC7914.TransferNativeFailed.selector);
        }
        success = signerAccount.transferFromNative(address(signerAccount), alice, transferAmount);
        // if the transfer was successful, check the balances have updated
        // otherwise check the balances have not changed
        if (success) {
            assertEq(signerAccount.allowance(alice), approvedAmount - transferAmount);
            assertEq(alice.balance, aliceBalanceBefore + transferAmount);
            assertEq(address(signerAccount).balance, signerAccountBalanceBefore - transferAmount);
        } else {
            assertEq(signerAccount.allowance(alice), approvedAmount);
            assertEq(alice.balance, aliceBalanceBefore);
            assertEq(address(signerAccount).balance, signerAccountBalanceBefore);
        }
    }
}
