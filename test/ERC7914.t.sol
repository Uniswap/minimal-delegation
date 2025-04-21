// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {IERC7914} from "../src/interfaces/IERC7914.sol";
import {ERC7914} from "../src/ERC7914.sol";
import {BaseAuthorization} from "../src/BaseAuthorization.sol";

contract ERC7914Test is DelegationHandler {
    event TransferFromNative(address indexed from, address indexed to, uint256 value);
    event ApproveNative(address indexed owner, address indexed spender, uint256 value);
    event ApproveNativeTransient(address indexed owner, address indexed spender, uint256 value);
    event TransferFromNativeTransient(address indexed from, address indexed to, uint256 value);

    address bob = makeAddr("bob");
    address recipient = makeAddr("recipient");

    function setUp() public {
        setUpDelegation();
    }

    function test_approveNative_revertsWithUnauthorized() public {
        vm.expectRevert(BaseAuthorization.Unauthorized.selector);
        signerAccount.approveNative(bob, 1 ether);
    }

    function test_approveNative_succeeds() public {
        vm.expectEmit(true, true, false, true);
        emit ApproveNative(address(signerAccount), bob, 1 ether);
        vm.prank(address(signerAccount));
        bool success = signerAccount.approveNative(bob, 1 ether);
        assertTrue(success);
        assertEq(signerAccount.allowance(bob), 1 ether);
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_approveNative_gas() public {
        vm.expectEmit(true, true, false, true);
        emit ApproveNative(address(signerAccount), bob, 1 ether);
        vm.startPrank(address(signerAccount));
        signerAccount.approveNative(bob, 1 ether);
        vm.snapshotGasLastCall("approveNative");
    }

    function test_transferFromNative_revertsWithIncorrectSender() public {
        vm.expectRevert(IERC7914.IncorrectSender.selector);
        signerAccount.transferFromNative(bob, recipient, 1 ether);
    }

    function test_transferFromNative_revertsWithAllowanceExceeded() public {
        vm.prank(address(signerAccount));
        bool success = signerAccount.approveNative(bob, 1 ether);
        assertTrue(success);
        vm.prank(bob);
        vm.expectRevert(IERC7914.AllowanceExceeded.selector);
        signerAccount.transferFromNative(address(signerAccount), bob, 2 ether);
    }

    function test_transferFromNative_zeroAmount_returnsTrue() public {
        vm.prank(address(signerAccount));
        bool success = signerAccount.approveNative(bob, 1 ether);
        vm.prank(bob);
        success = signerAccount.transferFromNative(address(signerAccount), bob, 0);
        assertEq(success, true);
    }

    function test_transferFromNative_succeeds() public {
        // send eth to signerAccount
        vm.deal(address(signerAccount), 1 ether);
        vm.prank(address(signerAccount));
        bool success = signerAccount.approveNative(bob, 1 ether);
        assertTrue(success);
        uint256 bobBalanceBefore = bob.balance;
        uint256 signerAccountBalanceBefore = address(signerAccount).balance;
        vm.expectEmit(true, true, false, true);
        emit TransferFromNative(address(signerAccount), bob, 1 ether);
        vm.prank(bob);
        success = signerAccount.transferFromNative(address(signerAccount), bob, 1 ether);
        assertTrue(success);
        assertEq(signerAccount.allowance(bob), 0);
        assertEq(bob.balance, bobBalanceBefore + 1 ether);
        assertEq(address(signerAccount).balance, signerAccountBalanceBefore - 1 ether);
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_transferFromNative_gas() public {
        // send eth to signerAccount
        vm.deal(address(signerAccount), 1 ether);
        vm.prank(address(signerAccount));
        signerAccount.approveNative(bob, 1 ether);
        vm.expectEmit(true, true, false, true);
        emit TransferFromNative(address(signerAccount), bob, 1 ether);
        vm.prank(bob);
        signerAccount.transferFromNative(address(signerAccount), bob, 1 ether);
        vm.snapshotGasLastCall("transferFromNative");
    }

    function test_fuzz_transferFromNative(uint256 balance, uint256 approvedAmount, uint256 transferAmount) public {
        // ensure there are funds in the signerAccount
        vm.deal(address(signerAccount), balance);
        vm.prank(address(signerAccount));
        bool success = signerAccount.approveNative(bob, approvedAmount);
        assertEq(signerAccount.allowance(bob), approvedAmount);
        assertTrue(success);

        uint256 bobBalanceBefore = bob.balance;
        uint256 signerAccountBalanceBefore = address(signerAccount).balance;

        vm.prank(bob);
        // Check if the transfer amount is greater than the approved amount or the balance of the signerAccount
        // and expect the appropriate revert
        if (transferAmount > approvedAmount) {
            vm.expectRevert(IERC7914.AllowanceExceeded.selector);
        } else if (transferAmount > address(signerAccount).balance) {
            vm.expectRevert(IERC7914.TransferNativeFailed.selector);
        }
        success = signerAccount.transferFromNative(address(signerAccount), bob, transferAmount);
        // if the transfer was successful, check the balances have updated
        // otherwise check the balances have not changed
        if (success) {
            if (approvedAmount < type(uint256).max) {
                assertEq(signerAccount.allowance(bob), approvedAmount - transferAmount);
            } else {
                assertEq(signerAccount.allowance(bob), approvedAmount);
            }
            assertEq(bob.balance, bobBalanceBefore + transferAmount);
            assertEq(address(signerAccount).balance, signerAccountBalanceBefore - transferAmount);
        } else {
            assertEq(signerAccount.allowance(bob), approvedAmount);
            assertEq(bob.balance, bobBalanceBefore);
            assertEq(address(signerAccount).balance, signerAccountBalanceBefore);
        }
    }

    function test_approveNativeTransient_revertsWithUnauthorized() public {
        vm.expectRevert(BaseAuthorization.Unauthorized.selector);
        signerAccount.approveNativeTransient(bob, 1 ether);
    }

    function test_approveNativeTransient_succeeds() public {
        vm.expectEmit(true, true, false, true);
        emit ApproveNativeTransient(address(signerAccount), bob, 1 ether);
        vm.startPrank(address(signerAccount));
        bool success = signerAccount.approveNativeTransient(bob, 1 ether);
        assertTrue(success);
        assertEq(signerAccount.transientAllowance(bob), 1 ether);
    }

    /// forge-config: default.isolate = true
    /// forge-config: ci.isolate = true
    function test_approveNativeTransient_gas() public {
        vm.expectEmit(true, true, false, true);
        emit ApproveNativeTransient(address(signerAccount), bob, 1 ether);
        vm.startPrank(address(signerAccount));
        signerAccount.approveNativeTransient(bob, 1 ether);
        vm.snapshotGasLastCall("approveNativeTransient");
    }

    function test_transferFromNativeTransient_revertsWithIncorrectSender() public {
        vm.expectRevert(IERC7914.IncorrectSender.selector);
        signerAccount.transferFromNativeTransient(bob, recipient, 1 ether);
    }

    function test_transferFromNativeTransient_revertsWithAllowanceExceeded() public {
        vm.prank(address(signerAccount));
        bool success = signerAccount.approveNativeTransient(bob, 1 ether);
        assertTrue(success);
        vm.prank(bob);
        vm.expectRevert(IERC7914.AllowanceExceeded.selector);
        signerAccount.transferFromNativeTransient(address(signerAccount), bob, 2 ether);
    }

    function test_transferFromNativeTransient_zeroAmount_returnsTrue() public {
        vm.prank(address(signerAccount));
        bool success = signerAccount.approveNativeTransient(bob, 1 ether);
        assertTrue(success);
        success = signerAccount.transferFromNativeTransient(address(signerAccount), bob, 0);
        assertEq(success, true);
    }

    function test_transferFromNativeTransient_succeeds() public {
        // send eth to signerAccount
        vm.deal(address(signerAccount), 1 ether);

        vm.prank(address(signerAccount));
        bool success = signerAccount.approveNativeTransient(bob, 1 ether);
        assertTrue(success);

        uint256 bobBalanceBefore = bob.balance;
        uint256 signerAccountBalanceBefore = address(signerAccount).balance;

        vm.expectEmit(true, true, false, true);
        emit TransferFromNativeTransient(address(signerAccount), bob, 1 ether);

        vm.prank(bob);
        success = signerAccount.transferFromNativeTransient(address(signerAccount), bob, 1 ether);
        assertTrue(success);

        assertEq(signerAccount.transientAllowance(bob), 0);
        assertEq(bob.balance, bobBalanceBefore + 1 ether);
        assertEq(address(signerAccount).balance, signerAccountBalanceBefore - 1 ether);
    }

    function test_fuzz_transferFromNativeTransient_succeeds(
        uint256 balance,
        uint256 approvedAmount,
        uint256 transferAmount
    ) public {
        // ensure there are funds in the signerAccount
        vm.deal(address(signerAccount), balance);
        vm.prank(address(signerAccount));
        bool success = signerAccount.approveNativeTransient(bob, approvedAmount);
        assertEq(signerAccount.transientAllowance(bob), approvedAmount);
        assertTrue(success);

        uint256 bobBalanceBefore = bob.balance;
        uint256 signerAccountBalanceBefore = address(signerAccount).balance;

        vm.prank(bob);
        // Check if the transfer amount is greater than the approved amount or the balance of the signerAccount
        // and expect the appropriate revert
        if (transferAmount > approvedAmount) {
            vm.expectRevert(IERC7914.AllowanceExceeded.selector);
        } else if (transferAmount > address(signerAccount).balance) {
            vm.expectRevert(IERC7914.TransferNativeFailed.selector);
        }
        success = signerAccount.transferFromNativeTransient(address(signerAccount), bob, transferAmount);
        // if the transfer was successful, check the balances have updated
        // otherwise check the balances have not changed
        if (success) {
            if (approvedAmount < type(uint256).max) {
                assertEq(signerAccount.transientAllowance(bob), approvedAmount - transferAmount);
            } else {
                assertEq(signerAccount.transientAllowance(bob), approvedAmount);
            }
            assertEq(bob.balance, bobBalanceBefore + transferAmount);
            assertEq(address(signerAccount).balance, signerAccountBalanceBefore - transferAmount);
        } else {
            assertEq(signerAccount.transientAllowance(bob), approvedAmount);
            assertEq(bob.balance, bobBalanceBefore);
            assertEq(address(signerAccount).balance, signerAccountBalanceBefore);
        }
    }
}
