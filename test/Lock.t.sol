// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {MockLock} from "./utils/MockLock.sol";

contract LockTest is Test {
    MockLock public mockLock;

    address public addressThis;
    address public externalLocker = makeAddr("externalLocker");

    bytes constant LOCKER_IS_THIS = abi.encodeWithSelector(bytes4(keccak256("lockerIsThis()")));
    bytes constant LOCKER_IS_ANYONE = abi.encodeWithSelector(bytes4(keccak256("lockerIsAnyone()")));

    function setUp() public {
        mockLock = new MockLock();
        addressThis = address(mockLock);
    }

    function test_lockerIsThis_succeeds() public {
        vm.prank(addressThis);
        mockLock.lockerIsThis();
    }

    function test_lockerIsThis_reverts_externalLocker() public {
        vm.prank(externalLocker);
        vm.expectRevert(abi.encodeWithSelector(MockLock.LockerIsNotThis.selector));
        mockLock.lockerIsThis();
    }

    function test_selfCall_lockerIsThis_succeeds() public {
        vm.prank(addressThis);
        mockLock.selfCall(LOCKER_IS_THIS);
    }

    function test_selfCall_lockerIsThis_reverts_externalLocker() public {
        vm.prank(externalLocker);
        vm.expectRevert(abi.encodeWithSelector(MockLock.LockerIsNotThis.selector));
        mockLock.selfCall(LOCKER_IS_THIS);
    }

    function test_selfCall_lockerIsAnyone_succeeds_externalLocker() public {
        vm.prank(externalLocker);
        mockLock.selfCall(LOCKER_IS_ANYONE);
    }
}
