// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/console2.sol";
import "forge-std/Script.sol";
import {CaliburEntry} from "../src/CaliburEntry.sol";

contract DeployCaliburEntry is Script {
    function setUp() public {}

    function run() public returns (CaliburEntry entry) {
        vm.startBroadcast();

        entry = new CaliburEntry{salt: bytes32(0)}();
        console2.log("CaliburEntry", address(entry));

        vm.stopBroadcast();
    }
}
