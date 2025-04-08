// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/console2.sol";
import "forge-std/Script.sol";
import {MinimalDelegationEntry} from "../src/MinimalDelegationEntry.sol";

contract DeployMinimalDelegationEntry is Script {
    function setUp() public {}

    function run() public returns (MinimalDelegationEntry entry) {
        vm.startBroadcast();

        entry = new MinimalDelegationEntry{salt: bytes32(0)}();
        console2.log("MinimalDelegationEntry", address(entry));

        vm.stopBroadcast();
    }
}
