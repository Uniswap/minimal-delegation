// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/console2.sol";
import "forge-std/Script.sol";
import {MinimalDelegation} from "../src/MinimalDelegation.sol";

contract DeployMinimalDelegation is Script {
    function setUp() public {}

    function run() public returns (MinimalDelegation delegation) {
        vm.startBroadcast();

        delegation = new MinimalDelegation();
        console2.log("MinimalDelegation", address(delegation));

        vm.stopBroadcast();
    }
}
