// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {MinimalDelegation} from "../src/MinimalDelegation.sol";

contract BaseTest is Test {
    MinimalDelegation public minimalDelegation;
    uint256 signerPrivateKey = 0xa11ce;
    address signer = vm.addr(signerPrivateKey);

    function setUp() public {
        minimalDelegation = new MinimalDelegation();

        // delegate the signer to the minimalDelegation
        vm.etch(signer, bytes.concat(hex"ef0100", abi.encodePacked(address(minimalDelegation))));
        require(signer.code.length > 0, "signer not delegated");
    }
}
