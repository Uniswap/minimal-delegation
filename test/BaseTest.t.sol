// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {Key, KeyLib} from "../src/lib/KeyLib.sol";
import {MinimalDelegation} from "../src/MinimalDelegation.sol";

contract BaseTest is Test {
    using KeyLib for Key;

    MinimalDelegation public minimalDelegation;
    uint256 signerPrivateKey = 0xa11ce;
    address signer = vm.addr(signerPrivateKey);

    function setUp() public {
        minimalDelegation = new MinimalDelegation();
        _delegate(signer, address(minimalDelegation));
    }

    function _delegate(address _signer, address _implementation) internal {
        vm.etch(_signer, bytes.concat(hex"ef0100", abi.encodePacked(_implementation)));
        require(_signer.code.length > 0, "signer not delegated");
    }
}
