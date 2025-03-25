// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IERC5267} from "openzeppelin-contracts/contracts/interfaces/IERC5267.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {IERC1271} from "../src/interfaces/IERC1271.sol";
import {IEIP712} from "../src/interfaces/IEIP712.sol";
import {WrappedDataHash} from "../src/libraries/WrappedDataHash.sol";
import {CallBuilder} from "./utils/CallBuilder.sol";
import {Call} from "../src/libraries/CallLib.sol";
import {CallLib} from "../src/libraries/CallLib.sol";

contract ERC712Test is DelegationHandler {
    using WrappedDataHash for bytes32;
    using CallLib for Call[];

    function setUp() public {
        setUpDelegation();
    }

    function test_domainSeparator() public view {
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        ) = signerAccount.eip712Domain();
        // Ensure that verifying contract is the signer
        assertEq(verifyingContract, address(signer));
        assertEq(abi.encode(extensions), abi.encode(new uint256[](0)));
        assertEq(salt, bytes32(0));
        assertEq(name, "Uniswap Minimal Delegation");
        assertEq(version, "1");
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        assertEq(expected, signerAccount.domainSeparator());
    }

    function test_hashTypedData() public view {
        Call[] memory calls = CallBuilder.init();
        bytes32 hashTypedData = signerAccount.hashTypedData(calls.hash());
        // re-implement 712 hash
        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", signerAccount.domainSeparator(), calls.hash()));
        assertEq(expected, hashTypedData);
    }
}
