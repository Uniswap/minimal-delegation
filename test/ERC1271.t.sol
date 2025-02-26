// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {IERC1271} from "../src/interfaces/IERC1271.sol";

contract ERC1271Test is DelegationHandler {
    function setUp() public {
        setUpDelegation();
    }

    function test_domainSeparator() public {
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        ) = IERC1271(address(signer)).eip712Domain();
        // Ensure that verifying contract is the signer
        assertEq(verifyingContract, address(signer));
        assertEq(abi.encode(extensions), abi.encode(new uint256[](0)));
        assertEq(salt, bytes32(0));
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        assertEq(expected, IERC1271(address(signer)).domainSeparator());
    }

    function test_replaySafeHash() public {
        bytes32 hash = keccak256("test");
        bytes32 replaySafeHash = IERC1271(address(signer)).replaySafeHash(hash);
        // re-implement 712 hash
        bytes32 _MESSAGE_TYPEHASH = keccak256("UniswapMinimalDelegationMessage(bytes32 hash)");
        bytes32 expected = keccak256(
            abi.encodePacked(
                "\x19\x01",
                IERC1271(address(signer)).domainSeparator(),
                // _hashStruct(bytes32)
                keccak256(abi.encode(_MESSAGE_TYPEHASH, hash))
            )
        );
        assertEq(expected, replaySafeHash);
    }
}
