// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IERC5267} from "openzeppelin-contracts/contracts/interfaces/IERC5267.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {IERC1271} from "../src/interfaces/IERC1271.sol";
import {IEIP712} from "../src/interfaces/IEIP712.sol";

contract ERC1271Test is DelegationHandler {
    bytes4 private constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 private constant _1271_INVALID_VALUE = 0xffffffff;

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

    function test_hashTypedData() public {
        bytes32 hash = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(hash);
        // re-implement 712 hash
        bytes32 _MESSAGE_TYPEHASH = keccak256("UniswapMinimalDelegationMessage(bytes32 hash)");
        bytes32 expected = keccak256(
            abi.encodePacked(
                "\x19\x01",
                signerAccount.domainSeparator(),
                // _hashStruct(bytes32)
                keccak256(abi.encode(_MESSAGE_TYPEHASH, hash))
            )
        );
        assertEq(expected, hashTypedData);
    }

    function test_isValidSignature_sep256k1_succeeds() public {
        bytes32 hash = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, hashTypedData);
        bytes memory signature = abi.encodePacked(r, s, v);
        // ensure the call returns the ERC1271 magic value
        assertEq(signerAccount.isValidSignature(hash, signature), _1271_MAGIC_VALUE);
    }

    function test_isValidSignature_sep256k1_invalidSigner() public {
        bytes32 hash = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(hash);
        // sign with a different private key
        uint256 invalidPrivateKey = 0xdeadbeef;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(invalidPrivateKey, hashTypedData);
        bytes memory signature = abi.encodePacked(r, s, v);
        // ensure the call returns the ERC1271 invalid magic value
        assertEq(signerAccount.isValidSignature(hash, signature), _1271_INVALID_VALUE);
    }

    function test_isValidSignature_invalidSignatureLength_reverts() public {
        bytes32 hash = keccak256("test");
        bytes memory signature = new bytes(63);
        vm.expectRevert();
        signerAccount.isValidSignature(hash, signature);
    }
}
