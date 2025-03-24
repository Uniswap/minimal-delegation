// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {MinimalDelegation} from "../src/MinimalDelegation.sol";
import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {KeyType} from "../src/libraries/KeyLib.sol";
import {TestKeyManager, TestKey} from "./utils/TestKeyManager.sol";
import {WrappedDataHash} from "../src/libraries/WrappedDataHash.sol";

contract MinimalDelegationIsValidSignatureTest is DelegationHandler {
    using TestKeyManager for TestKey;
    using WrappedDataHash for bytes32;

    bytes4 private constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 private constant _1271_INVALID_VALUE = 0xffffffff;

    function setUp() public {
        setUpDelegation();
    }

    function test_isValidSignature_P256_isValid() public {
        TestKey memory p256Key = TestKeyManager.initDefault(KeyType.P256);

        bytes32 testDigest = keccak256("Test");
        bytes32 testDigestToSign = signerAccount.hashTypedData(testDigest.hashWithWrappedType());
        bytes memory signature = p256Key.sign(testDigestToSign);

        vm.startPrank(address(signer));
        signerAccount.authorize(p256Key.toKey());
        bytes4 result = signerAccount.isValidSignature(testDigest, abi.encode(p256Key.toKeyHash(), signature));
        assertEq(result, _1271_MAGIC_VALUE);
    }

    function test_isValidSignature_sep256k1_succeeds() public view {
        bytes32 data = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(data.hashWithWrappedType());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, hashTypedData);
        bytes memory signature = abi.encodePacked(r, s, v);
        // ensure the call returns the ERC1271 magic value
        assertEq(signerAccount.isValidSignature(data, signature), _1271_MAGIC_VALUE);
    }

    function test_isValidSignature_sep256k1_invalidSigner() public view {
        bytes32 hash = keccak256("test");
        bytes32 hashTypedData = signerAccount.hashTypedData(hash.hashWithWrappedType());
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
