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

    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;

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
}
