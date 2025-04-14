// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {MockERC1271VerifyingContract} from "./MockERC1271VerifyingContract.sol";

contract ERC1271Handler {
    string internal DOMAIN_NAME = "MockERC1271VerifyingContract";
    string internal DOMAIN_VERSION = "1";

    MockERC1271VerifyingContract internal mockERC1271VerifyingContract =
        new MockERC1271VerifyingContract(DOMAIN_NAME, DOMAIN_VERSION);

    bytes32 TEST_APP_DOMAIN_SEPARATOR;
    string TEST_CONTENTS_DESCR;
    bytes32 TEST_CONTENTS_HASH;

    function setUpERC1271() public {
        // Constant at deploy time
        TEST_APP_DOMAIN_SEPARATOR = mockERC1271VerifyingContract.domainSeparator();
        // PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitSingle
        TEST_CONTENTS_DESCR = mockERC1271VerifyingContract.contentsDescrExplicit();
        // keccak256(PermitSingle({details: PermitDetails({token: address(0), amount: 0, expiration: 0, nonce: 0}), spender: address(0), sigDeadline: 0}))
        TEST_CONTENTS_HASH = mockERC1271VerifyingContract.defaultContentsHash();
    }
}
