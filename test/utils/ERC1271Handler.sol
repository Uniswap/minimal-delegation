// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {MockERC1271VerifyingContract} from "./MockERC1271VerifyingContract.sol";
import {MockERC7739Utils} from "./MockERC7739Utils.sol";

contract ERC1271Handler {
    string internal DOMAIN_NAME = "MockERC1271VerifyingContract";
    string internal DOMAIN_VERSION = "1.0.0";

    MockERC1271VerifyingContract internal mockERC1271VerifyingContract =
        new MockERC1271VerifyingContract(DOMAIN_NAME, DOMAIN_VERSION);

    MockERC7739Utils internal mockERC7739Utils = new MockERC7739Utils();

    function getERC1271Fixtures()
        public
        view
        returns (bytes32 appDomainSeparator, string memory contentsDescr, bytes32 contentsHash)
    {
        // Constant at deploy time
        appDomainSeparator = mockERC1271VerifyingContract.domainSeparator();
        // PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitSingle
        contentsDescr = mockERC1271VerifyingContract.contentsDescrExplicit();
        // keccak256(PermitSingle({details: PermitDetails({token: address(0), amount: 0, expiration: 0, nonce: 0}), spender: address(0), sigDeadline: 0}))
        contentsHash = mockERC1271VerifyingContract.defaultContentsHash();
    }
}
