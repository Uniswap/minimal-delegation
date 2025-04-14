// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

struct PermitSingle {
    PermitDetails details;
    address spender;
    uint256 sigDeadline;
}

struct PermitDetails {
    address token;
    uint160 amount;
    uint48 expiration;
    uint48 nonce;
}

/// @title MockERC1271VerifyingContract
/// @notice A mock contract that implements the ERC-1271 interface
/// @dev This contract is used to test against our ERC-7739 implementation
contract MockERC1271VerifyingContract is EIP712 {
    string internal constant PERMIT_SINGLE_TYPE =
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
    bytes32 internal constant PERMIT_SINGLE_TYPEHASH = keccak256(bytes(PERMIT_SINGLE_TYPE));

    string internal constant PERMIT_DETAILS_TYPE =
        "PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
    bytes32 internal constant PERMIT_DETAILS_TYPEHASH = keccak256(bytes(PERMIT_DETAILS_TYPE));

    constructor(string memory name, string memory version) EIP712(name, version) {}

    function EIP712Name() external view returns (string memory) {
        return _EIP712Name();
    }

    function EIP712Version() external view returns (string memory) {
        return _EIP712Version();
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// return the full contents descriptor string
    function contentsDescr() external pure returns (string memory) {
        return PERMIT_SINGLE_TYPE;
    }

    /// returns hashStruct(PermitSingle)
    function hash(PermitSingle memory permitSingle) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                PERMIT_SINGLE_TYPEHASH, hash(permitSingle.details), permitSingle.spender, permitSingle.sigDeadline
            )
        );
    }

    /// returns hashStruct(PermitDetails)
    function hash(PermitDetails memory permitDetails) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                PERMIT_DETAILS_TYPEHASH,
                permitDetails.token,
                permitDetails.amount,
                permitDetails.expiration,
                permitDetails.nonce
            )
        );
    }

    /// returns the EIP-712 digest using the domain separator
    function hashTypedDataV4(bytes32 dataHash) public view returns (bytes32) {
        return _hashTypedDataV4(dataHash);
    }

    /// returns the default contents for testing
    function defaultContents() public view returns (PermitSingle memory) {
        return PermitSingle({
            details: PermitDetails({token: address(0), amount: 0, expiration: 0, nonce: 0}),
            spender: address(0),
            sigDeadline: 0
        });
    }

    function defaultContentsHash() public view returns (bytes32) {
        return hash(defaultContents());
    }
}
