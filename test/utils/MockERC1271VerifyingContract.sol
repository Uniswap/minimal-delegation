// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

struct Mail {
    Letter letter;
}
    
struct Letter {
    address recipient;
}

/// @title MockERC1271VerifyingContract
/// @notice A mock contract that implements the ERC-1271 interface
/// @dev This contract is used to test against our ERC-7739 implementation
contract MockERC1271VerifyingContract is EIP712 {
    constructor(string memory name, string memory version) EIP712(name, version) {}

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// return the full contents descriptor string
    function contentsDescr() external pure returns (string memory) {
        return "Mail(Letter letter)";
    }
    
    /// returns hashStruct(Mail)
    function hash(Mail memory mail) public view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("Mail(Letter letter)"),
            hash(mail.letter)
        ));
    }

    /// returns hashStruct(Letter)
    function hash(Letter memory letter) public view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("Letter(address recipient)"),
            letter.recipient
        ));
    }

    /// returns the EIP-712 digest using the domain separator
    function hashTypedDataV4(bytes32 dataHash) public view returns (bytes32) {
        return _hashTypedDataV4(dataHash);
    }

    /// returns the default contents for testing
    function defaultContents() public view returns (Mail memory) {
        return Mail({letter: Letter({recipient: address(0)})});
    }

    function defaultContentsHash() public view returns (bytes32) {
        return hash(defaultContents());
    }
}