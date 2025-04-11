// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title TypedDataSignLib
/// @notice Library supporting nesting of EIP-712 typed data signatures
/// Follows ERC-7739 spec
library TypedDataSignLib {
    /// @dev Generate the type string for the TypedDataSign struct
    function _toTypedDataSignTypeString(string calldata contentsName, string calldata contentsType) internal pure returns (string memory) {
        return abi.encodePacked(
                    "TypedDataSign(",
                    contentsName,
                    " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                    contentsType
                )
    }

    function _toTypedDataSignTypeHash(string calldata contentsName, string calldata contentsType) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(_toTypedDataSignTypeString(contentsName, contentsType)));
    }

    /// TODO: bytes(contentsName).length = 0 return bytes32(0)?
    /// @dev domainBytes is abi.encodePacked(name, version, chainId, verifyingContract, salt)
    function hash(string calldata contentsName, string calldata contentsType, bytes32 contentsHash, bytes memory domainBytes) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                _toTypedDataSignTypeHash(contentsName, contentsType),
                contentsHash,
                domainBytes
            )
        );
    }
}
