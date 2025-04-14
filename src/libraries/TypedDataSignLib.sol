// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {console2} from "forge-std/console2.sol";

/// @title TypedDataSignLib
/// @notice Library supporting nesting of EIP-712 typed data signatures
/// Follows ERC-7739 spec
library TypedDataSignLib {
    /// @dev Generate the dynamic type string for the TypedDataSign struct
    function _toTypedDataSignTypeString(string memory contentsName, string memory contentsType)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
                "TypedDataSign(",
                contentsName,
                " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                contentsType
            );
    }

    /// @dev Create the type hash for a TypedDataSign struct
    function _toTypedDataSignTypeHash(string memory contentsName, string memory contentsType)
        internal
        pure
        returns (bytes32)
    {
        console2.log("test.TypedDataSignLib _toTypedDataSignTypeString %s", string(_toTypedDataSignTypeString(contentsName, contentsType)));
        return keccak256(_toTypedDataSignTypeString(contentsName, contentsType));
    }

    /// @notice contentsName and contentsType MUST be checked for length before hashing
    /// @dev domainBytes is abi.encode(name, version, chainId, verifyingContract, salt)
    function hash(
        string memory contentsName,
        string memory contentsType,
        bytes32 contentsHash,
        bytes memory domainBytes
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                _toTypedDataSignTypeHash(contentsName, contentsType), 
                contentsHash, 
                domainBytes
            )
        );
    }
}
