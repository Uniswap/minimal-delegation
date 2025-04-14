// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {console2} from "forge-std/console2.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {TypedDataSignLib} from "../../src/libraries/TypedDataSignLib.sol";
import {ERC7739Utils} from "../../src/libraries/ERC7739Utils.sol";

/// @title TypedDataSignBuilder
/// @notice A library to help build ERC-7739 nested typed data signatures
library TypedDataSignBuilder {
    /// @notice Helper function to extract the domain bytes from a contract which implements EIP-5267
    function toDomainBytes(IERC5267 account) internal view returns (bytes memory) {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract, bytes32 salt,) =
            account.eip712Domain();
        return abi.encode(keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract, salt);
    }

    /// @notice Builds a nested typed data signature for the given contents hash, domain bytes, and contents descriptor
    function hashTypedDataSign(
        bytes32 contentsHash,
        bytes memory domainBytes,
        bytes32 appSeparator,
        string memory contentsDescr
    ) internal pure returns (bytes32) {
        (string memory contentsName, string memory contentsType) = ERC7739Utils.decodeContentsDescr(contentsDescr);
        return MessageHashUtils.toTypedDataHash(
            appSeparator, TypedDataSignLib.hash(contentsName, contentsType, contentsHash, domainBytes)
        );
    }

    /// @notice Builds a nested typed data sign signature
    function buildTypedDataSignSignature(
        bytes memory signature,
        bytes32 appSeparator,
        bytes32 contentsHash,
        string memory contentsDescr
    ) internal pure returns (bytes memory) {
        return abi.encode(signature, appSeparator, contentsHash, contentsDescr);
    }
}
