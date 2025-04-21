// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC7739Utils} from "./libraries/ERC7739Utils.sol";
import {Key, KeyLib} from "./libraries/KeyLib.sol";
import {TypedDataSignLib} from "./libraries/TypedDataSignLib.sol";
import {PersonalSignLib} from "./libraries/PersonalSignLib.sol";
import {CalldataDecoder} from "./libraries/CalldataDecoder.sol";

/// @title ERC7739
/// @notice An abstract contract that implements the ERC-7739 standard
/// @notice This contract assumes that all data verified through ERC-1271 `isValidSignature` implements the defensive nested hashing scheme defined in EIP-7739
/// @dev See https://eips.ethereum.org/EIPS/eip-7739
abstract contract ERC7739 {
    using CalldataDecoder for bytes;
    using ERC7739Utils for *;
    using KeyLib for Key;

    /// @notice Decodes the data for TypedDataSign and verifies the signature against the key over the hash
    /// @dev Performs the required checks per the ERC-7739 spec:
    /// - The reconstructed hash matches the hash passed in via isValidSignature
    /// - The contentsDescr is valid
    function _isValidTypedDataSig(Key memory key, bytes32 hash, bytes memory domainBytes, bytes calldata wrappedSignature)
        internal
        view
        returns (bool)
    {
        (bytes calldata signature, bytes32 appSeparator, bytes32 contentsHash, string calldata contentsDescr) =
            wrappedSignature.decodeTypedDataSig();

        // If the reconstructed hash does not match the caller's hash, the signature is invalid
        if (hash != MessageHashUtils.toTypedDataHash(appSeparator, contentsHash)) return false;

        bytes32 digest = contentsHash.toNestedTypedDataSignHash(domainBytes, appSeparator, contentsDescr);
        // If the digest is 0, the contentsDescr was invalid
        if(digest == bytes32(0)) return false;

        return key.verify(digest, signature);
    }

    /// @notice Verifies a personal sign signature against the key over the hash
    function _isValidNestedPersonalSignature(Key memory key, bytes32 hash, bytes32 domainSeparator,bytes calldata signature)
        internal
        view
        returns (bool)
    {
        return key.verify(hash.toPersonalSignTypedDataHash(domainSeparator), signature);
    }
}
