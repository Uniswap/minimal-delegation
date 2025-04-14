// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC7739Utils} from "./libraries/ERC7739Utils.sol";
import {EIP712} from "./EIP712.sol";
import {Key, KeyLib} from "./libraries/KeyLib.sol";
import {TypedDataSignLib} from "./libraries/TypedDataSignLib.sol";
import {PersonalSignLib} from "./libraries/PersonalSignLib.sol";

/// @title ERC7739
/// @notice An abstract contract that implements the ERC-7739 standard
/// @notice This contract assumes that all data verified through ERC-1271 `isValidSignature` implements the defensive nested hashing scheme defined in EIP-7739
/// @dev See https://eips.ethereum.org/EIPS/eip-7739
abstract contract ERC7739 is EIP712 {
    using ERC7739Utils for *;
    using KeyLib for Key;

    /// @notice Hash a PersonalSign struct with the app's domain separator to produce an EIP-712 compatible hash
    /// @dev Uses this account's domain separator in the EIP-712 hash for replay protection
    /// @param hash The hashed message, done offchain
    /// @return The PersonalSign nested EIP-712 hash of the message
    function _getPersonalSignTypedDataHash(bytes32 hash) private view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(domainSeparator(), PersonalSignLib.hash(hash));
    }

    /// @notice Hash TypedDataSign with the app's domain separator to produce an EIP-712 compatible hash
    /// @dev Includes this account's domain in the hash for replay protection
    /// @param contentsName The top level type, per EIP-712
    /// @param contentsType The full type string of the contents, per EIP-712
    /// @param contentsHash The hash of the contents, per EIP-712
    function _getNestedTypedDataSignHash(
        bytes32 appSeparator,
        string memory contentsName,
        string memory contentsType,
        bytes32 contentsHash
    ) private view returns (bytes32) {
        // _eip712Domain().fields and _eip712Domain().extensions are not used
        (, string memory name, string memory version, uint256 chainId, address verifyingContract, bytes32 salt,) =
            eip712Domain();
        bytes memory domainBytes =
            abi.encode(keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract, salt);
        bytes32 typedDataSignHash = TypedDataSignLib.hash(contentsName, contentsType, contentsHash, domainBytes);
        return MessageHashUtils.toTypedDataHash(appSeparator, typedDataSignHash);
    }

    /// @notice Verifies that the claimed contentsHash hashed with the app's separator matches the isValidSignature provided data
    /// @dev This is a necessary check to ensure that the caller provided contentsHash is correct
    /// @param appSeparator The app's domain separator
    /// @param hash The data provided in `isValidSignature`
    /// @param contentsHash The hash of the contents, i.e. hashStruct(contents)
    function _callerHashMatchesReconstructedHash(bytes32 appSeparator, bytes32 hash, bytes32 contentsHash)
        private
        pure
        returns (bool)
    {
        return hash == MessageHashUtils.toTypedDataHash(appSeparator, contentsHash);
    }

    /// @notice Decodes the data for TypedDataSign and verifies the signature against the key over the hash
    /// @dev Performs the required checks per the ERC-7739 spec:
    /// - contentsDescr is not empty
    /// - contentsName is not empty
    /// - The reconstructed hash mathches the hash passed in via isValidSignature
    function _isValidTypedDataSig(Key memory key, bytes32 hash, bytes memory wrappedSignature)
        internal
        view
        returns (bool)
    {
        (bytes memory signature, bytes32 appSeparator, bytes32 contentsHash, string memory contentsDescr) =
            abi.decode(wrappedSignature, (bytes, bytes32, bytes32, string));

        if (bytes(contentsDescr).length == 0) return false;

        (string memory contentsName, string memory contentsType) = ERC7739Utils.decodeContentsDescr(contentsDescr);

        if (bytes(contentsName).length == 0) return false;

        if (!_callerHashMatchesReconstructedHash(appSeparator, hash, contentsHash)) return false;

        bytes32 digest = _getNestedTypedDataSignHash(appSeparator, contentsName, contentsType, contentsHash);
        return key.verify(digest, signature);
    }

    /// @notice Verifies a personal sign signature against the key over the hash
    function _isValidNestedPersonalSignature(Key memory key, bytes32 hash, bytes memory signature)
        internal
        view
        returns (bool)
    {
        return key.verify(_getPersonalSignTypedDataHash(hash), signature);
    }
}
