// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {console2} from "forge-std/console2.sol";
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

    // TODO: natspec for all

    /**
     * @dev Uses this contract's domain separator which is calculated at runtime
     */
    function _getPersonalSignTypedDataHash(bytes32 hash) private view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(_domainSeparator(), PersonalSignLib.hash(hash));
    }

    /// @dev the output MUST be hashed with the app's domain separator
    function _getNestedTypedDataSignHash(
        bytes32 appSeparator,
        string memory contentsName,
        string memory contentsType,
        bytes32 contentsHash
    ) private view returns (bytes32) {
        // _eip712Domain().fields and _eip712Domain().extensions are not used
        (, string memory name, string memory version, uint256 chainId, address verifyingContract, bytes32 salt,) =
            _eip712Domain();
        bytes memory domainBytes =
            abi.encode(keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract, salt);
        return MessageHashUtils.toTypedDataHash(
            appSeparator, TypedDataSignLib.hash(contentsName, contentsType, contentsHash, domainBytes)
        );
    }

    /// @dev the contentHash hashed with the app's separtor MUST match the caller provided hash
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

        console2.log("_isValidTypedDataSig appSeparator");
        console2.logBytes32(appSeparator);
        console2.log("_isValidTypedDataSig contentsName");
        console2.log(contentsName);
        console2.log("_isValidTypedDataSig contentsType");
        console2.log(contentsType);
        console2.log("_isValidTypedDataSig contentsHash");
        console2.logBytes32(contentsHash);

        bytes32 digest = _getNestedTypedDataSignHash(appSeparator, contentsName, contentsType, contentsHash);
        console2.log("_isValidTypedDataSig verifying digest");
        console2.logBytes32(digest);
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
