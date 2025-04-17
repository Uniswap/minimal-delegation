// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC7739Utils} from "./libraries/ERC7739Utils.sol";
import {EIP712} from "./EIP712.sol";
import {Key, KeyLib} from "./libraries/KeyLib.sol";
import {TypedDataSignLib} from "./libraries/TypedDataSignLib.sol";
import {PersonalSignLib} from "./libraries/PersonalSignLib.sol";
import {CalldataDecoder} from "./libraries/CalldataDecoder.sol";

/// @title ERC7739
/// @notice An abstract contract that implements the ERC-7739 standard
/// @notice This contract assumes that all data verified through ERC-1271 `isValidSignature` implements the defensive nested hashing scheme defined in EIP-7739
/// @dev See https://eips.ethereum.org/EIPS/eip-7739
abstract contract ERC7739 is EIP712 {
    using CalldataDecoder for bytes;
    using ERC7739Utils for *;
    using KeyLib for Key;

    /// @notice Encode the EIP-5267 domain into bytes
    function _domainBytes() private view returns (bytes memory) {
        // _eip712Domain().fields and _eip712Domain().extensions are not used
        (, string memory name, string memory version, uint256 chainId, address verifyingContract, bytes32 salt,) =
            eip712Domain();
        return abi.encode(keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract, salt);
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
    /// - The reconstructed hash matches the hash passed in via isValidSignature
    function _isValidTypedDataSig(Key memory key, bytes32 hash, bytes calldata wrappedSignature)
        internal
        view
        returns (bool)
    {
        (bytes calldata signature, bytes32 appSeparator, bytes32 contentsHash, string calldata contentsDescr) =
            wrappedSignature.decodeTypedDataSig();

        bytes32 digest;
        {
            (string calldata contentsName, string calldata contentsType) =
                ERC7739Utils.decodeContentsDescr(contentsDescr);
            assembly {
                // Check if either contentsName or contentsType is empty
                if or(iszero(contentsName.length), iszero(contentsType.length)) {
                    // return false
                    mstore(0x00, 0)
                    return(0x00, 32)
                }
            }
            digest = contentsHash.toNestedTypedDataSignHash(_domainBytes(), appSeparator, contentsName, contentsType);
        }
        if (!_callerHashMatchesReconstructedHash(appSeparator, hash, contentsHash)) return false;

        return key.verify(digest, signature);
    }

    /// @notice Verifies a personal sign signature against the key over the hash
    function _isValidNestedPersonalSignature(Key memory key, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        return key.verify(hash.toPersonalSignTypedDataHash(domainSeparator()), signature);
    }
}
