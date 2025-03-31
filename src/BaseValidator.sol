// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {Key, KeyLib} from "./libraries/KeyLib.sol";

contract BaseValidator {
    using KeyLib for Key;

    bytes32 public constant ROOT_KEY_HASH = bytes32(0);

    function _preRuntimeValidationHook(bytes32 digest, bytes32 keyHash, bytes calldata signature)
        internal
        view
        virtual
    {}
    function _postRuntimeValidationHook(bytes32 digest, bytes32 keyHash, bytes calldata signature)
        internal
        view
        virtual
    {}

    function _isRawSignature(bytes calldata signature) internal pure returns (bool) {
        return signature.length == 64 || signature.length == 65;
    }

    /// @dev Verifies a signature against the root key.
    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool isValid) {
        _preRuntimeValidationHook(digest, ROOT_KEY_HASH, signature);
        // The signature is not wrapped, so it can be verified against the root key.
        isValid = ECDSA.recoverCalldata(digest, signature) == address(this);
        _postRuntimeValidationHook(digest, ROOT_KEY_HASH, signature);
    }

    function _verifySignature(bytes32 digest, Key memory key, bytes calldata signature)
        internal
        view
        returns (bool isValid)
    {
        bytes32 keyHash = key.hash();
        _preRuntimeValidationHook(digest, keyHash, signature);
        isValid = key.verify(digest, signature);
        _postRuntimeValidationHook(digest, keyHash, signature);
    }
}
