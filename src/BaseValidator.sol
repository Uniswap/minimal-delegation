// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {Key, KeyLib} from "./libraries/KeyLib.sol";

/// Fallback validator for signature verification
contract BaseValidator {
    using KeyLib for Key;

    bytes32 public constant ROOT_KEY_HASH = bytes32(0);

    /// @notice Checks if the signature is not in wrapped form
    function _isUnwrapped(bytes calldata signature) internal pure returns (bool) {
        return signature.length == 64 || signature.length == 65;
    }

    /// @notice Verifies a signature against the root key.
    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool isValid) {
        // The signature is not wrapped, so it can be verified against the root key.
        isValid = ECDSA.recoverCalldata(digest, signature) == address(this);
    }

    /// @notice Verifies a signature against a key in storage
    /// @dev Should be used as a fallback for signature verification
    function _verifySignature(bytes32 digest, Key memory key, bytes calldata signature)
        internal
        view
        virtual
        returns (bool isValid)
    {
        isValid = key.verify(digest, signature);
    }
}
