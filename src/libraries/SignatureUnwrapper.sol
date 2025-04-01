// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CalldataDecoder} from "./CalldataDecoder.sol";

library SignatureUnwrapper {
    using CalldataDecoder for bytes;

    bytes32 public constant ROOT_KEY_HASH = bytes32(0);

    /// @notice Unwraps a signature.
    /// @dev If the signature length is 64 or 65, it is not wrapped and is returned to be verified against the root key.
    function unwrap(bytes calldata _signature) internal pure returns (bytes32 keyHash, bytes calldata signature) {
        if (_signature.length == 64 || _signature.length == 65) {
            /// The signature is not wrapped, so it must be a signature derived from the root key.
            return (ROOT_KEY_HASH, _signature);
        } else {
            (keyHash, signature) = _signature.decodeBytes32Bytes();
        }
    }
}
