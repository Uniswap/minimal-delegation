// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title CalldataDecoder
library CalldataDecoder {
    using CalldataDecoder for bytes;
    /// @notice equivalent to SliceOutOfBounds.selector, stored in least-significant bits

    /// @notice mask used for offsets and lengths to ensure no overflow
    /// @dev no sane abi encoding will pass in an offset or length greater than type(uint32).max
    ///      (note that this does deviate from standard solidity behavior and offsets/lengths will
    ///      be interpreted as mod type(uint32).max which will only impact malicious/buggy callers)
    uint256 constant OFFSET_OR_LENGTH_MASK = 0xffffffff;
    uint256 constant OFFSET_OR_LENGTH_MASK_AND_WORD_ALIGN = 0xffffffe0;

    /// error SliceOutOfBounds();
    uint256 constant SLICE_ERROR_SELECTOR = 0x3b99b53d;

    /// @notice Removes the selector from the calldata and returns the encoded params.
    function removeSelector(bytes calldata data) internal pure returns (bytes calldata params) {
        assembly ("memory-safe") {
            if lt(data.length, 4) {
                mstore(0, SLICE_ERROR_SELECTOR)
                revert(0x1c, 4)
            }
            params.offset := add(data.offset, 4)
            params.length := sub(data.length, 4)
        }
    }

    /// @notice Decode the r and s values from a P256 signature
    /// @dev The calldata is expected to be encoded as `abi.encode(bytes32 r, bytes32 s)`
    function decodeP256Signature(bytes calldata signature) internal pure returns (bytes32 r, bytes32 s) {
        assembly ("memory-safe") {
            if lt(signature.length, 0x40) {
                mstore(0, SLICE_ERROR_SELECTOR)
                revert(0x1c, 4)
            }
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
        }
    }

    /// @notice Decode the signature and hook data from the calldata
    /// @dev The calldata is expected to be encoded as `abi.encode(bytes signature, bytes hookData)`
    function decodeSignatureWithHookData(bytes calldata data)
        internal
        pure
        returns (bytes calldata signature, bytes calldata hookData)
    {
        signature = toBytes(data, 0);
        hookData = toBytes(data, 1);
    }

    /// @notice Decode the keyHash, signature, and hook data from the calldata
    /// @dev The calldata is expected to be encoded as `abi.encode(bytes32 keyHash, bytes signature, bytes hookData)`
    function decodeSignatureWithKeyHashAndHookData(bytes calldata data)
        internal
        pure
        returns (bytes32 keyHash, bytes calldata signature, bytes calldata hookData)
    {
        assembly {
            keyHash := calldataload(data.offset)
        }
        signature = toBytes(data, 1);
        hookData = toBytes(data, 2);
    }

    /// @notice Decode the signature, appSeparator, contentsHash, and contentsDescr from the calldata
    ///         the return values MUST be checked for length before use
    /// @dev The calldata is expected to be encoded as `abi.encode(bytes signature, bytes32 appSeparator, bytes32 contentsHash, string contentsDescr)`
    ///      there may be an uint16 contentsLength at the end of the calldata, but this is not used
    function decodeTypedDataSig(bytes calldata data)
        internal
        pure
        returns (bytes calldata signature, bytes32 appSeparator, bytes32 contentsHash, string calldata contentsDescr)
    {
        signature = toBytes(data, 0);
        assembly {
            appSeparator := calldataload(add(data.offset, 0x20))
            contentsHash := calldataload(add(data.offset, 0x40))
        }
        bytes calldata contentsDescrBytes = toBytes(data, 3);
        assembly {
            contentsDescr.offset := contentsDescrBytes.offset
            contentsDescr.length := contentsDescrBytes.length
        }
    }

    /// @notice Decode the `_arg`-th element in `_bytes` as `bytes`
    /// @dev Performs a length check, returning empty bytes if it fails. This MUST be checked by the caller.
    // @param _bytes The input bytes string to extract a bytes string from
    // @param _arg The index of the argument to extract
    function toBytes(bytes calldata _bytes, uint256 _arg) internal pure returns (bytes calldata res) {
        uint256 length;
        assembly ("memory-safe") {
            // The offset of the `_arg`-th element is `32 * arg`, which stores the offset of the length pointer.
            // shl(5, x) is equivalent to mul(32, x)
            let lengthPtr :=
                add(_bytes.offset, and(calldataload(add(_bytes.offset, shl(5, _arg))), OFFSET_OR_LENGTH_MASK))
            // the number of bytes in the bytes string
            length := and(calldataload(lengthPtr), OFFSET_OR_LENGTH_MASK)
            // the offset where the bytes string begins
            let offset := add(lengthPtr, 0x20)
            // assign the return parameters
            res.length := length
            res.offset := offset

            // if the provided bytes string isnt as long as the encoding says, return empty bytes
            if lt(add(_bytes.length, _bytes.offset), add(length, offset)) {
                res.length := 0
                res.offset := 0
            }
        }
    }
}
