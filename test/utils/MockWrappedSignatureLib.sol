// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {WrappedSignatureLib} from "../../src/libraries/WrappedSignatureLib.sol";

contract MockWrappedSignatureLib {
    using WrappedSignatureLib for bytes;

    function decodeWithHookData(bytes calldata data)
        public
        pure
        returns (bytes memory signature, bytes memory hookData)
    {
        return data.decodeWithHookData();
    }

    function decodeWithKeyHashAndHookData(bytes calldata data)
        public
        pure
        returns (bytes32 keyHash, bytes memory signature, bytes memory hookData)
    {
        return data.decodeWithKeyHashAndHookData();
    }

    function decodeAsTypedDataSig(bytes calldata data)
        public
        pure
        returns (bytes memory signature, bytes32 appSeparator, bytes32 contentsHash, string memory contentsDescr)
    {
        return data.decodeAsTypedDataSig();
    }

    function decodeSignatureWithHookDataInMemory(bytes calldata data)
        public
        pure
        returns (bytes memory signature, bytes memory hookData)
    {
        (signature, hookData) = abi.decode(data, (bytes, bytes));
    }

    function decodeWithKeyHashAndHookDataInMemory(bytes calldata data)
        public
        pure
        returns (bytes32 keyHash, bytes memory signature, bytes memory hookData)
    {
        (keyHash, signature, hookData) = abi.decode(data, (bytes32, bytes, bytes));
    }
}
