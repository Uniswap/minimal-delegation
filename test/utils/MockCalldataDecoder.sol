// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CalldataDecoder} from "../../src/libraries/CalldataDecoder.sol";
import {Call} from "../../src/libraries/CallLib.sol";

contract MockCalldataDecoder {
    using CalldataDecoder for bytes;

    function removeSelector(bytes calldata data) public pure returns (bytes memory _data) {
        return data.removeSelector();
    }

    function decodeP256Signature(bytes calldata data) public pure returns (bytes32 r, bytes32 s) {
        return data.decodeP256Signature();
    }

    function decodeSignatureWithHookData(bytes calldata data)
        public
        pure
        returns (bytes memory signature, bytes memory hookData)
    {
        return data.decodeSignatureWithHookData();
    }

    function decodeSignatureWithKeyHashAndHookData(bytes calldata data)
        public
        pure
        returns (bytes32 keyHash, bytes memory signature, bytes memory hookData)
    {
        return data.decodeSignatureWithKeyHashAndHookData();
    }

    function decodeTypedDataSig(bytes calldata data)
        public
        pure
        returns (bytes memory signature, bytes32 appSeparator, bytes32 contentsHash, string memory contentsDescr)
    {
        return data.decodeTypedDataSig();
    }
}
