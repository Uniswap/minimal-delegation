// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {JavascriptFfi} from "./JavascriptFfi.sol";
import {SignedBatchedCall} from "../../src/libraries/SignedBatchedCallLib.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {console2} from "forge-std/console2.sol";

contract FFISignTypedData is JavascriptFfi {
    using stdJson for string;

    function ffi_signTypedData(
        uint256 privateKey,
        SignedBatchedCall memory signedBatchedCall,
        address verifyingContract
    ) public returns (bytes memory) {
        // Create JSON object
        string memory jsonObj = _createJsonInput(privateKey, signedBatchedCall, verifyingContract);

        // Run the JavaScript script
        return runScript("sign-typed-data", jsonObj);
    }

    /**
     * @dev Creates a JSON input string for the JavaScript script
     */
    function _createJsonInput(uint256 privateKey, SignedBatchedCall memory signedBatchedCall, address verifyingContract)
        internal
        pure
        returns (string memory)
    {
        string memory callsJson = "[";

        for (uint256 i = 0; i < signedBatchedCall.batchedCall.calls.length; i++) {
            if (i > 0) {
                callsJson = string.concat(callsJson, ",");
            }

            callsJson = string.concat(
                callsJson,
                "{",
                '"to":"',
                vm.toString(signedBatchedCall.batchedCall.calls[i].to),
                '",',
                '"value":',
                vm.toString(signedBatchedCall.batchedCall.calls[i].value),
                ",",
                '"data":"0x',
                bytesToHex(signedBatchedCall.batchedCall.calls[i].data),
                '"',
                "}"
            );
        }

        callsJson = string.concat(callsJson, "]");

        string memory batchedCallJson = string.concat(
            "{",
            '"calls":',
            callsJson,
            ",",
            '"shouldRevert":',
            signedBatchedCall.batchedCall.shouldRevert ? "true" : "false",
            "}"
        );

        // Create the SignedBatchedCall object
        string memory signedBatchedCallJson = string.concat(
            "{",
            '"batchedCall":',
            batchedCallJson,
            ",",
            '"nonce":',
            vm.toString(signedBatchedCall.nonce),
            ",",
            '"keyHash":"',
            vm.toString(signedBatchedCall.keyHash),
            '"',
            "}"
        );

        string memory jsonObj = string.concat(
            "{",
            '"privateKey":"',
            vm.toString(privateKey),
            '",',
            '"verifyingContract":"',
            vm.toString(verifyingContract),
            '",',
            '"signedBatchedCall":',
            signedBatchedCallJson,
            "}"
        );

        console2.log(jsonObj);

        return jsonObj;
    }

    /**
     * @dev Converts bytes to a hex string
     */
    function bytesToHex(bytes memory data) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory result = new bytes(data.length * 2);

        for (uint256 i = 0; i < data.length; i++) {
            result[i * 2] = hexChars[uint8(data[i] >> 4)];
            result[i * 2 + 1] = hexChars[uint8(data[i] & 0x0f)];
        }

        return string(result);
    }
}
