// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {JavascriptFfi} from "./JavascriptFfi.sol";
import {SignedCalls} from "../../src/libraries/SignedCallsLib.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {console2} from "forge-std/console2.sol";

contract FFISignTypedData is JavascriptFfi {
    using stdJson for string;

    function ffi_signTypedData(uint256 privateKey, SignedCalls memory signedCalls, address verifyingContract)
        public
        returns (bytes memory)
    {
        // Create JSON object
        string memory jsonObj = _createJsonInput(privateKey, signedCalls, verifyingContract);

        // Run the JavaScript script
        return runScript("sign-typed-data", jsonObj);
    }

    /**
     * @dev Creates a JSON input string for the JavaScript script
     */
    function _createJsonInput(uint256 privateKey, SignedCalls memory signedCalls, address verifyingContract)
        internal
        pure
        returns (string memory)
    {
        string memory callsJson = "[";

        for (uint256 i = 0; i < signedCalls.calls.length; i++) {
            if (i > 0) {
                callsJson = string.concat(callsJson, ",");
            }

            callsJson = string.concat(
                callsJson,
                "{",
                '"to":"',
                vm.toString(signedCalls.calls[i].to),
                '",',
                '"value":',
                vm.toString(signedCalls.calls[i].value),
                ",",
                '"data":"0x',
                bytesToHex(signedCalls.calls[i].data),
                '"',
                "}"
            );
        }

        callsJson = string.concat(callsJson, "]");

        // Create the SignedCalls object
        string memory signedCallsJson = string.concat(
            "{",
            '"calls":',
            callsJson,
            ",",
            '"nonce":',
            vm.toString(signedCalls.nonce),
            ",",
            '"keyHash":"',
            vm.toString(signedCalls.keyHash),
            '",',
            '"shouldRevert":',
            signedCalls.shouldRevert ? "true" : "false",
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
            '"signedCalls":',
            signedCallsJson,
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
