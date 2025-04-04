// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {JavascriptFfi} from "./JavascriptFfi.sol";
import {Call} from "../../src/libraries/CallLib.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {console2} from "forge-std/console2.sol";

contract FFISignTypedData is JavascriptFfi {
    using stdJson for string;

    function ffi_signTypedData(uint256 privateKey, Call[] memory calls, uint256 nonce, address verifyingContract)
        public
        returns (bytes memory)
    {
        // Create JSON object
        string memory jsonObj = _createJsonInput(privateKey, calls, nonce, verifyingContract);

        // Run the JavaScript script
        return runScript("sign-typed-data", jsonObj);
    }

    /**
     * @dev Creates a JSON input string for the JavaScript script
     */
    function _createJsonInput(uint256 privateKey, Call[] memory calls, uint256 nonce, address verifyingContract)
        internal
        pure
        returns (string memory)
    {
        string memory callsJson = "[";

        for (uint256 i = 0; i < calls.length; i++) {
            if (i > 0) {
                callsJson = string.concat(callsJson, ",");
            }

            callsJson = string.concat(
                callsJson,
                "{",
                '"to":"',
                vm.toString(calls[i].to),
                '",',
                '"value":',
                vm.toString(calls[i].value),
                ",",
                '"data":"0x',
                bytesToHex(calls[i].data),
                '"',
                "}"
            );
        }

        callsJson = string.concat(callsJson, "]");

        string memory jsonObj = string.concat(
            "{",
            '"privateKey":"',
            vm.toString(privateKey),
            '",',
            '"verifyingContract":"',
            vm.toString(verifyingContract),
            '",',
            '"calls":',
            callsJson,
            ',"nonce":',
            vm.toString(nonce),
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
