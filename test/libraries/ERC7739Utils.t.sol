// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {ERC7739Utils} from "../../src/libraries/ERC7739Utils.sol";

/// Helper contract to test internal library functions
contract MockERC7739Utils {
    function decodeContentsDescr(string memory contentsDescr)
        public
        pure
        returns (string memory contentsName, string memory contentsType)
    {
        return ERC7739Utils.decodeContentsDescr(contentsDescr);
    }
}

/// @title ERC7739UtilsTest
/// @notice Test suite for the ERC7739Utils library
/// @author fixtures from https://github.com/OpenZeppelin/openzeppelin-community-contracts/blob/53f590e4f4902bee0e06e455332e3321c697ea8b/test/utils/cryptography/ERC7739Utils.test.js
contract ERC7739UtilsTest is Test {
    MockERC7739Utils mockERC7739Utils;

    function setUp() public {
        mockERC7739Utils = new MockERC7739Utils();
    }

    function test_decodeContentsDescr_returnsEmptyStringsIfEmptyDescriptor() public view {
        string memory contentsDescr = "";
        (string memory contentsName, string memory contentsType) = mockERC7739Utils.decodeContentsDescr(contentsDescr);
        assertEq(contentsName, "");
        assertEq(contentsType, "");
    }

    function test_decodeContentsDescr_implicitMode_returnsContentsNameAndType() public view {
        string memory contentsDescr = "SomeType(address foo,uint256 bar)";
        (string memory contentsName, string memory contentsType) = mockERC7739Utils.decodeContentsDescr(contentsDescr);
        assertEq(contentsName, "SomeType");
        assertEq(contentsType, "SomeType(address foo,uint256 bar)");
    }

    function test_decodeContentsDescr_implicitMode_returnsEmptyStringsIfNoName() public view {
        string memory contentsDescr = "(SomeType(address foo,uint256 bar)"; // starts with (
        (string memory contentsName, string memory contentsType) = mockERC7739Utils.decodeContentsDescr(contentsDescr);
        assertEq(contentsName, "");
        assertEq(contentsType, "");
    }

    function test_decodeContentsDescr_implicityMode_returnsEmptyStringsIfNoParentheses() public view {
        string memory contentsDescr = "SomeType";
        (string memory contentsName, string memory contentsType) = mockERC7739Utils.decodeContentsDescr(contentsDescr);
        assertEq(contentsName, "");
        assertEq(contentsType, "");
    }

    function test_decodeContentsDescr_explicitMode_returnsContentsNameAndType() public view {
        string memory contentsDescr = "A(C c)B(A a)C(uint256 v)B";
        (string memory contentsName, string memory contentsType) = mockERC7739Utils.decodeContentsDescr(contentsDescr);
        assertEq(contentsName, "B");
        assertEq(contentsType, "A(C c)B(A a)C(uint256 v)");
    }

    function test_decodeContentsDescr_explicitMode_returnsEmptyStringsIfStartsWithParentheses() public view {
        string memory contentsDescr = "(SomeType(address foo,uint256 bar)(SomeType";
        (string memory contentsName, string memory contentsType) = mockERC7739Utils.decodeContentsDescr(contentsDescr);
        assertEq(contentsName, "");
        assertEq(contentsType, "");
    }

    function test_decodeContentsDescr_implicitMode_returnsEmptyStrings_ifInvalidChar() public view {
        // invalid char: ,
        string memory contentsDescr = "SomeType,(address foo,uint256 bar)";
        (string memory contentsName, string memory contentsType) = mockERC7739Utils.decodeContentsDescr(contentsDescr);
        assertEq(contentsName, "");
        assertEq(contentsType, "");

        // invalid char: space
        contentsDescr = "SomeType (address foo,uint256 bar)";
        (contentsName, contentsType) = mockERC7739Utils.decodeContentsDescr(contentsDescr);
        assertEq(contentsName, "");
        assertEq(contentsType, "");

        // invalid char: )
        contentsDescr = "SomeType)(address foo,uint256 bar)";
        (contentsName, contentsType) = mockERC7739Utils.decodeContentsDescr(contentsDescr);
        assertEq(contentsName, "");
        assertEq(contentsType, "");

        // invalid char: \x00
        contentsDescr = "SomeType\x00(address foo,uint256 bar)";
        (contentsName, contentsType) = mockERC7739Utils.decodeContentsDescr(contentsDescr);
        assertEq(contentsName, "");
        assertEq(contentsType, "");
    }
}
