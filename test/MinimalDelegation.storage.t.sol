// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {MinimalDelegation} from "../src/MinimalDelegation.sol";

contract MinimalDelegationStorageTest is DelegationHandler {
    function setUp() public {
        setUpDelegation();
    }

    /// @dev Sanity check tests for changes in namespace and version
    function test_erc7201_namespaceAndVersion() public {
        assertEq(ERC7201.namespaceAndVersion(), "Uniswap.ERC7201.1.0.0");
    }

    /// @dev Sanity check tests for changes in the calculated custom storage root
    function test_erc7201_customStorageRoot() public {
        bytes32 customStorageRoot = keccak256(abi.encode(uint256(keccak256("Uniswap.ERC7201.1.0.0")) - 1)) & ~bytes32(uint256(0xff));
        assertEq(ERC7201.CUSTOM_STORAGE_ROOT, customStorageRoot);
    }
}
