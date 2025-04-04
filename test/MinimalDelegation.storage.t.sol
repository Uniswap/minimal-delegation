// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {DelegationHandler} from "./utils/DelegationHandler.sol";
import {MinimalDelegation} from "../src/MinimalDelegation.sol";

contract MinimalDelegationStorageTest is DelegationHandler {
    /**
     * MinimalDelegation storage layout
     * slots are assigned starting from the custom layout slot and in order of declaration, from left to right
     *
     * MinimalDelegation is IERC7821, ERC1271, EIP712, ERC4337Account, Receiver, KeyManagement, NonceManager, ERC7201 layout at 0xc807f46cbe2302f9a007e47db23c8af6a94680c1d26280fb9582873dbe5c9200
     *
     * 0: mapping(bytes32 keyHash => KeyExtraStorage) keyExtraStorage;
     * 1: mapping(bytes32 keyHash => bytes encodedKey) keyStorage;
     * 2: EnumerableSetLib.Bytes32Set keyHashes;
     * 3: mapping(uint256 key => uint256 seq) nonceSequenceNumber
     * 4: uint256 entryPoint
     */
    uint256 private constant KEY_EXTRA_STORAGE_SLOT = 0;
    uint256 private constant KEY_STORAGE_SLOT = 1;
    uint256 private constant KEY_HASHES_SLOT = 2;
    uint256 private constant NONCE_SEQUENCE_NUMBER_SLOT = 3;
    uint256 private constant ENTRY_POINT_SLOT = 4;

    function setUp() public {
        setUpDelegation();
    }

    function _addOffset(bytes32 slot, uint256 offset) internal pure returns (bytes32) {
        return bytes32(uint256(slot) + offset);
    }

    function _calculateNestedMappingSlot(uint256 key, bytes32 rootSlot) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, uint256(rootSlot)));
    }

    /// @dev Sanity check tests for changes in namespace and version
    function test_erc7201_namespaceAndVersion() public {
        assertEq(signerAccount.namespaceAndVersion(), "Uniswap.MinimalDelegation.1.0.0");
    }

    /// @dev Sanity check tests for changes in the calculated custom storage root
    function test_erc7201_customStorageRoot() public {
        bytes32 customStorageRoot =
            keccak256(abi.encode(uint256(keccak256("Uniswap.MinimalDelegation.1.0.0")) - 1)) & ~bytes32(uint256(0xff));
        assertEq(signerAccount.CUSTOM_STORAGE_ROOT(), customStorageRoot);
    }

    function test_nonceSequenceNumber_nested_key() public {
        uint192 nonceKey = 1;

        vm.record();
        signerAccount.getSeq(nonceKey);
        (bytes32[] memory readSlots, bytes32[] memory writeSlots) = vm.accesses(address(signerAccount));
        assertEq(readSlots.length, 1);
        assertEq(writeSlots.length, 0);

        bytes32 mappingRootSlot = _addOffset(signerAccount.CUSTOM_STORAGE_ROOT(), NONCE_SEQUENCE_NUMBER_SLOT);
        bytes32 nestedSlot = _calculateNestedMappingSlot(nonceKey, mappingRootSlot);
        assertEq(readSlots[0], nestedSlot);
    }

    function test_entrypoint() public {
        vm.record();
        signerAccount.ENTRY_POINT();
        (bytes32[] memory readSlots, bytes32[] memory writeSlots) = vm.accesses(address(signerAccount));
        assertEq(readSlots.length, 1);
        assertEq(writeSlots.length, 0);
        assertEq(readSlots[0], _addOffset(signerAccount.CUSTOM_STORAGE_ROOT(), ENTRY_POINT_SLOT));
    }
}
