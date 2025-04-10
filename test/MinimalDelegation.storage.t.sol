// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {DelegationHandler} from "./utils/DelegationHandler.sol";

contract MinimalDelegationStorageTest is DelegationHandler {
    /**
     * MinimalDelegation storage layout
     * slots are assigned starting from the custom layout slot and in order of declaration, from left to right
     *
     * MinimalDelegation is IERC7821, ERC1271, EIP712, ERC4337Account, Receiver, KeyManagement, NonceManager, ERC7914, ERC7201 layout at 0xc807f46cbe2302f9a007e47db23c8af6a94680c1d26280fb9582873dbe5c9200
     *
     * 0: uint256 _CACHED_ENTRYPOINT
     * 1: mapping(bytes32 keyHash => KeyExtraStorage) keyExtraStorage;
     * 2: mapping(bytes32 keyHash => bytes encodedKey) keyStorage;
     * 3: EnumerableSetLib.Bytes32Set keyHashes;
     * 4: mapping(uint256 key => uint256 seq) nonceSequenceNumber
     * 5: mapping(address => uint256) allowance;
     */
    uint256 private constant ENTRY_POINT_SLOT = 0;
    uint256 private constant KEY_EXTRA_STORAGE_SLOT = 1;
    uint256 private constant KEY_STORAGE_SLOT = 2;
    uint256 private constant KEY_HASHES_SLOT = 3;
    uint256 private constant NONCE_SEQUENCE_NUMBER_SLOT = 4;
    uint256 private constant ALLOWANCE_SLOT = 5;

    function setUp() public {
        setUpDelegation();
    }

    function _addOffset(bytes32 slot, uint256 offset) internal pure returns (bytes32) {
        return bytes32(uint256(slot) + offset);
    }

    function _calculateNestedMappingSlot(uint256 key, bytes32 rootSlot) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, uint256(rootSlot)));
    }

    function _calculateNestedMappingSlotAddress(address addr, bytes32 rootSlot) internal pure returns (bytes32) {
        return keccak256(abi.encode(addr, uint256(rootSlot)));
    }

    /// @dev Sanity check tests for changes in namespace and version
    function test_erc7201_namespaceAndVersion() public view {
        assertEq(signerAccount.namespaceAndVersion(), "Uniswap.MinimalDelegation.1.0.0");
    }

    /// @dev Sanity check tests for changes in the calculated custom storage root
    function test_erc7201_customStorageRoot() public view {
        bytes32 customStorageRoot =
            keccak256(abi.encode(uint256(keccak256("Uniswap.MinimalDelegation.1.0.0")) - 1)) & ~bytes32(uint256(0xff));
        assertEq(signerAccount.CUSTOM_STORAGE_ROOT(), customStorageRoot);
    }

    function test_nonceSequenceNumber_nested_key() public {
        uint256 nonceKey = 1;

        vm.record();
        signerAccount.getSeq(nonceKey);
        (bytes32[] memory readSlots, bytes32[] memory writeSlots) = vm.accesses(address(signerAccount));
        assertEq(readSlots.length, 1);
        assertEq(writeSlots.length, 0);

        bytes32 mappingRootSlot = _addOffset(signerAccount.CUSTOM_STORAGE_ROOT(), NONCE_SEQUENCE_NUMBER_SLOT);
        bytes32 nestedSlot = _calculateNestedMappingSlot(nonceKey, mappingRootSlot);
        assertEq(readSlots[0], nestedSlot);
    }

    function test_allowance() public {
        vm.record();
        signerAccount.allowance(address(0));
        (bytes32[] memory readSlots, bytes32[] memory writeSlots) = vm.accesses(address(signerAccount));
        assertEq(readSlots.length, 1);
        assertEq(writeSlots.length, 0);

        bytes32 mappingRootSlot = _addOffset(signerAccount.CUSTOM_STORAGE_ROOT(), ALLOWANCE_SLOT);
        bytes32 nestedSlot = _calculateNestedMappingSlotAddress(address(0), mappingRootSlot);
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
