// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {Key, KeyLib, KeyType} from "../../src/libraries/KeyLib.sol";
import {MinimalDelegation} from "../../src/MinimalDelegation.sol";
import {IMinimalDelegation} from "../../src/interfaces/IMinimalDelegation.sol";

contract DelegationHandler is Test {
    using KeyLib for Key;

    MinimalDelegation public minimalDelegation;
    uint256 signerPrivateKey = 0xa11ce;
    address signer = vm.addr(signerPrivateKey);
    IMinimalDelegation public signerAccount;
    uint256 DEFAULT_KEY_EXPIRY = 10 days;

    address mockSecp256k1PublicKey = makeAddr("mockSecp256k1PublicKey");
    Key public mockSecp256k1Key = Key(0, KeyType.Secp256k1, true, abi.encodePacked(mockSecp256k1PublicKey));

    address mockSecp256k1PublicKey2 = makeAddr("mockSecp256k1PublicKey2");
    // May need to remove block.timestamp in the future if using vm.roll / warp
    Key public mockSecp256k1Key2 =
        Key(uint40(block.timestamp + 3600), KeyType.Secp256k1, false, abi.encodePacked(mockSecp256k1PublicKey2));

    function setUpDelegation() public {
        minimalDelegation = new MinimalDelegation();
        _delegate(signer, address(minimalDelegation));
        signerAccount = IMinimalDelegation(signer);
    }

    function _delegate(address _signer, address _implementation) internal {
        vm.etch(_signer, bytes.concat(hex"ef0100", abi.encodePacked(_implementation)));
        require(_signer.code.length > 0, "signer not delegated");
    }
}
