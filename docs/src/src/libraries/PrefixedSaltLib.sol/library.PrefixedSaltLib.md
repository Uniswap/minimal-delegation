# PrefixedSaltLib
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/1457ed9d5e0382ab8547f6bc36a3738475e8b5fe/src/libraries/PrefixedSaltLib.sol)

A library for packing and updating the salt with a prefix for EIP-712 domain separators


## Functions
### pack

Pack the prefix and implementation address into a bytes32


```solidity
function pack(uint96 prefix, address implementation) internal pure returns (bytes32);
```

