# EntrypointLib
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/8189d62a80ed3ac2bd308849641dca52350f024a/src/libraries/EntrypointLib.sol)

*This library is used to dirty the most significant bit of the cached entrypoint
to indicate that the entrypoint has been overriden by the account*


## State Variables
### ENTRY_POINT_OVERRIDDEN

```solidity
uint256 internal constant ENTRY_POINT_OVERRIDDEN = 1 << 255;
```


## Functions
### pack

Packs the entry point into a uint256.


```solidity
function pack(address entrypoint) internal pure returns (uint256);
```

### unpack

Unpacks the entry point address from a uint256.


```solidity
function unpack(uint256 packedEntrypoint) internal pure returns (address);
```

### isOverriden

Checks if the entry point has been overriden by the user.


```solidity
function isOverriden(uint256 packedEntrypoint) internal pure returns (bool);
```

