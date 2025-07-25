# CallLib
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/8189d62a80ed3ac2bd308849641dca52350f024a/src/libraries/CallLib.sol)

A library for hashing and encoding calls


## State Variables
### CALL_TYPE
*The type string for the Call struct*


```solidity
bytes internal constant CALL_TYPE = "Call(address to,uint256 value,bytes data)";
```


### CALL_TYPEHASH
*The typehash for the Call struct*


```solidity
bytes32 internal constant CALL_TYPEHASH = keccak256(CALL_TYPE);
```


## Functions
### hash

Hash a single struct according to EIP-712.


```solidity
function hash(Call memory call) internal pure returns (bytes32);
```

### hash

Hash an array of structs according to EIP-712.


```solidity
function hash(Call[] memory calls) internal pure returns (bytes32);
```

