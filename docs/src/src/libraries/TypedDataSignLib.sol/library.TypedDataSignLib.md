# TypedDataSignLib
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/8189d62a80ed3ac2bd308849641dca52350f024a/src/libraries/TypedDataSignLib.sol)

Library supporting nesting of EIP-712 typed data signatures
Follows ERC-7739 spec


## Functions
### _toTypedDataSignTypeString

contentsName and contentsType MUST be checked for length before hashing

*Generate the dynamic type string for the TypedDataSign struct*


```solidity
function _toTypedDataSignTypeString(string memory contentsName, string memory contentsType)
    internal
    pure
    returns (bytes memory);
```

### _toTypedDataSignTypeHash

contentsName and contentsType MUST be checked for length before hashing

*Create the type hash for a TypedDataSign struct*


```solidity
function _toTypedDataSignTypeHash(string memory contentsName, string memory contentsType)
    internal
    pure
    returns (bytes32);
```

### hash

EIP-712 hashStruct implementation for TypedDataSign

*domainBytes is abi.encode(keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract, salt)*


```solidity
function hash(string memory contentsName, string memory contentsType, bytes32 contentsHash, bytes memory domainBytes)
    internal
    pure
    returns (bytes32);
```

