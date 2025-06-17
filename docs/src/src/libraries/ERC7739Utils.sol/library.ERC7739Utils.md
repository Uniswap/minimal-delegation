# ERC7739Utils
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/8189d62a80ed3ac2bd308849641dca52350f024a/src/libraries/ERC7739Utils.sol)

**Author:**
Extends the original implementation at
https://github.com/OpenZeppelin/openzeppelin-community-contracts/blob/53f590e4f4902bee0e06e455332e3321c697ea8b/contracts/utils/cryptography/ERC7739Utils.sol


## Functions
### toPersonalSignTypedDataHash

Hash a PersonalSign struct with the app's domain separator to produce an EIP-712 compatible hash

*Uses this account's domain separator in the EIP-712 hash for replay protection*


```solidity
function toPersonalSignTypedDataHash(bytes32 hash, bytes32 domainSeparator) internal pure returns (bytes32);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`hash`|`bytes32`|The hashed message, calculated offchain|
|`domainSeparator`|`bytes32`|This account's domain separator|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bytes32`|The PersonalSign nested EIP-712 hash of the message|


### toNestedTypedDataSignHash

Hash TypedDataSign with the app's domain separator to produce an EIP-712 compatible hash

*Includes this account's domain in the hash for replay protection*


```solidity
function toNestedTypedDataSignHash(
    bytes32 contentsHash,
    bytes memory domainBytes,
    bytes32 appSeparator,
    string calldata contentsName,
    string calldata contentsType
) internal pure returns (bytes32);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`contentsHash`|`bytes32`|The hash of the contents, per EIP-712|
|`domainBytes`|`bytes`|The encoded domain bytes from EIP-5267|
|`appSeparator`|`bytes32`|The app's domain separator|
|`contentsName`|`string`|The type name of the contents|
|`contentsType`|`string`|The type description of the contents|


### decodeContentsDescr

Parse the type name out of the ERC-7739 contents type description. Supports both the implicit and explicit modes

*Returns empty strings if the contentsDescr is invalid, which must be handled by the calling function*


```solidity
function decodeContentsDescr(string calldata contentsDescr)
    internal
    pure
    returns (string calldata contentsName, string calldata contentsType);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`contentsName`|`string`|The type name of the contents|
|`contentsType`|`string`|The type description of the contents|


### _isForbiddenChar

Perform onchain sanitization of contentsName as defined by the ERC-7739 spec

*Following ERC-7739 specifications, a `contentsName` is considered invalid if it's empty or it contains
any of the following bytes: ", )\x00"*


```solidity
function _isForbiddenChar(bytes1 char) private pure returns (bool);
```

