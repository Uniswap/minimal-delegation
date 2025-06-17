# IExecutionHook
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/8189d62a80ed3ac2bd308849641dca52350f024a/src/interfaces/IExecutionHook.sol)

Hooks that are executed before and after a Call is executed


## Functions
### beforeExecute

*Must revert if the entire call should revert.*


```solidity
function beforeExecute(bytes32 keyHash, address to, uint256 value, bytes calldata data)
    external
    returns (bytes4, bytes memory);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`keyHash`|`bytes32`|The key hash to check against|
|`to`|`address`|The address to call|
|`value`|`uint256`|value of the call|
|`data`|`bytes`||

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bytes4`|Context to pass to afterExecute hook, if present. An empty bytes array MAY be returned.|
|`<none>`|`bytes`||


### afterExecute

*Must revert if the entire call should revert.*


```solidity
function afterExecute(bytes32 keyHash, bool success, bytes calldata output, bytes calldata beforeExecuteData)
    external
    returns (bytes4);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`keyHash`|`bytes32`|The key hash to check against|
|`success`|`bool`|Whether the call succeeded|
|`output`|`bytes`|The output of the call|
|`beforeExecuteData`|`bytes`|The context returned by the beforeExecute hook.|


