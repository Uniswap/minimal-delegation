# ERC7914
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/8189d62a80ed3ac2bd308849641dca52350f024a/src/ERC7914.sol)

**Inherits:**
[IERC7914](/src/interfaces/IERC7914.sol/interface.IERC7914.md), [BaseAuthorization](/src/BaseAuthorization.sol/contract.BaseAuthorization.md)

Abstract ERC-7914 implementation with support for transient allowances

*this ERC is not finalized and is subject to change in the future
https://github.com/ethereum/ERCs/blob/8380220418521ff1995445cff5ca1d0e496a3d2d/ERCS/erc-7914.md*


## State Variables
### nativeAllowance

```solidity
mapping(address spender => uint256 allowance) public nativeAllowance;
```


## Functions
### approveNative

Approves a spender to transfer native tokens on behalf of the caller


```solidity
function approveNative(address spender, uint256 amount) external onlyThis returns (bool);
```

### approveNativeTransient

Approves a spender to transfer native tokens on behalf of the caller with transient storage


```solidity
function approveNativeTransient(address spender, uint256 amount) external onlyThis returns (bool);
```

### transferFromNative

Transfers native tokens from the caller to a recipient

*Doesn't forward transferFrom requests - the specified `from` address must be address(this)*


```solidity
function transferFromNative(address from, address recipient, uint256 amount) external returns (bool);
```

### transferFromNativeTransient

Transfers native tokens from the caller to a recipient with transient storage

*Doesn't forward transferFrom requests - the specified `from` address must be address(this)*


```solidity
function transferFromNativeTransient(address from, address recipient, uint256 amount) external returns (bool);
```

### transientNativeAllowance

Returns the transient allowance of a spender


```solidity
function transientNativeAllowance(address spender) public view returns (uint256);
```

### _transferFrom

*Internal function to validate and execute transfers*


```solidity
function _transferFrom(address from, address recipient, uint256 amount, bool isTransient) internal;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`from`|`address`|The address to transfer from|
|`recipient`|`address`|The address to receive the funds|
|`amount`|`uint256`|The amount to transfer|
|`isTransient`|`bool`|Whether this is transient allowance or not|


