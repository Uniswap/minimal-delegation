# TransientNativeAllowance
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/8189d62a80ed3ac2bd308849641dca52350f024a/src/libraries/TransientNativeAllowance.sol)

This is a temporary library that allows us to use transient storage (tstore/tload)
TODO: This library can be deleted when we have the transient keyword support in solidity.

*The custom storage layout keyword does not work for transient storage.
However, since transient storage is automatically cleared between transactions and does not persist, custom storage is not needed.*


## Functions
### _computeSlot

calculates which storage slot a transient native allowance should be stored in for a given spender


```solidity
function _computeSlot(address spender) internal pure returns (bytes32 hashSlot);
```

### get

Returns the transient allowance for a given spender


```solidity
function get(address spender) internal view returns (uint256 allowance);
```

### set

Sets the transient allowance for a given spender


```solidity
function set(address spender, uint256 allowance) internal;
```

