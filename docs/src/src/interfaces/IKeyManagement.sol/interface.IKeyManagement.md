# IKeyManagement
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/8189d62a80ed3ac2bd308849641dca52350f024a/src/interfaces/IKeyManagement.sol)


## Functions
### register

*Registers the `key`.*


```solidity
function register(Key memory key) external;
```

### revoke

*Revokes the key with the `keyHash`.*


```solidity
function revoke(bytes32 keyHash) external;
```

### update

*Updates the `keyHash` with the `keySettings`.*


```solidity
function update(bytes32 keyHash, Settings keySettings) external;
```

### keyCount

*Returns the number of registered keys.*


```solidity
function keyCount() external view returns (uint256);
```

### keyAt

*Returns the key at the `i`-th position in the key list.*


```solidity
function keyAt(uint256 i) external view returns (Key memory);
```

### getKey

*Returns the key corresponding to the `keyHash`. Reverts if the key does not exist.*


```solidity
function getKey(bytes32 keyHash) external view returns (Key memory key);
```

### getKeySettings

*Returns the settings for the `keyHash`.*


```solidity
function getKeySettings(bytes32 keyHash) external view returns (Settings);
```

### isRegistered

*Returns whether the key is actively registered on the contract.*


```solidity
function isRegistered(bytes32 keyHash) external view returns (bool);
```

## Events
### Registered
*Emitted when a key is registered.*


```solidity
event Registered(bytes32 indexed keyHash, Key key);
```

### Revoked
*Emitted when a key is revoked.*


```solidity
event Revoked(bytes32 indexed keyHash);
```

### KeySettingsUpdated
*Emitted when a key's settings are updated.*


```solidity
event KeySettingsUpdated(bytes32 indexed keyHash, Settings settings);
```

## Errors
### KeyDoesNotExist
*The key does not exist.*


```solidity
error KeyDoesNotExist();
```

### KeyExpired
*The key has expired.*


```solidity
error KeyExpired(uint40 expiration);
```

### CannotUpdateRootKey
*Cannot apply restrictions to the root key.*


```solidity
error CannotUpdateRootKey();
```

### CannotRegisterRootKey
*Cannot register the root key.*


```solidity
error CannotRegisterRootKey();
```

### OnlyAdminCanSelfCall
*Only admin keys can self-call.*


```solidity
error OnlyAdminCanSelfCall();
```

