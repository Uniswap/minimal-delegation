# SettingsLib
[Git Source](https://github.com/Uniswap/minimal-delegation/blob/8189d62a80ed3ac2bd308849641dca52350f024a/src/libraries/SettingsLib.sol)

Key settings are packed into a uint256 where
- the least significant 20 bytes (0-19) specify an address to callout to for extra or overrideable validation.
- bytes 20-24 are used for the expiration timestamp.
- byte 25 is used to specify if the key is an admin key or not.
- the remaining bytes are reserved for future use.
6 bytes |   1 byte       | 5 bytes           | 20 bytes
UNUSED  |   isAdmin      | expiration        | hook


## State Variables
### MASK_20_BYTES

```solidity
uint160 constant MASK_20_BYTES = uint160(0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF);
```


### MASK_5_BYTES

```solidity
uint40 constant MASK_5_BYTES = uint40(0xFFFFFFFFFF);
```


### MASK_1_BYTE

```solidity
uint8 constant MASK_1_BYTE = uint8(0xFF);
```


### DEFAULT

```solidity
Settings constant DEFAULT = Settings.wrap(0);
```


### ROOT_KEY_SETTINGS

```solidity
Settings constant ROOT_KEY_SETTINGS = Settings.wrap(uint256(1) << 200);
```


## Functions
### isAdmin

Returns whether the key is an admin key


```solidity
function isAdmin(Settings settings) internal pure returns (bool _isAdmin);
```

### expiration

Returns the expiration timestamp in unix time


```solidity
function expiration(Settings settings) internal pure returns (uint40 _expiration);
```

### hook

Returns the hook address of the key


```solidity
function hook(Settings settings) internal pure returns (IHook _hook);
```

### isExpired

A key is expired if its expiration is less than the current block timestamp
Strictly less than is inline with how expiry is handled in the ERC-4337 EntryPoint contract

*Keys with expiry of 0 never expire.*


```solidity
function isExpired(Settings settings) internal view returns (bool _isExpired, uint40 _expiration);
```

