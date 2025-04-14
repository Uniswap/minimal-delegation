# Minimal Delegation

a minimal, non-upgradeable implementation contract that can be set on an EIP-7702 delegation txn

## Installation
```bash
foundryup --install nightly

cd test/js-scripts && yarn && yarn build

forge test
```

## Features

- **ERC-4337**: Gas sponsorship and userOp handling through a 4337 interface.
- **ERC-7821**: Generic transaction batching through an ERC-7821 interface.
- **ERC-7201**: Name spaced storage to prevent collisions.
- **Key Management + Authorization** Adding & revoking keys that have access to perform operations as specified by the account owner.
- **Multicall**: Execute multiple contract calls in a single transaction.

## Call Data Structures

The contract uses a nested structure approach for managing batched calls:

- **Call**: Basic structure with `to`, `value`, and `data` for a single contract call
- **BatchedCall**: Contains an array of `Call` structures and a `shouldRevert` flag to control error handling
- **SignedBatchedCall**: Adds authentication and nonce management with `batchedCall`, `nonce`, and `keyHash` fields

This nested structure provides better separation of concerns and more flexible signature verification.

## Migration Guide

If you're upgrading from a previous version of MinimalDelegation, note these breaking changes:

1. **Function Signatures**: 
   - `execute(Call[] calls, bool shouldRevert)` → `execute(BatchedCall memory batchedCall)`
   - `execute(SignedCalls signedCalls, bytes signature)` → `execute(SignedBatchedCall memory signedBatchedCall, bytes wrappedSignature)`

2. **Typed Data Hashing**:
   - Typehashes for EIP-712 signatures have changed due to the nested structure
   - Signatures created for the old structures will not work with the new implementation

3. **Hook Data**:
   - Hook processing has changed from `verifySignature` to `handleAfterVerifySignature`
   - Hook permissions now follow an AFTER_* pattern for most operations

4. **Data Organization**:
   - Access to calls is now through nested fields: `signedBatchedCall.batchedCall.calls`
   - The `shouldRevert` flag has moved to the `BatchedCall` structure

Client applications will need to update their transaction construction and signature generation to align with these changes.


## Architecture
- **Non-Upgradeability**: Upgradability is only allowed through re-delegation rather than a proxy.
- **Singleton:** One canonical contract is delegated to.
- **Hook System:** Extensible hook system for customizing account behavior

## Hook Permissions

The contract uses a permission-based hook system that allows for extending functionality at different execution points:

- **BEFORE_EXECUTE_FLAG**: Called before executing a transaction
- **AFTER_EXECUTE_FLAG**: Called after executing a transaction
- **AFTER_VERIFY_SIGNATURE_FLAG**: Called after verifying a signature
- **AFTER_VALIDATE_USER_OP_FLAG**: Called after validating a UserOperation
- **AFTER_IS_VALID_SIGNATURE_FLAG**: Called after validating an ERC1271 signature

Each hook is associated with a key and only called when the key has the appropriate permissions.

## Inheritance Diagram

```mermaid
classDiagram
    MinimalDelegation --|> ERC7821
    MinimalDelegation --|> ERC1271
    MinimalDelegation --|> EIP712
    MinimalDelegation --|> ERC4337Account
    MinimalDelegation --|> Receiver
    MinimalDelegation --|> KeyManagement
    MinimalDelegation --|> NonceManager
    MinimalDelegation --|> ERC7914
    MinimalDelegation --|> ERC7201
    MinimalDelegation --|> Multicall
    
    EIP712 --|> IERC5267
    ERC4337Account --|> IAccount
    
    class MinimalDelegation {
        +execute(BatchedCall batchedCall)
        +execute(SignedBatchedCall signedBatchedCall, bytes wrappedSignature)
        +execute(bytes32 mode, bytes executionData)
        +executeUserOp(PackedUserOperation userOp, bytes32)
        +updateEntryPoint(address entryPoint)
        +validateUserOp(PackedUserOperation userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        +multicall(bytes[] data)
    }
```

## Sequence Diagrams

### Direct execute() Flow

```mermaid
sequenceDiagram
    participant SignerAccount as EOA (delegated to MinimalDelegation)
    participant Account as MinimalDelegation
    participant Target
    
    Note over SignerAccount, Account: EOA is delegated to MinimalDelegation via EIP-7702
    SignerAccount->>Account: execute(BatchedCall batchedCall)
    Account->>Account: Check msg.sender.toKeyHash() is owner or admin
    Account->>Account: _dispatch(batchedCall, keyHash)
    loop For each call in batchedCall.calls
        Account->>Account: _execute(call, keyHash)
        Account->>Account: getKeySettings(keyHash)
        Account->>Account: Check if admin for self-calls
        
        opt If hook has BEFORE_EXECUTE permission
            Account->>Hook: handleBeforeExecute(keyHash, to, value, data)
            Hook-->>Account: beforeExecuteData
        end
        
        Account->>+Target: to.call{value}(data)
        Target-->>-Account: (success, output)
        
        opt If hook has AFTER_EXECUTE permission
            Account->>Hook: handleAfterExecute(keyHash, beforeExecuteData)
        end
        
        opt If !success && batchedCall.shouldRevert
            Account->>Account: revert CallFailed(output)
        end
    end
```

### Signature-based execute() Flow

```mermaid
sequenceDiagram
    actor Signer
    participant Relayer
    participant Account as MinimalDelegation
    participant Hook
    participant Target
    
    Signer->>Signer: Create SignedBatchedCall structure
    Signer->>Signer: Sign the hash with private key
    Signer->>Relayer: Send signed transaction data
    Relayer->>+Account: execute(SignedBatchedCall, wrappedSignature)
    Account->>Account: _handleVerifySignature(signedBatchedCall, wrappedSignature)
    Account->>Account: _useNonce(signedBatchedCall.nonce)
    Account->>Account: Decode wrappedSignature to (signature, hookData)
    Account->>Account: getKey(signedBatchedCall.keyHash)
    Account->>Account: _hashTypedData(signedBatchedCall.hash())
    Account->>Account: key.verify(digest, signature)
    
    opt If !isValid
        Account-->>Relayer: revert InvalidSignature()
    end
    
    Account->>Account: getKeySettings(signedBatchedCall.keyHash)
    Account->>Account: _checkExpiry(settings)
    
    opt If hook has AFTER_VERIFY_SIGNATURE permission
        Account->>Hook: handleAfterVerifySignature(keyHash, digest, hookData)
    end
    
    Account->>Account: _dispatch(signedBatchedCall.batchedCall, signedBatchedCall.keyHash)
    
    loop For each call in signedBatchedCall.batchedCall.calls
        Account->>Account: _execute(call, keyHash)
        Account->>Account: getKeySettings(keyHash)
        Account->>Account: Check if admin for self-calls
        
        opt If hook has BEFORE_EXECUTE permission
            Account->>Hook: handleBeforeExecute(keyHash, to, value, data)
            Hook-->>Account: beforeExecuteData
        end
        
        Account->>+Target: to.call{value}(data)
        Target-->>-Account: (success, output)
        
        opt If hook has AFTER_EXECUTE permission
            Account->>Hook: handleAfterExecute(keyHash, beforeExecuteData)
        end
        
        opt If !success && signedBatchedCall.batchedCall.shouldRevert
            Account-->>Relayer: revert CallFailed(output)
        end
    end
    
    Account-->>-Relayer: Success
```

### ERC7821 execute() Flow

```mermaid
sequenceDiagram
    participant SignerAccount as EOA (delegated to MinimalDelegation)
    participant Account as MinimalDelegation
    participant Target
    participant Hook
    
    Note over SignerAccount, Account: EOA is delegated to MinimalDelegation via EIP-7702
    SignerAccount->>Account: execute(bytes32 mode, bytes executionData)
    Account->>Account: mode.isBatchedCall()
    opt If !mode.isBatchedCall()
        Account-->>SignerAccount: revert UnsupportedExecutionMode()
    end
    
    Account->>Account: abi.decode(executionData) to Call[]
    Account->>Account: Create BatchedCall struct with calls and mode.shouldRevert()
    Account->>Account: execute(batchedCall)
    Account->>Account: Check msg.sender.toKeyHash() is owner or admin
    Account->>Account: _dispatch(batchedCall, keyHash)
    
    loop For each call in batchedCall.calls
        Account->>Account: _execute(call, keyHash)
        Account->>Account: getKeySettings(keyHash)
        Account->>Account: Check if admin for self-calls
        
        opt If hook has BEFORE_EXECUTE permission
            Account->>Hook: handleBeforeExecute(keyHash, to, value, data)
            Hook-->>Account: beforeExecuteData
        end
        
        Account->>+Target: to.call{value}(data)
        Target-->>-Account: (success, output)
        
        opt If hook has AFTER_EXECUTE permission
            Account->>Hook: handleAfterExecute(keyHash, beforeExecuteData)
        end
        
        opt If !success && batchedCall.shouldRevert
            Account-->>SignerAccount: revert CallFailed(output)
        end
    end
    
    Account-->>SignerAccount: Success
```

### ERC4337 UserOp Flow

```mermaid
sequenceDiagram
    actor Signer
    participant Bundler
    participant EntryPoint
    participant Account as MinimalDelegation
    participant Hook
    participant Target
    
    Signer->>Signer: Create UserOperation
    Signer->>Signer: Sign userOpHash
    Signer->>Bundler: Submit UserOperation
    
    Bundler->>+EntryPoint: handleOps([userOp], beneficiary)
    EntryPoint->>+Account: validateUserOp(userOp, userOpHash, missingAccountFunds)
    
    Account->>Account: _payEntryPoint(missingAccountFunds)
    Account->>Account: Decode signature to (keyHash, signature, hookData)
    Account->>Account: getKey(keyHash)
    Account->>Account: key.verify(userOpHash, signature)
    
    opt If !isValid
        Account-->>EntryPoint: Return SIG_VALIDATION_FAILED
    end
    
    Account->>Account: getKeySettings(keyHash)
    Account->>Account: _checkExpiry(settings)
    Account->>Account: Calculate validationData with expiration
    
    opt If hook has AFTER_VALIDATE_USER_OP permission
        Account->>Hook: handleAfterValidateUserOp(keyHash, userOp, userOpHash, hookData)
        Hook-->>Account: validationData (can override)
    end
    
    Account-->>-EntryPoint: validationData
    
    EntryPoint->>+Account: executeUserOp(userOp, userOpHash)
    Account->>Account: Decode signature to extract keyHash
    Account->>Account: Decode callData to BatchedCall
    Account->>Account: _dispatch(batchedCall, keyHash)
    
    loop For each call in batchedCall.calls
        Account->>Account: _execute(call, keyHash)
        Account->>Account: getKeySettings(keyHash)
        Account->>Account: Check if admin for self-calls
        
        opt If hook has BEFORE_EXECUTE permission
            Account->>Hook: handleBeforeExecute(keyHash, to, value, data)
            Hook-->>Account: beforeExecuteData
        end
        
        Account->>+Target: to.call{value}(data)
        Target-->>-Account: (success, output)
        
        opt If hook has AFTER_EXECUTE permission
            Account->>Hook: handleAfterExecute(keyHash, beforeExecuteData)
        end
        
        opt If !success && batchedCall.shouldRevert
            Account-->>EntryPoint: revert CallFailed(output)
        end
    end
    
    Account-->>-EntryPoint: Success
    EntryPoint-->>-Bundler: Success
```

### ERC1271 isValidSignature Flow

```mermaid
sequenceDiagram
    participant VerifyingContract
    participant Account as MinimalDelegation
    participant Hook
    
    VerifyingContract->>+Account: isValidSignature(bytes32 data, bytes wrappedSignature)
    
    Account->>Account: Decode wrappedSignature to (keyHash, signature, hookData)
    Account->>Account: Create digest from data.hashWithWrappedType()
    Account->>Account: getKey(keyHash)
    Account->>Account: key.verify(digest, signature)
    
    opt If !isValid
        Account-->>VerifyingContract: Return _1271_INVALID_VALUE (0xffffffff)
    end
    
    Account->>Account: getKeySettings(keyHash)
    Account->>Account: _checkExpiry(settings)
    Account->>Account: result = _1271_MAGIC_VALUE (0x1626ba7e)
    
    opt If hook has AFTER_IS_VALID_SIGNATURE permission
        Account->>Hook: handleAfterIsValidSignature(keyHash, digest, hookData)
        Hook-->>Account: result (can override)
    end
    
    Account-->>-VerifyingContract: result (0x1626ba7e if valid, otherwise 0xffffffff)
```