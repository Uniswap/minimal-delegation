import {type Address} from "viem"


// Define the domain name and version. Note chainId and verifyingContract are not constants.
export const DOMAIN_NAME = 'Uniswap Minimal Delegation';
export const DOMAIN_VERSION = "1";

// Define the struct types
export const types = {
  SignedBatchedCall: [
    { name: 'batchedCall', type: 'BatchedCall' },
    { name: 'nonce', type: 'uint256' },
    { name: 'keyHash', type: 'bytes32' }
  ],
  BatchedCall: [
    { name: 'calls', type: 'Call[]' },
    { name: 'shouldRevert', type: 'bool' }
  ],
  Call: [
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'data', type: 'bytes' }
  ]
} as const;

  // Type definitions
export type Call = {
    to: Address;
    value: number;
    data: string;
  }

export type BatchedCall = {
    calls: Call[];
    shouldRevert: boolean;
  }

export type SignedBatchedCall = {
    batchedCall: BatchedCall;
    nonce: number;
    keyHash: string;
  }