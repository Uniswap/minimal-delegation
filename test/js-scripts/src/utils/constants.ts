import {type Address} from "viem"


// Define the domain name and version. Note chainId and verifyingContract are not constants.
export const DOMAIN_NAME = 'Calibur';
export const DOMAIN_VERSION = "1";
export const DEFAULT_DOMAIN_SALT = "0x0000000000000000000000000000000000000000000000000000000000000000";

export interface InputData {
  privateKey: string;
  verifyingContract: Address;
}

// Define the struct types
export const types = {
  SignedBatchedCall: [
    { name: 'batchedCall', type: 'BatchedCall' },
    { name: 'nonce', type: 'uint256' },
    { name: 'keyHash', type: 'bytes32' },
    { name: 'executor', type: 'address' },
    { name: 'deadline', type: 'uint256' }
  ],
  BatchedCall: [
    { name: 'calls', type: 'Call[]' },
    { name: 'revertOnFailure', type: 'bool' }
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
    revertOnFailure: boolean;
  }

export interface SignedBatchedCall {
  batchedCall: BatchedCall;
  nonce: bigint;
  keyHash: string;
  executor: string;
  deadline: bigint;
}