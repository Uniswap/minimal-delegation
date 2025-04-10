import {type Address} from "viem"


// Define the domain name and version. Note chainId and verifyingContract are not constants.
export const DOMAIN_NAME = 'Uniswap Minimal Delegation';
export const DOMAIN_VERSION = "1";

// Define the struct types
export const types = {
  SignedCalls: [
    { name: 'calls', type: 'Call[]' },
    { name: 'nonce', type: 'uint256' },
    { name: 'keyHash', type: 'bytes32' },
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

export type SignedCalls = {
    calls: Call[];
    nonce: number;
    keyHash: string;
    shouldRevert: boolean;
  }