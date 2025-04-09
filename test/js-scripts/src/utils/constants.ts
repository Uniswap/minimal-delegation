import {type Address} from "viem"


// Define the domain name and version. Note chainId and verifyingContract are not constants.
export const DOMAIN_NAME = 'Uniswap Minimal Delegation';
export const DOMAIN_VERSION = "1";

// Define the struct types
export const types = {
    Call: [
      { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'data', type: 'bytes' }
    ],
    SignedCalls: [
      { name: 'calls', type: 'Call[]' },
      { name: 'nonce', type: 'uint256' },
      { name: 'shouldRevert', type: 'bool' },
      { name: 'keyHash', type: 'bytes32' }
    ]
    } as const;

  // Type definitions
export type Call = {
    to: Address;
    value: number;
    data: string;
  }