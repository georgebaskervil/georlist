// Type overrides for compatibility between Node.js and Bun

import { Response as NodeFetchResponse } from 'node-fetch';

// Declare compatible Response type
declare global {
  // Use node-fetch's Response type
  type Response = NodeFetchResponse;
}

export {}; 