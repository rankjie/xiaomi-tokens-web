import { sanitize } from './sanitize';

// Debug logging utility that works in both Node.js and Cloudflare Workers
const isDebugEnabled = (): boolean => {
  // Check for Node.js environment
  if (typeof process !== 'undefined' && process.env) {
    return process.env.DEBUG === 'true' || process.env.DEBUG === '1';
  }
  
  // For Cloudflare Workers, you would need to use wrangler.toml to set vars
  // or use a global DEBUG variable
  if (typeof globalThis !== 'undefined' && (globalThis as any).DEBUG) {
    return (globalThis as any).DEBUG === 'true' || (globalThis as any).DEBUG === '1';
  }
  
  return false;
};

// Sanitize arguments before logging
const sanitizeArgs = (args: any[]): any[] => {
  return args.map(arg => {
    // Skip sanitizing strings that are likely labels/messages
    if (typeof arg === 'string' && !arg.includes(':') && arg.length < 100) {
      return arg;
    }
    return sanitize(arg);
  });
};

export const debug = {
  log: (...args: any[]) => {
    if (isDebugEnabled()) {
      console.log(...sanitizeArgs(args));
    }
  },
  error: (...args: any[]) => {
    if (isDebugEnabled()) {
      console.error(...sanitizeArgs(args));
    }
  },
  warn: (...args: any[]) => {
    if (isDebugEnabled()) {
      console.warn(...sanitizeArgs(args));
    }
  }
};