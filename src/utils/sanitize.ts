// Utility to sanitize sensitive information from logs
export function sanitize(value: any): any {
  if (typeof value === 'string') {
    // Hide tokens, keys, and passwords
    if (value.length > 20) {
      return value.substring(0, 4) + '...' + value.substring(value.length - 4);
    }
    return value;
  }
  
  if (Array.isArray(value)) {
    return value.map(item => sanitize(item));
  }
  
  if (value && typeof value === 'object') {
    const sanitized: any = {};
    for (const key in value) {
      const lowerKey = key.toLowerCase();
      
      // Hide sensitive fields
      if (lowerKey.includes('password') || 
          lowerKey.includes('token') || 
          lowerKey.includes('key') ||
          lowerKey.includes('secret') ||
          lowerKey.includes('ssecurity') ||
          lowerKey.includes('cookie') ||
          lowerKey.includes('auth') ||
          lowerKey.includes('sign') ||
          lowerKey.includes('nonce')) {
        
        const val = value[key];
        if (typeof val === 'string' && val.length > 0) {
          sanitized[key] = val.length > 8 ? val.substring(0, 4) + '...' + val.substring(val.length - 4) : '[hidden]';
        } else if (val && typeof val === 'object') {
          sanitized[key] = '[object hidden]';
        } else if (val) {
          sanitized[key] = '[hidden]';
        } else {
          sanitized[key] = val;
        }
      } else {
        sanitized[key] = sanitize(value[key]);
      }
    }
    return sanitized;
  }
  
  return value;
}

// Helper to check if a value exists without revealing it
export function exists(value: any): string {
  if (!value) return 'missing';
  if (typeof value === 'string' && value.length > 0) return 'present';
  if (typeof value === 'object' && Object.keys(value).length > 0) return 'present';
  return 'empty';
}