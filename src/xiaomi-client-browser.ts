import { SessionData, Device } from './types';

// RC4 implementation for browser
class RC4 {
  private s: number[];
  private i: number;
  private j: number;

  constructor(key: Uint8Array) {
    this.s = new Array(256);
    this.i = 0;
    this.j = 0;
    
    // Initialize S array
    for (let i = 0; i < 256; i++) {
      this.s[i] = i;
    }
    
    // Key scheduling algorithm
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + this.s[i] + key[i % key.length]) % 256;
      [this.s[i], this.s[j]] = [this.s[j], this.s[i]];
    }
  }

  encrypt(data: Uint8Array): Uint8Array {
    const result = new Uint8Array(data.length);
    
    for (let k = 0; k < data.length; k++) {
      this.i = (this.i + 1) % 256;
      this.j = (this.j + this.s[this.i]) % 256;
      [this.s[this.i], this.s[this.j]] = [this.s[this.j], this.s[this.i]];
      const t = (this.s[this.i] + this.s[this.j]) % 256;
      result[k] = data[k] ^ this.s[t];
    }
    
    return result;
  }

  decrypt(data: Uint8Array): Uint8Array {
    // RC4 encryption and decryption are the same operation
    return this.encrypt(data);
  }
}

export class XiaomiCloudConnectorBrowser {
  private username: string;
  private password: string;
  private agent: string;
  private deviceId: string;
  private cookies: Record<string, string> = {};
  private sign: string | null = null;
  private ssecurity: string | null = null;
  private userId: string | null = null;
  private cUserId: string | null = null;
  private passToken: string | null = null;
  private location: string | null = null;
  private code: string | null = null;
  private serviceToken: string | null = null;
  private verifyUrl: string | null = null;
  private identitySession: string | null = null;
  private identityOptions: number[] = [];
  
  // Progress callback
  public onProgress?: (progress: any) => Promise<void>;

  constructor(username: string, password: string) {
    this.username = username;
    this.password = password;
    this.agent = this.generateAgent();
    this.deviceId = this.generateDeviceId();
  }

  private generateAgent(): string {
    // Match Python implementation exactly
    const agentId = Array.from({ length: 13 }, () => 
      String.fromCharCode(65 + Math.floor(Math.random() * 5)) // A-E (65-69)
    ).join('');
    const randomText = Array.from({ length: 18 }, () => 
      String.fromCharCode(97 + Math.floor(Math.random() * 26)) // a-z (97-122)
    ).join('');
    return `${randomText}-${agentId} APP/com.xiaomi.mihome APPV/10.5.201`;
  }

  private generateDeviceId(): string {
    // Match Python implementation: 6 lowercase letters
    return Array.from({ length: 6 }, () => 
      String.fromCharCode(97 + Math.floor(Math.random() * 26)) // a-z
    ).join('');
  }

  private async hashPassword(password: string): Promise<string> {
    // MD5 implementation since Web Crypto API doesn't support MD5
    const md5 = (string: string) => {
      function rotateLeft(value: number, shift: number) {
        return (value << shift) | (value >>> (32 - shift));
      }
      
      function addUnsigned(x: number, y: number) {
        const x4 = (x & 0x40000000);
        const y4 = (y & 0x40000000);
        const x8 = (x & 0x80000000);
        const y8 = (y & 0x80000000);
        const result = (x & 0x3FFFFFFF) + (y & 0x3FFFFFFF);
        if (x4 & y4) return (result ^ 0x80000000 ^ x8 ^ y8);
        if (x4 | y4) {
          if (result & 0x40000000) return (result ^ 0xC0000000 ^ x8 ^ y8);
          else return (result ^ 0x40000000 ^ x8 ^ y8);
        } else {
          return (result ^ x8 ^ y8);
        }
      }
      
      function f(x: number, y: number, z: number) { return (x & y) | ((~x) & z); }
      function g(x: number, y: number, z: number) { return (x & z) | (y & (~z)); }
      function h(x: number, y: number, z: number) { return (x ^ y ^ z); }
      function i(x: number, y: number, z: number) { return (y ^ (x | (~z))); }
      
      function ff(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
        a = addUnsigned(a, addUnsigned(addUnsigned(f(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
      }
      
      function gg(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
        a = addUnsigned(a, addUnsigned(addUnsigned(g(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
      }
      
      function hh(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
        a = addUnsigned(a, addUnsigned(addUnsigned(h(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
      }
      
      function ii(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
        a = addUnsigned(a, addUnsigned(addUnsigned(i(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
      }
      
      function convertToWordArray(string: string) {
        const wordCount = ((string.length + 8) >> 6) + 1;
        const wordArray = new Array(wordCount * 16);
        for (let i = 0; i < wordCount * 16; i++) wordArray[i] = 0;
        
        for (let i = 0; i < string.length; i++) {
          wordArray[i >> 2] |= string.charCodeAt(i) << ((i % 4) * 8);
        }
        
        wordArray[string.length >> 2] |= 0x80 << ((string.length % 4) * 8);
        wordArray[wordCount * 16 - 2] = string.length * 8;
        
        return wordArray;
      }
      
      function wordToHex(value: number) {
        let hex = '';
        for (let i = 0; i <= 3; i++) {
          const byte = (value >>> (i * 8)) & 255;
          hex += ('0' + byte.toString(16)).slice(-2);
        }
        return hex;
      }
      
      const x = convertToWordArray(string);
      let a = 0x67452301;
      let b = 0xEFCDAB89;
      let c = 0x98BADCFE;
      let d = 0x10325476;
      
      for (let k = 0; k < x.length; k += 16) {
        const tempA = a;
        const tempB = b;
        const tempC = c;
        const tempD = d;
        
        a = ff(a, b, c, d, x[k + 0], 7, 0xD76AA478);
        d = ff(d, a, b, c, x[k + 1], 12, 0xE8C7B756);
        c = ff(c, d, a, b, x[k + 2], 17, 0x242070DB);
        b = ff(b, c, d, a, x[k + 3], 22, 0xC1BDCEEE);
        a = ff(a, b, c, d, x[k + 4], 7, 0xF57C0FAF);
        d = ff(d, a, b, c, x[k + 5], 12, 0x4787C62A);
        c = ff(c, d, a, b, x[k + 6], 17, 0xA8304613);
        b = ff(b, c, d, a, x[k + 7], 22, 0xFD469501);
        a = ff(a, b, c, d, x[k + 8], 7, 0x698098D8);
        d = ff(d, a, b, c, x[k + 9], 12, 0x8B44F7AF);
        c = ff(c, d, a, b, x[k + 10], 17, 0xFFFF5BB1);
        b = ff(b, c, d, a, x[k + 11], 22, 0x895CD7BE);
        a = ff(a, b, c, d, x[k + 12], 7, 0x6B901122);
        d = ff(d, a, b, c, x[k + 13], 12, 0xFD987193);
        c = ff(c, d, a, b, x[k + 14], 17, 0xA679438E);
        b = ff(b, c, d, a, x[k + 15], 22, 0x49B40821);
        
        a = gg(a, b, c, d, x[k + 1], 5, 0xF61E2562);
        d = gg(d, a, b, c, x[k + 6], 9, 0xC040B340);
        c = gg(c, d, a, b, x[k + 11], 14, 0x265E5A51);
        b = gg(b, c, d, a, x[k + 0], 20, 0xE9B6C7AA);
        a = gg(a, b, c, d, x[k + 5], 5, 0xD62F105D);
        d = gg(d, a, b, c, x[k + 10], 9, 0x2441453);
        c = gg(c, d, a, b, x[k + 15], 14, 0xD8A1E681);
        b = gg(b, c, d, a, x[k + 4], 20, 0xE7D3FBC8);
        a = gg(a, b, c, d, x[k + 9], 5, 0x21E1CDE6);
        d = gg(d, a, b, c, x[k + 14], 9, 0xC33707D6);
        c = gg(c, d, a, b, x[k + 3], 14, 0xF4D50D87);
        b = gg(b, c, d, a, x[k + 8], 20, 0x455A14ED);
        a = gg(a, b, c, d, x[k + 13], 5, 0xA9E3E905);
        d = gg(d, a, b, c, x[k + 2], 9, 0xFCEFA3F8);
        c = gg(c, d, a, b, x[k + 7], 14, 0x676F02D9);
        b = gg(b, c, d, a, x[k + 12], 20, 0x8D2A4C8A);
        
        a = hh(a, b, c, d, x[k + 5], 4, 0xFFFA3942);
        d = hh(d, a, b, c, x[k + 8], 11, 0x8771F681);
        c = hh(c, d, a, b, x[k + 11], 16, 0x6D9D6122);
        b = hh(b, c, d, a, x[k + 14], 23, 0xFDE5380C);
        a = hh(a, b, c, d, x[k + 1], 4, 0xA4BEEA44);
        d = hh(d, a, b, c, x[k + 4], 11, 0x4BDECFA9);
        c = hh(c, d, a, b, x[k + 7], 16, 0xF6BB4B60);
        b = hh(b, c, d, a, x[k + 10], 23, 0xBEBFBC70);
        a = hh(a, b, c, d, x[k + 13], 4, 0x289B7EC6);
        d = hh(d, a, b, c, x[k + 0], 11, 0xEAA127FA);
        c = hh(c, d, a, b, x[k + 3], 16, 0xD4EF3085);
        b = hh(b, c, d, a, x[k + 6], 23, 0x4881D05);
        a = hh(a, b, c, d, x[k + 9], 4, 0xD9D4D039);
        d = hh(d, a, b, c, x[k + 12], 11, 0xE6DB99E5);
        c = hh(c, d, a, b, x[k + 15], 16, 0x1FA27CF8);
        b = hh(b, c, d, a, x[k + 2], 23, 0xC4AC5665);
        
        a = ii(a, b, c, d, x[k + 0], 6, 0xF4292244);
        d = ii(d, a, b, c, x[k + 7], 10, 0x432AFF97);
        c = ii(c, d, a, b, x[k + 14], 15, 0xAB9423A7);
        b = ii(b, c, d, a, x[k + 5], 21, 0xFC93A039);
        a = ii(a, b, c, d, x[k + 12], 6, 0x655B59C3);
        d = ii(d, a, b, c, x[k + 3], 10, 0x8F0CCC92);
        c = ii(c, d, a, b, x[k + 10], 15, 0xFFEFF47D);
        b = ii(b, c, d, a, x[k + 1], 21, 0x85845DD1);
        a = ii(a, b, c, d, x[k + 8], 6, 0x6FA87E4F);
        d = ii(d, a, b, c, x[k + 15], 10, 0xFE2CE6E0);
        c = ii(c, d, a, b, x[k + 6], 15, 0xA3014314);
        b = ii(b, c, d, a, x[k + 13], 21, 0x4E0811A1);
        a = ii(a, b, c, d, x[k + 4], 6, 0xF7537E82);
        d = ii(d, a, b, c, x[k + 11], 10, 0xBD3AF235);
        c = ii(c, d, a, b, x[k + 2], 15, 0x2AD7D2BB);
        b = ii(b, c, d, a, x[k + 9], 21, 0xEB86D391);
        
        a = addUnsigned(a, tempA);
        b = addUnsigned(b, tempB);
        c = addUnsigned(c, tempC);
        d = addUnsigned(d, tempD);
      }
      
      return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toUpperCase();
    };
    
    return md5(password);
  }

  private async proxyFetch(url: string, options: any = {}): Promise<any> {
    // When running on server (Node.js), make direct request
    if (typeof window === 'undefined') {
      const response = await fetch(url, {
        method: options.method || 'GET',
        headers: options.headers || {},
        body: options.body,
        redirect: 'manual' // Handle redirects manually to preserve cookies
      });
      
      const responseText = await response.text();
      
      // Parse cookies from headers
      // Node.js fetch returns raw headers which may have multiple set-cookie values
      const rawHeaders = (response as any).headers.raw?.();
      if (rawHeaders && rawHeaders['set-cookie']) {
        this.parseCookies(rawHeaders['set-cookie']);
      } else {
        const setCookieHeader = response.headers.get('set-cookie');
        if (setCookieHeader) {
          this.parseCookies(setCookieHeader);
        }
      }
      
      return {
        ok: response.ok,
        status: response.status,
        headers: {
          location: response.headers.get('location')
        },
        text: async () => responseText,
        json: async () => {
          let jsonStr = responseText;
          // Handle JSONP response format &&&START&&&{...}
          if (jsonStr.includes('&&&START&&&')) {
            jsonStr = jsonStr.replace('&&&START&&&', '');
          }
          return JSON.parse(jsonStr);
        }
      };
    }
    
    // When running in browser, use proxy
    const response = await fetch('/api/proxy', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        url,
        method: options.method || 'GET',
        headers: options.headers || {},
        body: options.body
      })
    });

    const result = await response.json();
    if (result.error) {
      throw new Error(result.error);
    }

    // Parse cookies from headers
    if (result.headers['set-cookie']) {
      this.parseCookies(result.headers['set-cookie']);
    }

    return {
      ok: result.status >= 200 && result.status < 300,
      status: result.status,
      text: async () => result.body,
      json: async () => {
        let jsonStr = result.body;
        // Handle JSONP response format &&&START&&&{...}
        if (jsonStr.includes('&&&START&&&')) {
          jsonStr = jsonStr.replace('&&&START&&&', '');
        }
        return JSON.parse(jsonStr);
      }
    };
  }

  async loginStep1(): Promise<boolean> {
    const url = "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true";
    try {
      const response = await this.proxyFetch(url, {
        headers: {
          'User-Agent': this.agent,
          'Cookie': `userId=${this.username}`
        }
      });
      
      const data = await response.json();
      if (data && data._sign) {
        this.sign = data._sign;
        return true;
      }
    } catch (error) {
      console.error("Login step 1 failed:", error);
    }
    return false;
  }

  async loginStep2(): Promise<{ success: boolean; requires2FA?: boolean; verifyUrl?: string; error?: string }> {
    const url = "https://account.xiaomi.com/pass/serviceLoginAuth2";
    const hash = await this.hashPassword(this.password);
    
    const fields = {
      "_json": "true",
      "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
      "sid": "xiaomiio",
      "_sign": this.sign,
      "hash": hash,
      "callback": "https://sts.api.io.mi.com/sts",
      "user": this.username,
      "deviceId": this.deviceId,
      "serviceParam": '{"checkSafePhone":false}'
    };

    try {
      const response = await this.proxyFetch(url, {
        method: 'POST',
        headers: {
          'User-Agent': this.agent,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams(fields).toString()
      });
      
      if (!response.ok) {
        console.error("Login step 2 HTTP error:", response.status);
        const text = await response.text();
        console.error("Response text:", text);
        return { success: false, error: `HTTP ${response.status}` };
      }
      
      const data = await response.json();
      // console.log("Login step 2 response:", data);
      
      if (data.code === 0) {
        // Check if additional verification is required
        if (data.securityStatus === 16 && data.notificationUrl) {
          // Security verification required (similar to 2FA)
          this.verifyUrl = data.notificationUrl;
          return { success: false, requires2FA: true, verifyUrl: this.verifyUrl };
        }
        
        // Normal successful login
        this.ssecurity = data.ssecurity;
        this.userId = data.userId;
        this.cUserId = data.cUserId;
        this.passToken = data.passToken;
        this.location = data.location;
        this.code = data.code;
        
        // console.log("Login step 2 success:", {
        //   userId: this.userId,
        //   location: this.location,
        //   cookies: this.cookies
        // });
        
        // Only return success if we have required data
        if (this.location) {
          return { success: true };
        } else {
          return { success: false, error: "Missing location URL" };
        }
      } else if (data.code === 20003) {
        // 2FA required
        this.verifyUrl = data.notificationUrl;
        return { success: false, requires2FA: true, verifyUrl: this.verifyUrl };
      } else {
        return { success: false, error: data.desc || "Login failed" };
      }
    } catch (error: any) {
      console.error("Login step 2 failed:", error);
      return { success: false, error: error.message };
    }
  }

  async checkIdentityOptions(): Promise<boolean> {
    if (!this.verifyUrl) {
      console.error("No verify URL available");
      return false;
    }

    // console.log("Checking identity options from:", this.verifyUrl);
    
    try {
      // Replace 'identity/authStart' with 'identity/list' as per Python implementation
      const listUrl = this.verifyUrl.replace('identity/authStart', 'identity/list');
      // console.log("Fetching identity list from:", listUrl);
      
      const response = await this.proxyFetch(listUrl, {
        headers: {
          'User-Agent': this.agent,
          'Cookie': this.buildCookieString()
        }
      });

      const text = await response.text();
      // console.log("Identity list response:", text);

      // Extract identity_session cookie
      if (this.cookies.identity_session) {
        this.identitySession = this.cookies.identity_session;
        // console.log("Got identity_session:", this.identitySession);
      }

      try {
        // Remove &&&START&&& if present (as per Python: resp.text.replace('&&&START&&&', ''))
        const cleanText = text.replace('&&&START&&&', '');
        const data = JSON.parse(cleanText);
        
        // Extract flag and options as per Python:
        // flag = data.get('flag', 4)
        // options = data.get('options', [flag])
        const flag = data.flag || 4;
        this.identityOptions = data.options || [flag];
        
        // console.log("Identity options from API:", this.identityOptions);
        return true;
      } catch (e) {
        console.error("Failed to parse identity list response:", e);
        // Default to phone (4) if parsing fails
        this.identityOptions = [4];
        return true;
      }
    } catch (error) {
      console.error("Failed to check identity options:", error);
      // Default to phone (4) if request fails
      this.identityOptions = [4];
      return true;
    }
  }

  async verify2FATicket(ticket: string): Promise<{ success: boolean; error?: string }> {
    // console.log("verify2FATicket called with ticket:", ticket);
    
    // First, check identity options if we haven't already
    if (this.identityOptions.length === 0) {
      await this.checkIdentityOptions();
    }

    // Try each verification method
    for (const flag of this.identityOptions) {
      const api = flag === 4 ? '/identity/auth/verifyPhone' : 
                  flag === 8 ? '/identity/auth/verifyEmail' : null;
      
      if (!api) continue;

      const url = `https://account.xiaomi.com${api}`;
      const data = new URLSearchParams({
        '_flag': flag.toString(),
        'ticket': ticket,
        'trust': 'true',
        '_json': 'true'
      });

      const params = new URLSearchParams({
        '_dc': Date.now().toString()
      });

      const fullUrl = `${url}?${params}`;
      // console.log(`Trying verification with flag ${flag}:`, fullUrl);

      try {
        const cookieString = this.buildCookieString() + 
          (this.identitySession ? `; identity_session=${this.identitySession}` : '');

        const response = await this.proxyFetch(fullUrl, {
          method: 'POST',
          headers: {
            'User-Agent': this.agent,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': cookieString
          },
          body: data.toString()
        });
        
        // console.log(`Verification response status (flag ${flag}):`, response.status);
        
        const result = await response.json();
        // console.log(`Verification response data (flag ${flag}):`, result);
        
        if (result && result.code === 0) {
          // Success! Follow the location if provided
          if (result.location) {
            // console.log("Following redirect to:", result.location);
            try {
              // Follow the redirect chain
              let currentUrl = result.location;
              let redirectCount = 0;
              const maxRedirects = 5;
              
              while (redirectCount < maxRedirects) {
                const response = await this.proxyFetch(currentUrl, {
                  headers: {
                    'User-Agent': this.agent,
                    'Cookie': this.buildCookieString() + (this.identitySession ? `; identity_session=${this.identitySession}` : '')
                  }
                });
                
                // console.log(`Redirect ${redirectCount + 1} status:`, response.status);
                
                // Check if there's another redirect
                if (response.status >= 300 && response.status < 400 && response.headers?.location) {
                  currentUrl = response.headers.location;
                  // console.log(`Following next redirect to:`, currentUrl);
                  redirectCount++;
                  continue;
                }
                
                // Try to extract data from the response
                try {
                  const text = await response.text();
                  // console.log(`Redirect response preview:`, text.substring(0, 200));
                  
                  // Check if this response contains session data
                  if (text.includes('ssecurity') || text.includes('serviceToken')) {
                    const jsonMatch = text.match(/\{.*?\}/);
                    if (jsonMatch) {
                      const data = JSON.parse(jsonMatch[0]);
                      if (data.ssecurity) this.ssecurity = data.ssecurity;
                      if (data.userId) this.userId = data.userId;
                      if (data.serviceToken) this.serviceToken = data.serviceToken;
                      if (data.location) this.location = data.location;
                    }
                  }
                } catch (e) {
                  // console.log("Error parsing redirect response:", e);
                }
                
                break;
              }
            } catch (e) {
              console.error("Redirect follow error:", e);
            }
          }
          
          // Extract session data from result
          if (result.ssecurity) this.ssecurity = result.ssecurity;
          if (result.userId) this.userId = result.userId;
          if (result.cUserId) this.cUserId = result.cUserId;
          if (result.passToken) this.passToken = result.passToken;
          if (result.location) this.location = result.location;
          
          return { success: true };
        }
      } catch (error) {
        console.error(`Verification failed for flag ${flag}:`, error);
      }
    }
    
    return { success: false, error: "Invalid verification code" };
  }

  async loginStep3(): Promise<boolean> {
    if (!this.location) {
      console.error("Login step 3: No location URL");
      return false;
    }

    try {
      let currentUrl = this.location;
      let attempts = 0;
      const maxRedirects = 5;
      
      // Follow redirects manually
      while (attempts < maxRedirects) {
        const response = await this.proxyFetch(currentUrl, {
          headers: {
            'User-Agent': this.agent,
            'Cookie': this.buildCookieString()
          }
        });
        
        // Check for redirect
        if (response.status >= 300 && response.status < 400) {
          const redirectUrl = response.headers?.location;
          if (redirectUrl) {
            currentUrl = redirectUrl;
            attempts++;
            continue;
          }
        }
        
        break;
      }
      
      // console.log("Login step 3 cookies:", this.cookies);
      
      // Extract serviceToken from cookies
      if (this.cookies.serviceToken) {
        this.serviceToken = this.cookies.serviceToken;
        return true;
      } else {
        console.error("Login step 3: No serviceToken in cookies");
      }
    } catch (error) {
      console.error("Login step 3 failed:", error);
    }
    return false;
  }

  private parseCookies(cookieString: string | string[]): void {
    const cookieStrings = Array.isArray(cookieString) ? cookieString : [cookieString];
    
    cookieStrings.forEach(cookieStr => {
      // Parse each Set-Cookie header
      const parts = cookieStr.split(';');
      const [keyValue] = parts;
      const [key, value] = keyValue.trim().split('=');
      
      if (key && value) {
        this.cookies[key] = value;
      }
    });
  }

  private generateNonce(): string {
    // Python: nonce_bytes = os.urandom(8) + (int(millis / 60000)).to_bytes(4, byteorder='big')
    const randomBytes = new Uint8Array(8);
    crypto.getRandomValues(randomBytes);
    
    const millis = Date.now();
    const timeBytes = new Uint8Array(4);
    const timeValue = Math.floor(millis / 60000);
    // Convert to big-endian bytes
    timeBytes[0] = (timeValue >> 24) & 0xff;
    timeBytes[1] = (timeValue >> 16) & 0xff;
    timeBytes[2] = (timeValue >> 8) & 0xff;
    timeBytes[3] = timeValue & 0xff;
    
    // Combine random + time bytes
    const nonceBytes = new Uint8Array(12);
    nonceBytes.set(randomBytes, 0);
    nonceBytes.set(timeBytes, 8);
    
    // Convert to base64
    let binary = '';
    for (let i = 0; i < nonceBytes.length; i++) {
      binary += String.fromCharCode(nonceBytes[i]);
    }
    return btoa(binary);
  }

  private async signedNonce(nonce: string): Promise<string> {
    if (!this.ssecurity) {
      console.error("No ssecurity available for signing");
      throw new Error("Missing ssecurity");
    }
    
    try {
      // Python: hashlib.sha256(base64.b64decode(self._ssecurity) + base64.b64decode(nonce))
      // Decode both ssecurity and nonce from base64
      const ssecurityBytes = Uint8Array.from(atob(this.ssecurity), c => c.charCodeAt(0));
      const nonceBytes = Uint8Array.from(atob(nonce), c => c.charCodeAt(0));
      
      // Concatenate the byte arrays
      const combined = new Uint8Array(ssecurityBytes.length + nonceBytes.length);
      combined.set(ssecurityBytes, 0);
      combined.set(nonceBytes, ssecurityBytes.length);
      
      const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
      const hashArray = new Uint8Array(hashBuffer);
      
      // Convert to base64
      let binary = '';
      for (let i = 0; i < hashArray.length; i++) {
        binary += String.fromCharCode(hashArray[i]);
      }
      return btoa(binary);
    } catch (error) {
      console.error("Error in signedNonce:", error);
      throw error;
    }
  }

  private encryptRC4(password: string, payload: string): string {
    // Python: r.encrypt(bytes(1024)) then r.encrypt(payload.encode())
    const keyBytes = Uint8Array.from(atob(password), c => c.charCodeAt(0));
    const rc4 = new RC4(keyBytes);
    
    // Discard first 1024 bytes as per Python implementation
    rc4.encrypt(new Uint8Array(1024));
    
    // Encrypt the payload
    const payloadBytes = new TextEncoder().encode(payload);
    const encrypted = rc4.encrypt(payloadBytes);
    
    // Convert to base64
    return btoa(String.fromCharCode(...encrypted));
  }

  private decryptRC4(password: string, payload: string): string {
    // Python: r.encrypt(bytes(1024)) then r.encrypt(base64.b64decode(payload))
    const keyBytes = Uint8Array.from(atob(password), c => c.charCodeAt(0));
    const rc4 = new RC4(keyBytes);
    
    // Discard first 1024 bytes
    rc4.encrypt(new Uint8Array(1024));
    
    // Decrypt the base64 payload
    const encryptedBytes = Uint8Array.from(atob(payload), c => c.charCodeAt(0));
    const decrypted = rc4.decrypt(encryptedBytes);
    
    // Convert to string
    return new TextDecoder().decode(decrypted);
  }

  private async generateEncSignature(url: string, method: string, signedNonce: string, params: Record<string, any>): Promise<string> {
    // Python: signature_params = [str(method).upper(), url.split("com")[1].replace("/app/", "/")]
    const urlPath = url.split('com')[1].replace('/app/', '/');
    const signatureParams = [method.toUpperCase(), urlPath];
    
    // Add sorted params
    Object.keys(params).sort().forEach(k => {
      signatureParams.push(`${k}=${params[k]}`);
    });
    
    signatureParams.push(signedNonce);
    const signString = signatureParams.join('&');
    
    // SHA1 hash and base64 encode
    const encoder = new TextEncoder();
    const data = encoder.encode(signString);
    
    // Use SubtleCrypto for SHA1
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = new Uint8Array(hashBuffer);
    
    // Convert to base64
    let binary = '';
    for (let i = 0; i < hashArray.length; i++) {
      binary += String.fromCharCode(hashArray[i]);
    }
    return btoa(binary);
  }

  private async generateSignature(url: string, signedNonce: string, nonce: string, params?: Record<string, any>): Promise<string> {
    try {
      // Python: signature_params = [url.split("com")[1], signed_nonce, nonce]
      const urlPath = url.split(".com")[1] || url;
      const signatureParams = [urlPath, signedNonce, nonce];
      
      // Add params as key=value pairs (sorted by key)
      if (params) {
        Object.keys(params).sort().forEach(k => {
          signatureParams.push(`${k}=${params[k]}`);
        });
      }
      
      const signString = signatureParams.join('&');
      // console.log("Sign string:", signString);
      
      // Use signedNonce as HMAC key (decoded from base64)
      const keyData = Uint8Array.from(atob(signedNonce), c => c.charCodeAt(0));
      
      const key = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      
      const encoder = new TextEncoder();
      const signature = await crypto.subtle.sign(
        'HMAC',
        key,
        encoder.encode(signString)
      );
      
      // Convert to base64
      const signatureArray = new Uint8Array(signature);
      let binary = '';
      for (let i = 0; i < signatureArray.length; i++) {
        binary += String.fromCharCode(signatureArray[i]);
      }
      
      return btoa(binary);
    } catch (error) {
      console.error("Error generating signature:", error);
      throw error;
    }
  }

  async getDevices(server: string = 'cn'): Promise<{ success: boolean; devices?: Device[]; error?: string }> {
    try {
      // console.log("\n=== Getting devices using encrypted API ===");
      
      await this.reportProgress({ message: 'Getting homes...', step: 'homes' });
      
      const allHomes: Array<{home_id: string, home_owner: string, name?: string}> = [];
      
      // First get homes
      const homes = await this.getHomes(server);
      if (homes.success && homes.homes) {
        for (const h of homes.homes) {
          allHomes.push({ home_id: h.id, home_owner: this.userId!, name: h.name });
        }
      }
      
      // Also get shared homes
      await this.reportProgress({ message: 'Checking shared homes...', step: 'shared' });
      const devCnt = await this.getDeviceCountDetails(server);
      if (devCnt.success && devCnt.shareFamilies) {
        for (const h of devCnt.shareFamilies) {
          allHomes.push({ home_id: h.home_id, home_owner: h.home_owner });
        }
      }

      // console.log(`Found ${allHomes.length} total homes (owned + shared)`);
      await this.reportProgress({ 
        message: `Found ${allHomes.length} home(s)`, 
        step: 'homes_complete',
        totalHomes: allHomes.length 
      });
      
      if (allHomes.length === 0) {
        return { success: true, devices: [] };
      }
      
      const allDevices: Device[] = [];
      
      // Get devices for each home
      for (let i = 0; i < allHomes.length; i++) {
        const home = allHomes[i];
        await this.reportProgress({ 
          message: `Getting devices from home ${i + 1}/${allHomes.length}${home.name ? ` (${home.name})` : ''}...`, 
          step: 'devices',
          currentHome: i + 1,
          totalHomes: allHomes.length
        });
        
        const devices = await this.getHomeDevices(server, home.home_id, home.home_owner);
        if (devices.success && devices.devices) {
          // Stream devices as they come
          for (const device of devices.devices) {
            allDevices.push(device);
            await this.reportProgress({ 
              message: `Found device: ${device.name}`,
              step: 'device_found',
              device,
              totalDevices: allDevices.length
            });
          }
        }
      }
      
      // console.log(`Total devices found: ${allDevices.length}`);
      return { success: true, devices: allDevices };
    } catch (error: any) {
      console.error("Get devices failed:", error);
      return { success: false, error: error.message };
    }
  }
  
  private async reportProgress(progress: any): Promise<void> {
    if (this.onProgress) {
      await this.onProgress(progress);
    }
  }

  private async getHomes(server: string): Promise<{ success: boolean; homes?: any[]; error?: string }> {
    const url = this.getApiUrl(server) + "/v2/homeroom/gethome";
    const params = {
      data: '{"fg": true, "fetch_share": true, "fetch_share_dev": true, "limit": 300, "app_ver": 7}'
    };
    
    const result = await this.executeApiCallEncrypted(url, params);
    if (result && result.code === 0) {
      const homes = result.result?.homelist || [];
      // console.log(`Got ${homes.length} homes from server ${server}`);
      return { success: true, homes };
    }
    
    return { success: false, error: result?.message || "Failed to get homes" };
  }

  private async getHomeDevices(server: string, homeId: string, ownerId: string): Promise<{ success: boolean; devices?: Device[]; error?: string }> {
    const url = this.getApiUrl(server) + "/v2/home/home_device_list";
    const params = {
      data: `{"home_owner": ${ownerId}, "home_id": ${homeId}, "limit": 200, "get_split_device": true, "support_smart_home": true}`
    };
    
    const result = await this.executeApiCallEncrypted(url, params);
    if (result && result.code === 0) {
      const devices = result.result?.device_info || [];
      // console.log(`Got ${devices.length} devices from home ${homeId}`);
      
      // Transform to our Device interface and fetch BLE keys for Bluetooth devices
      const transformedDevices: Device[] = [];
      
      for (const d of devices) {
        const device: Device = {
          did: d.did,
          name: d.name,
          model: d.model,
          token: d.token,
          ip: d.localip,
          mac: d.mac,
          ssid: d.ssid,
          bssid: d.bssid,
          rssi: d.rssi,
          isOnline: d.isOnline || false,
          desc: d.desc,
          extra: d.extra || {}
        };
        
        // Check if this is a Bluetooth device and fetch BLE key
        if (d.did && d.did.includes('blt')) {
          await this.reportProgress({ 
            message: `Fetching BLE key for ${d.name}...`,
            step: 'ble_key',
            deviceName: d.name
          });
          
          const bleData = await this.getBeaconKey(server, d.did);
          if (bleData && bleData.beaconkey) {
            device.extra = device.extra || {};
            device.extra.ble_key = bleData.beaconkey;
            // console.log(`Got BLE key for ${d.did}: ${bleData.beaconkey}`);
          }
        }
        
        transformedDevices.push(device);
      }
      
      return { success: true, devices: transformedDevices };
    }
    
    return { success: false, error: result?.message || "Failed to get devices" };
  }

  private getApiUrl(server: string): string {
    return server === 'cn' ? 'https://api.io.mi.com/app' : `https://${server}.api.io.mi.com/app`;
  }

  private async executeApiCallEncrypted(url: string, params: Record<string, any>): Promise<any> {
    const nonce = this.generateNonce();
    const signedNonce = await this.signedNonce(nonce);
    
    // Generate encrypted params
    const encParams = await this.generateEncParams(url, 'POST', signedNonce, nonce, params);
    
    const headers = {
      'Accept-Encoding': 'identity',
      'User-Agent': this.agent,
      'Content-Type': 'application/x-www-form-urlencoded',
      'x-xiaomi-protocal-flag-cli': 'PROTOCAL-HTTP2',
      'MIOT-ENCRYPT-ALGORITHM': 'ENCRYPT-RC4',
      'Cookie': this.buildCookieString()
    };

    const queryString = new URLSearchParams(encParams).toString();
    // console.log(`Making encrypted request to: ${url}`);
    
    try {
      const response = await this.proxyFetch(`${url}?${queryString}`, {
        method: 'POST',
        headers
      });
      
      const responseText = await response.text();
      // console.log('Encrypted response received, length:', responseText.length);
      
      // Decrypt response
      const decrypted = this.decryptRC4(signedNonce, responseText);
      // console.log('Decrypted response:', decrypted.substring(0, 200));
      
      return JSON.parse(decrypted);
    } catch (error: any) {
      console.error('Encrypted API call failed:', error);
      throw error;
    }
  }

  private async generateEncParams(url: string, method: string, signedNonce: string, nonce: string, params: Record<string, any>): Promise<Record<string, string>> {
    // First add rc4_hash__
    const tempParams = { ...params };
    tempParams['rc4_hash__'] = await this.generateEncSignature(url, method, signedNonce, tempParams);
    
    // Encrypt all params
    const encryptedParams: Record<string, string> = {};
    for (const [k, v] of Object.entries(tempParams)) {
      encryptedParams[k] = this.encryptRC4(signedNonce, String(v));
    }
    
    // Generate final signature with encrypted params
    encryptedParams['signature'] = await this.generateEncSignature(url, method, signedNonce, encryptedParams);
    encryptedParams['ssecurity'] = this.ssecurity!;
    encryptedParams['_nonce'] = nonce;
    
    return encryptedParams;
  }


  private buildCookieString(): string {
    const cookieEntries = [];
    
    // Add userId if available
    if (this.userId) {
      cookieEntries.push(`userId=${this.userId}`);
    }
    
    // Add serviceToken if available
    if (this.serviceToken) {
      cookieEntries.push(`serviceToken=${this.serviceToken}`);
      cookieEntries.push(`yetAnotherServiceToken=${this.serviceToken}`);
    }
    
    // Add additional cookies as per Python implementation
    cookieEntries.push('locale=en_GB');
    cookieEntries.push('timezone=GMT+02:00');
    cookieEntries.push('is_daylight=1');
    cookieEntries.push('dst_offset=3600000');
    cookieEntries.push('channel=MI_APP_STORE');
    cookieEntries.push('sdkVersion=accountsdk-18.8.15');
    cookieEntries.push(`deviceId=${this.deviceId}`);
    
    // Add any other cookies
    Object.entries(this.cookies).forEach(([key, value]) => {
      if (!['userId', 'serviceToken', 'yetAnotherServiceToken', 'locale', 'timezone', 'is_daylight', 'dst_offset', 'channel', 'sdkVersion', 'deviceId'].includes(key)) {
        cookieEntries.push(`${key}=${value}`);
      }
    });
    
    return cookieEntries.join('; ');
  }

  getSessionData(): SessionData {
    return {
      username: this.username,
      userId: this.userId!,
      serviceToken: this.serviceToken!,
      ssecurity: this.ssecurity!,
      cookies: this.cookies,
      deviceId: this.deviceId,
      savedAt: new Date().toISOString()
    };
  }

  loadSessionData(sessionData: SessionData | any): void {
    this.username = sessionData.username;
    this.userId = sessionData.userId;
    this.serviceToken = sessionData.serviceToken;
    this.ssecurity = sessionData.ssecurity;
    this.cookies = sessionData.cookies || {};
    this.deviceId = sessionData.deviceId || sessionData.device_id || this.generateDeviceId();
    
    // Ensure critical cookies are set
    if (this.userId) this.cookies.userId = this.userId;
    if (this.serviceToken) {
      this.cookies.serviceToken = this.serviceToken;
      this.cookies.yetAnotherServiceToken = this.serviceToken;
    }
  }

  async validateSession(): Promise<boolean> {
    // console.log("Validating session - serviceToken:", this.serviceToken ? "present" : "missing");
    // console.log("Validating session - ssecurity:", this.ssecurity ? "present" : "missing");
    // console.log("Validating session - userId:", this.userId);
    
    if (!this.serviceToken || !this.ssecurity) {
      console.error("Missing required tokens for validation");
      return false;
    }

    try {
      // Use get_dev_cnt like Python for validation
      const result = await this.getDeviceCount('cn');
      return result.success;
    } catch (error) {
      console.error("Session validation error:", error);
      return false;
    }
  }

  private async getDeviceCount(server: string): Promise<{ success: boolean; error?: string }> {
    const url = this.getApiUrl(server) + "/v2/user/get_device_cnt";
    const params = {
      data: '{ "fetch_own": true, "fetch_share": true}'
    };
    
    try {
      const result = await this.executeApiCallEncrypted(url, params);
      if (result && result.code === 0) {
        // console.log('Device count validation successful');
        return { success: true };
      }
      return { success: false, error: result?.message || "Failed" };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  private async getDeviceCountDetails(server: string): Promise<{ success: boolean; shareFamilies?: any[]; error?: string }> {
    const url = this.getApiUrl(server) + "/v2/user/get_device_cnt";
    const params = {
      data: '{ "fetch_own": true, "fetch_share": true}'
    };
    
    try {
      const result = await this.executeApiCallEncrypted(url, params);
      if (result && result.code === 0) {
        const shareFamilies = result.result?.share?.share_family || [];
        // console.log(`Found ${shareFamilies.length} shared families`);
        return { success: true, shareFamilies };
      }
      return { success: false, error: result?.message || "Failed" };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  private async getBeaconKey(server: string, did: string): Promise<{ beaconkey?: string; beaconkey_block4?: string } | null> {
    const url = this.getApiUrl(server) + "/v2/device/blt_get_beaconkey";
    const params = {
      data: `{"did":"${did}","pdid":1}`
    };
    
    try {
      const result = await this.executeApiCallEncrypted(url, params);
      if (result && result.code === 0 && result.result) {
        return {
          beaconkey: result.result.beaconkey,
          beaconkey_block4: result.result.beaconkey_block4
        };
      }
      return null;
    } catch (error: any) {
      console.error(`Failed to get beacon key for ${did}:`, error.message);
      return null;
    }
  }
}