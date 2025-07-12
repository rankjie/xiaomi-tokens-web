import { SessionData, Device } from "./types";
import { debug } from "./utils/debug";

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
    const agentId = Array.from(
      { length: 13 },
      () => String.fromCharCode(65 + Math.floor(Math.random() * 5)) // A-E (65-69)
    ).join("");
    const randomText = Array.from(
      { length: 18 },
      () => String.fromCharCode(97 + Math.floor(Math.random() * 26)) // a-z (97-122)
    ).join("");
    return `${randomText}-${agentId} APP/com.xiaomi.mihome APPV/10.5.201`;
  }

  private generateDeviceId(): string {
    // Match Python implementation: 6 lowercase letters
    return Array.from(
      { length: 6 },
      () => String.fromCharCode(97 + Math.floor(Math.random() * 26)) // a-z
    ).join("");
  }

  private async hashPassword(password: string): Promise<string> {
    // MD5 implementation since Web Crypto API doesn't support MD5
    const md5 = (string: string) => {
      function rotateLeft(value: number, shift: number) {
        return (value << shift) | (value >>> (32 - shift));
      }

      function addUnsigned(x: number, y: number) {
        const x4 = x & 0x40000000;
        const y4 = y & 0x40000000;
        const x8 = x & 0x80000000;
        const y8 = y & 0x80000000;
        const result = (x & 0x3fffffff) + (y & 0x3fffffff);
        if (x4 & y4) return result ^ 0x80000000 ^ x8 ^ y8;
        if (x4 | y4) {
          if (result & 0x40000000) return result ^ 0xc0000000 ^ x8 ^ y8;
          else return result ^ 0x40000000 ^ x8 ^ y8;
        } else {
          return result ^ x8 ^ y8;
        }
      }

      function f(x: number, y: number, z: number) {
        return (x & y) | (~x & z);
      }
      function g(x: number, y: number, z: number) {
        return (x & z) | (y & ~z);
      }
      function h(x: number, y: number, z: number) {
        return x ^ y ^ z;
      }
      function i(x: number, y: number, z: number) {
        return y ^ (x | ~z);
      }

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
        let hex = "";
        for (let i = 0; i <= 3; i++) {
          const byte = (value >>> (i * 8)) & 255;
          hex += ("0" + byte.toString(16)).slice(-2);
        }
        return hex;
      }

      const x = convertToWordArray(string);
      let a = 0x67452301;
      let b = 0xefcdab89;
      let c = 0x98badcfe;
      let d = 0x10325476;

      for (let k = 0; k < x.length; k += 16) {
        const tempA = a;
        const tempB = b;
        const tempC = c;
        const tempD = d;

        a = ff(a, b, c, d, x[k + 0], 7, 0xd76aa478);
        d = ff(d, a, b, c, x[k + 1], 12, 0xe8c7b756);
        c = ff(c, d, a, b, x[k + 2], 17, 0x242070db);
        b = ff(b, c, d, a, x[k + 3], 22, 0xc1bdceee);
        a = ff(a, b, c, d, x[k + 4], 7, 0xf57c0faf);
        d = ff(d, a, b, c, x[k + 5], 12, 0x4787c62a);
        c = ff(c, d, a, b, x[k + 6], 17, 0xa8304613);
        b = ff(b, c, d, a, x[k + 7], 22, 0xfd469501);
        a = ff(a, b, c, d, x[k + 8], 7, 0x698098d8);
        d = ff(d, a, b, c, x[k + 9], 12, 0x8b44f7af);
        c = ff(c, d, a, b, x[k + 10], 17, 0xffff5bb1);
        b = ff(b, c, d, a, x[k + 11], 22, 0x895cd7be);
        a = ff(a, b, c, d, x[k + 12], 7, 0x6b901122);
        d = ff(d, a, b, c, x[k + 13], 12, 0xfd987193);
        c = ff(c, d, a, b, x[k + 14], 17, 0xa679438e);
        b = ff(b, c, d, a, x[k + 15], 22, 0x49b40821);

        a = gg(a, b, c, d, x[k + 1], 5, 0xf61e2562);
        d = gg(d, a, b, c, x[k + 6], 9, 0xc040b340);
        c = gg(c, d, a, b, x[k + 11], 14, 0x265e5a51);
        b = gg(b, c, d, a, x[k + 0], 20, 0xe9b6c7aa);
        a = gg(a, b, c, d, x[k + 5], 5, 0xd62f105d);
        d = gg(d, a, b, c, x[k + 10], 9, 0x2441453);
        c = gg(c, d, a, b, x[k + 15], 14, 0xd8a1e681);
        b = gg(b, c, d, a, x[k + 4], 20, 0xe7d3fbc8);
        a = gg(a, b, c, d, x[k + 9], 5, 0x21e1cde6);
        d = gg(d, a, b, c, x[k + 14], 9, 0xc33707d6);
        c = gg(c, d, a, b, x[k + 3], 14, 0xf4d50d87);
        b = gg(b, c, d, a, x[k + 8], 20, 0x455a14ed);
        a = gg(a, b, c, d, x[k + 13], 5, 0xa9e3e905);
        d = gg(d, a, b, c, x[k + 2], 9, 0xfcefa3f8);
        c = gg(c, d, a, b, x[k + 7], 14, 0x676f02d9);
        b = gg(b, c, d, a, x[k + 12], 20, 0x8d2a4c8a);

        a = hh(a, b, c, d, x[k + 5], 4, 0xfffa3942);
        d = hh(d, a, b, c, x[k + 8], 11, 0x8771f681);
        c = hh(c, d, a, b, x[k + 11], 16, 0x6d9d6122);
        b = hh(b, c, d, a, x[k + 14], 23, 0xfde5380c);
        a = hh(a, b, c, d, x[k + 1], 4, 0xa4beea44);
        d = hh(d, a, b, c, x[k + 4], 11, 0x4bdecfa9);
        c = hh(c, d, a, b, x[k + 7], 16, 0xf6bb4b60);
        b = hh(b, c, d, a, x[k + 10], 23, 0xbebfbc70);
        a = hh(a, b, c, d, x[k + 13], 4, 0x289b7ec6);
        d = hh(d, a, b, c, x[k + 0], 11, 0xeaa127fa);
        c = hh(c, d, a, b, x[k + 3], 16, 0xd4ef3085);
        b = hh(b, c, d, a, x[k + 6], 23, 0x4881d05);
        a = hh(a, b, c, d, x[k + 9], 4, 0xd9d4d039);
        d = hh(d, a, b, c, x[k + 12], 11, 0xe6db99e5);
        c = hh(c, d, a, b, x[k + 15], 16, 0x1fa27cf8);
        b = hh(b, c, d, a, x[k + 2], 23, 0xc4ac5665);

        a = ii(a, b, c, d, x[k + 0], 6, 0xf4292244);
        d = ii(d, a, b, c, x[k + 7], 10, 0x432aff97);
        c = ii(c, d, a, b, x[k + 14], 15, 0xab9423a7);
        b = ii(b, c, d, a, x[k + 5], 21, 0xfc93a039);
        a = ii(a, b, c, d, x[k + 12], 6, 0x655b59c3);
        d = ii(d, a, b, c, x[k + 3], 10, 0x8f0ccc92);
        c = ii(c, d, a, b, x[k + 10], 15, 0xffeff47d);
        b = ii(b, c, d, a, x[k + 1], 21, 0x85845dd1);
        a = ii(a, b, c, d, x[k + 8], 6, 0x6fa87e4f);
        d = ii(d, a, b, c, x[k + 15], 10, 0xfe2ce6e0);
        c = ii(c, d, a, b, x[k + 6], 15, 0xa3014314);
        b = ii(b, c, d, a, x[k + 13], 21, 0x4e0811a1);
        a = ii(a, b, c, d, x[k + 4], 6, 0xf7537e82);
        d = ii(d, a, b, c, x[k + 11], 10, 0xbd3af235);
        c = ii(c, d, a, b, x[k + 2], 15, 0x2ad7d2bb);
        b = ii(b, c, d, a, x[k + 9], 21, 0xeb86d391);

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
    if (typeof (globalThis as any).window === "undefined") {
      const response = await fetch(url, {
        method: options.method || "GET",
        headers: options.headers || {},
        body: options.body,
        redirect: "manual", // Handle redirects manually to preserve cookies
      });

      const responseText = await response.text();

      // Parse cookies from headers
      // Node.js fetch returns raw headers which may have multiple set-cookie values
      const rawHeaders = (response as any).headers.raw?.();
      if (rawHeaders && rawHeaders["set-cookie"]) {
        this.parseCookies(rawHeaders["set-cookie"]);
      } else {
        const setCookieHeader = response.headers.get("set-cookie");
        if (setCookieHeader) {
          this.parseCookies(setCookieHeader);
        }
      }

      return {
        ok: response.ok,
        status: response.status,
        headers: {
          location: response.headers.get("location"),
        },
        text: async () => responseText,
        json: async () => {
          let jsonStr = responseText;
          // Handle JSONP response format &&&START&&&{...}
          if (jsonStr.includes("&&&START&&&")) {
            jsonStr = jsonStr.replace("&&&START&&&", "");
          }
          return JSON.parse(jsonStr);
        },
      };
    }

    // When running in browser, use proxy
    const response = await fetch("/api/proxy", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url,
        method: options.method || "GET",
        headers: options.headers || {},
        body: options.body,
      }),
    });

    const result = await response.json() as any;
    if (result.error) {
      throw new Error(result.error);
    }

    // Parse cookies from headers
    if (result.headers && result.headers["set-cookie"]) {
      this.parseCookies(result.headers["set-cookie"]);
    }

    return {
      ok: result.status >= 200 && result.status < 300,
      status: result.status,
      headers: result.headers || {},
      text: async () => result.body,
      json: async () => {
        let jsonStr = result.body;
        // Handle JSONP response format &&&START&&&{...}
        if (jsonStr.includes("&&&START&&&")) {
          jsonStr = jsonStr.replace("&&&START&&&", "");
        }
        return JSON.parse(jsonStr);
      },
    };
  }

  private setupInitialCookies(): void {
    // Set up cookies like Python does in login() method
    this.cookies.sdkVersion = "accountsdk-18.8.15";
    this.cookies.deviceId = this.deviceId;
  }

  async loginStep1(): Promise<boolean> {
    // Set up initial cookies before any login steps
    this.setupInitialCookies();
    
    const url = "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true";
    try {
      const response = await this.proxyFetch(url, {
        headers: {
          "User-Agent": this.agent,
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: `userId=${this.username}`,
        },
      });

      const data = await response.json();
      debug.log("[loginStep1] Response data keys:", Object.keys(data));
      if (data && data._sign) {
        this.sign = data._sign;
        debug.log("[loginStep1] Got sign:", this.sign ? 'present' : 'missing');
        return true;
      }
    } catch (error) {
      debug.error("Login step 1 failed:", error);
    }
    return false;
  }

  async loginStep2(): Promise<{ success: boolean; requires2FA?: boolean; verifyUrl?: string; error?: string }> {
    const url = "https://account.xiaomi.com/pass/serviceLoginAuth2";
    const hash = await this.hashPassword(this.password);

    debug.log("[loginStep2] Starting with state:", {
      sign: this.sign ? 'present' : 'missing',
      cookies: Object.keys(this.cookies),
      username: this.username,
      deviceId: this.deviceId
    });

    const fields = {
      sid: "xiaomiio",
      hash: hash,
      callback: "https://sts.api.io.mi.com/sts",
      qs: "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
      user: this.username,
      _sign: this.sign || "",
      _json: "true"
    };
    
    debug.log("[loginStep2] Request fields:", {
      sid: fields.sid,
      user: fields.user,
      hash: fields.hash ? 'present' : 'empty',
      _sign: fields._sign ? 'present' : 'empty'
    });

    try {
      const response = await this.proxyFetch(url, {
        method: "POST",
        headers: {
          "User-Agent": this.agent,
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: this.buildCookieString(),
        },
        body: new URLSearchParams(fields).toString(),
      });

      if (!response.ok) {
        debug.error("Login step 2 HTTP error:", response.status);
        const text = await response.text();
        debug.error("Response text:", text);
        return { success: false, error: `HTTP ${response.status}` };
      }

      const data = await response.json();
      debug.log("[loginStep2] Response:", {
        code: data.code,
        securityStatus: data.securityStatus,
        hasNotificationUrl: !!data.notificationUrl,
        hasLocation: !!data.location,
        hasSSecurity: !!data.ssecurity,
        hasCookies: Object.keys(this.cookies)
      });

      // Check if ssecurity is present and valid (like Python line 140)
      const hasValidSSecurity = data.ssecurity && data.ssecurity.length > 4;
      
      if (hasValidSSecurity) {
        // Extract all values like Python does (lines 142-147)
        this.ssecurity = data.ssecurity;
        this.userId = data.userId;
        this.cUserId = data.cUserId;
        this.passToken = data.passToken;
        this.location = data.location;
        this.code = data.code;

        debug.log("[loginStep2] Login successful, extracted data:", {
          userId: this.userId,
          hasLocation: !!this.location,
          hasSSecurity: !!this.ssecurity,
          ssecurity: this.ssecurity ? 'present' : 'missing',
          cookies: Object.keys(this.cookies)
        });
        
        return { success: true };
      } else {
        // Check for 2FA requirement like Python (line 149)
        if (data.notificationUrl) {
          this.verifyUrl = data.notificationUrl;
          return { success: false, requires2FA: true, verifyUrl: this.verifyUrl || undefined };
        }
        
        debug.log("[loginStep2] Login failed - no ssecurity or notificationUrl");
        return { success: false, error: data.desc || "Login failed" };
      }
    } catch (error: any) {
      debug.error("Login step 2 failed:", error);
      return { success: false, error: error.message };
    }
  }

  async checkIdentityOptions(): Promise<boolean> {
    if (!this.verifyUrl) {
      debug.error("No verify URL available");
      return false;
    }

    debug.log("[checkIdentityOptions] Checking from URL:", this.verifyUrl);
    debug.log("[checkIdentityOptions] Current cookies before:", Object.keys(this.cookies));

    try {
      // Replace 'identity/authStart' with 'identity/list' as per Python implementation
      const listUrl = this.verifyUrl.replace("identity/authStart", "identity/list");
      debug.log("[checkIdentityOptions] Fetching identity list from:", listUrl);

      const response = await this.proxyFetch(listUrl, {
        headers: {
          "User-Agent": this.agent,
          Cookie: this.buildCookieString(),
        },
      });

      const text = await response.text();
      debug.log("[checkIdentityOptions] Response preview:", text.substring(0, 200));
      debug.log("[checkIdentityOptions] Cookies after request:", Object.keys(this.cookies));

      // Extract identity_session cookie
      if (this.cookies.identity_session) {
        this.identitySession = this.cookies.identity_session;
        debug.log("[checkIdentityOptions] Got identity_session:", this.identitySession ? 'present' : 'missing');
      }

      try {
        // Remove &&&START&&& if present (as per Python: resp.text.replace('&&&START&&&', ''))
        const cleanText = text.replace("&&&START&&&", "");
        const data = JSON.parse(cleanText);

        // Extract flag and options as per Python:
        // flag = data.get('flag', 4)
        // options = data.get('options', [flag])
        const flag = data.flag || 4;
        this.identityOptions = data.options || [flag];

        // console.log("Identity options from API:", this.identityOptions);
        return true;
      } catch (e) {
        debug.error("Failed to parse identity list response:", e);
        // Default to phone (4) if parsing fails
        this.identityOptions = [4];
        return true;
      }
    } catch (error) {
      debug.error("Failed to check identity options:", error);
      // Default to phone (4) if request fails
      this.identityOptions = [4];
      return true;
    }
  }

  async verify2FATicket(ticket: string): Promise<{ success: boolean; error?: string }> {
    debug.log("[verify2FATicket] Called with ticket:", ticket ? 'present' : 'missing');
    debug.log("[verify2FATicket] Initial state:", {
      identityOptions: this.identityOptions,
      identitySession: this.identitySession ? 'present' : 'missing',
      cookies: Object.keys(this.cookies),
      sign: this.sign ? 'present' : 'missing'
    });

    // First, check identity options if we haven't already
    if (this.identityOptions.length === 0) {
      await this.checkIdentityOptions();
    }

    // Try each verification method
    for (const flag of this.identityOptions) {
      const api = flag === 4 ? "/identity/auth/verifyPhone" : flag === 8 ? "/identity/auth/verifyEmail" : null;

      if (!api) continue;

      const url = `https://account.xiaomi.com${api}`;
      const data = new URLSearchParams({
        _flag: flag.toString(),
        ticket: ticket,
        trust: "true",
        _json: "true",
      });

      const params = new URLSearchParams({
        _dc: Date.now().toString(),
      });

      const fullUrl = `${url}?${params}`;
      // console.log(`Trying verification with flag ${flag}:`, fullUrl);

      try {
        const cookieString =
          this.buildCookieString() + (this.identitySession ? `; identity_session=${this.identitySession}` : "");

        const response = await this.proxyFetch(fullUrl, {
          method: "POST",
          headers: {
            "User-Agent": this.agent,
            "Content-Type": "application/x-www-form-urlencoded",
            Cookie: cookieString,
          },
          body: data.toString(),
        });

        // console.log(`Verification response status (flag ${flag}):`, response.status);

        const result = await response.json();
        // console.log(`Verification response data (flag ${flag}):`, result);

        if (result && result.code === 0) {
          debug.log(`[verify2FATicket] Success with flag ${flag}!`);
          
          // Follow location if provided (as in Python implementation)
          if (result.location) {
            debug.log("[verify2FATicket] Following redirect chain starting from:", result.location);
            
            let currentUrl = result.location;
            let redirectCount = 0;
            const maxRedirects = 5;
            
            try {
              // Follow redirect chain like Python's session.get() does
              while (redirectCount < maxRedirects) {
                const response = await this.proxyFetch(currentUrl, {
                  headers: {
                    "User-Agent": this.agent,
                    Cookie: this.buildCookieString(),
                  },
                });
                
                // Parse cookies from each response
                if (response.headers?.["set-cookie"]) {
                  this.parseCookies(response.headers["set-cookie"]);
                }
                
                debug.log(`[verify2FATicket] Redirect ${redirectCount + 1} status:`, response.status);
                debug.log(`[verify2FATicket] Redirect ${redirectCount + 1} cookies:`, Object.keys(this.cookies));
                
                // Check if there's another redirect
                if (response.status >= 300 && response.status < 400 && response.headers?.location) {
                  // Handle relative URLs
                  const redirectLocation = response.headers.location;
                  if (redirectLocation.startsWith('http')) {
                    currentUrl = redirectLocation;
                  } else {
                    // Relative URL - construct full URL
                    const baseUrl = new URL(currentUrl);
                    currentUrl = new URL(redirectLocation, `${baseUrl.protocol}//${baseUrl.host}`).toString();
                  }
                  debug.log(`[verify2FATicket] Following next redirect to:`, currentUrl);
                  redirectCount++;
                } else {
                  // No more redirects, we're done
                  debug.log("[verify2FATicket] Redirect chain complete");
                  debug.log("[verify2FATicket] Final cookies:", Object.keys(this.cookies));
                  
                  // Extract important values from final URL if it's the STS callback
                  if (currentUrl.includes('sts.api.io.mi.com/sts')) {
                    const urlObj = new URL(currentUrl);
                    const nonce = urlObj.searchParams.get('nonce');
                    if (nonce) {
                      debug.log("[verify2FATicket] Found nonce in STS URL:", nonce ? 'present' : 'missing');
                      // Note: This nonce is NOT the ssecurity - ssecurity comes from loginStep2
                    }
                  }
                  break;
                }
              }
              
              if (redirectCount >= maxRedirects) {
                debug.error("[verify2FATicket] Too many redirects");
              }
            } catch (e) {
              debug.log("[verify2FATicket] Redirect follow error:", e);
            }
          }
          
          // Clear identity session as per Python: self._identity_session = None
          this.identitySession = null;
          
          // Extract important values from cookies after redirect chain
          if (this.cookies.userId) {
            this.userId = this.cookies.userId;
            debug.log("[verify2FATicket] Extracted userId from cookies:", this.userId);
          }
          if (this.cookies.serviceToken) {
            this.serviceToken = this.cookies.serviceToken;
            debug.log("[verify2FATicket] Extracted serviceToken from cookies");
          }
          if (this.cookies.passToken) {
            this.passToken = this.cookies.passToken;
          }
          if (this.cookies.cUserId) {
            this.cUserId = this.cookies.cUserId;
          }
          
          return { success: true };
        }
      } catch (error) {
        debug.error(`Verification failed for flag ${flag}:`, error);
      }
    }

    return { success: false, error: "Invalid verification code" };
  }

  async loginStep3(): Promise<boolean> {
    if (!this.location) {
      debug.error("Login step 3: No location URL");
      return false;
    }

    try {
      // Match Python exactly - just make a GET request
      const response = await this.proxyFetch(this.location, {
        headers: {
          "User-Agent": this.agent,
          "Content-Type": "application/x-www-form-urlencoded",
        },
      });

      // Python checks status_code == 200
      if (response.ok) {
        // Extract serviceToken from cookies
        if (this.cookies.serviceToken) {
          this.serviceToken = this.cookies.serviceToken;
          return true;
        } else {
          debug.error("Login step 3: No serviceToken in cookies");
          return false;
        }
      } else {
        debug.error("Login step 3: HTTP error:", response.status);
        return false;
      }
    } catch (error) {
      debug.error("Login step 3 failed:", error);
      return false;
    }
  }

  private parseCookies(cookieString: string | string[]): void {
    const cookieStrings = Array.isArray(cookieString) ? cookieString : [cookieString];
    const newCookies: Record<string, string> = {};

    cookieStrings.forEach((cookieStr) => {
      // Handle comma-separated cookies from proxy
      const individualCookies = cookieStr.split(/,(?=\s*\w+=)/);
      
      individualCookies.forEach((cookie) => {
        // Parse each Set-Cookie header
        const parts = cookie.trim().split(";");
        const [keyValue] = parts;
        if (!keyValue) return;
        
        const [key, value] = keyValue.trim().split("=");

        if (key && value) {
          // Special handling for deviceId - don't override our original deviceId with wb_* values
          if (key === 'deviceId' && value.startsWith('wb_') && this.deviceId && !this.deviceId.startsWith('wb_')) {
            debug.log(`[parseCookies] Ignoring wb_* deviceId, keeping original`);
            return;
          }
          
          // Don't set cookies with value 'EXPIRED'
          if (value === 'EXPIRED') {
            debug.log(`[parseCookies] Ignoring expired cookie: ${key}`);
            delete this.cookies[key];
            return;
          }
          
          this.cookies[key] = value;
          newCookies[key] = value;
        }
      });
    });
    
    if (Object.keys(newCookies).length > 0) {
      debug.log("[parseCookies] New cookies set:", Object.keys(newCookies));
      debug.log("[parseCookies] Cookie values:", Object.keys(newCookies).reduce((acc, key) => {
        // Sanitize sensitive cookie values
        if (['serviceToken', 'passToken', 'identity_session'].includes(key)) {
          acc[key] = 'present';
        } else if (key === 'userId' || key === 'cUserId' || key === 'deviceId') {
          acc[key] = newCookies[key]; // These are safe to log
        } else {
          acc[key] = newCookies[key].substring(0, 8) + '...';
        }
        return acc;
      }, {} as Record<string, string>));
    }
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
    let binary = "";
    for (let i = 0; i < nonceBytes.length; i++) {
      binary += String.fromCharCode(nonceBytes[i]);
    }
    return btoa(binary);
  }

  private async signedNonce(nonce: string): Promise<string> {
    if (!this.ssecurity) {
      debug.error("No ssecurity available for signing");
      throw new Error("Missing ssecurity");
    }

    debug.log("[signedNonce] Signing with ssecurity:", this.ssecurity ? 'present' : 'missing');
    debug.log("[signedNonce] Nonce to sign:", nonce ? 'present' : 'missing');

    try {
      // Python: hashlib.sha256(base64.b64decode(self._ssecurity) + base64.b64decode(nonce))
      // Decode both ssecurity and nonce from base64
      let ssecurityBytes: Uint8Array;
      try {
        ssecurityBytes = Uint8Array.from(atob(this.ssecurity), (c) => c.charCodeAt(0));
      } catch (e) {
        debug.error("[signedNonce] Failed to decode ssecurity as base64, might not be encoded:", e);
        throw new Error("Invalid ssecurity encoding");
      }
      
      const nonceBytes = Uint8Array.from(atob(nonce), (c) => c.charCodeAt(0));

      // Concatenate the byte arrays
      const combined = new Uint8Array(ssecurityBytes.length + nonceBytes.length);
      combined.set(ssecurityBytes, 0);
      combined.set(nonceBytes, ssecurityBytes.length);

      const hashBuffer = await crypto.subtle.digest("SHA-256", combined);
      const hashArray = new Uint8Array(hashBuffer);

      // Convert to base64
      let binary = "";
      for (let i = 0; i < hashArray.length; i++) {
        binary += String.fromCharCode(hashArray[i]);
      }
      return btoa(binary);
    } catch (error) {
      debug.error("Error in signedNonce:", error);
      throw error;
    }
  }

  private encryptRC4(password: string, payload: string): string {
    // Python: r.encrypt(bytes(1024)) then r.encrypt(payload.encode())
    const keyBytes = Uint8Array.from(atob(password), (c) => c.charCodeAt(0));
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
    try {
      // Python: r.encrypt(bytes(1024)) then r.encrypt(base64.b64decode(payload))
      const keyBytes = Uint8Array.from(atob(password), (c) => c.charCodeAt(0));
      const rc4 = new RC4(keyBytes);

      // Discard first 1024 bytes
      rc4.encrypt(new Uint8Array(1024));

      // The payload might not be base64 encoded, try to decode it
      let encryptedBytes: Uint8Array;
      try {
        // Try base64 decode first
        encryptedBytes = Uint8Array.from(atob(payload), (c) => c.charCodeAt(0));
      } catch (e) {
        // If base64 decode fails, treat as raw bytes
        encryptedBytes = new TextEncoder().encode(payload);
      }
      
      const decrypted = rc4.decrypt(encryptedBytes);

      // Convert to string
      return new TextDecoder().decode(decrypted);
    } catch (error) {
      debug.error("Decryption error:", error);
      debug.error("Payload length:", payload.length);
      debug.error("Payload preview:", payload.substring(0, 100));
      throw error;
    }
  }

  private async generateEncSignature(
    url: string,
    method: string,
    signedNonce: string,
    params: Record<string, any>
  ): Promise<string> {
    // Python: signature_params = [str(method).upper(), url.split("com")[1].replace("/app/", "/")]
    const urlPath = url.split("com")[1].replace("/app/", "/");
    const signatureParams = [method.toUpperCase(), urlPath];

    // Add sorted params
    Object.keys(params)
      .sort()
      .forEach((k) => {
        signatureParams.push(`${k}=${params[k]}`);
      });

    signatureParams.push(signedNonce);
    const signString = signatureParams.join("&");

    // SHA1 hash and base64 encode
    const encoder = new TextEncoder();
    const data = encoder.encode(signString);

    // Use SubtleCrypto for SHA1
    const hashBuffer = await crypto.subtle.digest("SHA-1", data);
    const hashArray = new Uint8Array(hashBuffer);

    // Convert to base64
    let binary = "";
    for (let i = 0; i < hashArray.length; i++) {
      binary += String.fromCharCode(hashArray[i]);
    }
    return btoa(binary);
  }

  private async generateSignature(
    url: string,
    signedNonce: string,
    nonce: string,
    params?: Record<string, any>
  ): Promise<string> {
    try {
      // Python: signature_params = [url.split("com")[1], signed_nonce, nonce]
      const urlPath = url.split(".com")[1] || url;
      const signatureParams = [urlPath, signedNonce, nonce];

      // Add params as key=value pairs (sorted by key)
      if (params) {
        Object.keys(params)
          .sort()
          .forEach((k) => {
            signatureParams.push(`${k}=${params[k]}`);
          });
      }

      const signString = signatureParams.join("&");
      // console.log("Sign string:", signString);

      // Use signedNonce as HMAC key (decoded from base64)
      const keyData = Uint8Array.from(atob(signedNonce), (c) => c.charCodeAt(0));

      const key = await crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);

      const encoder = new TextEncoder();
      const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(signString));

      // Convert to base64
      const signatureArray = new Uint8Array(signature);
      let binary = "";
      for (let i = 0; i < signatureArray.length; i++) {
        binary += String.fromCharCode(signatureArray[i]);
      }

      return btoa(binary);
    } catch (error) {
      debug.error("Error generating signature:", error);
      throw error;
    }
  }

  async getDevices(server: string = "cn"): Promise<{ success: boolean; devices?: Device[]; error?: string }> {
    try {
      // console.log("\n=== Getting devices using encrypted API ===");

      await this.reportProgress({ message: "Getting homes...", step: "homes" });

      const allHomes: Array<{ home_id: string; home_owner: string; name?: string }> = [];

      // First get homes
      const homes = await this.getHomes(server);
      if (homes.success && homes.homes) {
        for (const h of homes.homes) {
          allHomes.push({ home_id: h.id, home_owner: this.userId!, name: h.name });
        }
      }

      // Also get shared homes
      await this.reportProgress({ message: "Checking shared homes...", step: "shared" });
      const devCnt = await this.getDeviceCountDetails(server);
      if (devCnt.success && devCnt.shareFamilies) {
        for (const h of devCnt.shareFamilies) {
          allHomes.push({ home_id: h.home_id, home_owner: h.home_owner });
        }
      }

      // console.log(`Found ${allHomes.length} total homes (owned + shared)`);
      await this.reportProgress({
        message: `Found ${allHomes.length} home(s)`,
        step: "homes_complete",
        totalHomes: allHomes.length,
      });

      if (allHomes.length === 0) {
        return { success: true, devices: [] };
      }

      const allDevices: Device[] = [];

      // Get devices for each home
      for (let i = 0; i < allHomes.length; i++) {
        const home = allHomes[i];
        await this.reportProgress({
          message: `Getting devices from home ${i + 1}/${allHomes.length}${home.name ? ` (${home.name})` : ""}...`,
          step: "devices",
          currentHome: i + 1,
          totalHomes: allHomes.length,
        });

        const devices = await this.getHomeDevices(server, home.home_id, home.home_owner);
        if (devices.success && devices.devices) {
          // Stream devices as they come
          for (const device of devices.devices) {
            allDevices.push(device);
            await this.reportProgress({
              message: `Found device: ${device.name}`,
              step: "device_found",
              device,
              totalDevices: allDevices.length,
            });
          }
        }
      }

      // console.log(`Total devices found: ${allDevices.length}`);
      return { success: true, devices: allDevices };
    } catch (error: any) {
      debug.error("Get devices failed:", error);
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
      data: '{"fg": true, "fetch_share": true, "fetch_share_dev": true, "limit": 300, "app_ver": 7}',
    };

    const result = await this.executeApiCallEncrypted(url, params);
    if (result && result.code === 0) {
      const homes = result.result?.homelist || [];
      // console.log(`Got ${homes.length} homes from server ${server}`);
      return { success: true, homes };
    }

    return { success: false, error: result?.message || "Failed to get homes" };
  }

  private async getHomeDevices(
    server: string,
    homeId: string,
    ownerId: string
  ): Promise<{ success: boolean; devices?: Device[]; error?: string }> {
    const url = this.getApiUrl(server) + "/v2/home/home_device_list";
    const params = {
      data: `{"home_owner": ${ownerId}, "home_id": ${homeId}, "limit": 200, "get_split_device": true, "support_smart_home": true}`,
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
          extra: d.extra || {},
        };

        // Check if this is a Bluetooth device and fetch BLE key
        if (d.did && d.did.includes("blt")) {
          await this.reportProgress({
            message: `Fetching BLE key for ${d.name}...`,
            step: "ble_key",
            deviceName: d.name,
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
    return server === "cn" ? "https://api.io.mi.com/app" : `https://${server}.api.io.mi.com/app`;
  }

  private async executeApiCallEncrypted(url: string, params: Record<string, any>): Promise<any> {
    debug.log("[executeApiCallEncrypted] Called with URL:", url);
    debug.log("[executeApiCallEncrypted] Current auth state:", {
      ssecurity: this.ssecurity ? 'present' : 'missing',
      userId: this.userId,
      serviceToken: this.serviceToken ? 'present' : 'missing'
    });
    
    const nonce = this.generateNonce();
    const signedNonce = await this.signedNonce(nonce);

    // Generate encrypted params
    const encParams = await this.generateEncParams(url, "POST", signedNonce, nonce, params);

    const headers = {
      "Accept-Encoding": "identity",
      "User-Agent": this.agent,
      "Content-Type": "application/x-www-form-urlencoded",
      "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
      "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
      Cookie: this.buildCookieString(),
    };

    const queryString = new URLSearchParams(encParams).toString();
    // console.log(`Making encrypted request to: ${url}`);

    try {
      const response = await this.proxyFetch(`${url}?${queryString}`, {
        method: "POST",
        headers,
      });

      const responseText = await response.text();
      // console.log('Encrypted response received, length:', responseText.length);

      // Check if response is an error
      if (!response.ok) {
        debug.error("API error response:", response.status, responseText);
        throw new Error(`API request failed: ${response.status}`);
      }

      // Decrypt response
      const decrypted = this.decryptRC4(signedNonce, responseText);
      // console.log('Decrypted response:', decrypted.substring(0, 200));

      try {
        return JSON.parse(decrypted);
      } catch (e) {
        debug.error("Failed to parse decrypted response:", decrypted.substring(0, 200));
        throw new Error("Invalid response format");
      }
    } catch (error: any) {
      debug.error("Encrypted API call failed:", error);
      throw error;
    }
  }

  private async generateEncParams(
    url: string,
    method: string,
    signedNonce: string,
    nonce: string,
    params: Record<string, any>
  ): Promise<Record<string, string>> {
    // First add rc4_hash__
    const tempParams = { ...params };
    tempParams["rc4_hash__"] = await this.generateEncSignature(url, method, signedNonce, tempParams);

    // Encrypt all params
    const encryptedParams: Record<string, string> = {};
    for (const [k, v] of Object.entries(tempParams)) {
      encryptedParams[k] = this.encryptRC4(signedNonce, String(v));
    }

    // Generate final signature with encrypted params
    encryptedParams["signature"] = await this.generateEncSignature(url, method, signedNonce, encryptedParams);
    encryptedParams["ssecurity"] = this.ssecurity!;
    encryptedParams["_nonce"] = nonce;

    return encryptedParams;
  }

  private buildCookieString(): string {
    const cookieEntries = [];

    // Add userId if available (from either this.userId or cookies)
    const userId = this.userId || this.cookies.userId;
    if (userId && userId !== 'EXPIRED') {
      cookieEntries.push(`userId=${userId}`);
    }

    // Add serviceToken if available
    if (this.serviceToken || this.cookies.serviceToken) {
      const token = this.serviceToken || this.cookies.serviceToken;
      cookieEntries.push(`serviceToken=${token}`);
      cookieEntries.push(`yetAnotherServiceToken=${token}`);
    }
    
    // Add passToken if available
    const passToken = this.passToken || this.cookies.passToken;
    if (passToken && passToken !== 'EXPIRED') {
      cookieEntries.push(`passToken=${passToken}`);
    }
    
    // Add cUserId if available
    const cUserId = this.cUserId || this.cookies.cUserId;
    if (cUserId && cUserId !== 'EXPIRED') {
      cookieEntries.push(`cUserId=${cUserId}`);
    }

    // Add additional cookies as per Python implementation
    cookieEntries.push("locale=en_GB");
    cookieEntries.push("timezone=GMT+02:00");
    cookieEntries.push("is_daylight=1");
    cookieEntries.push("dst_offset=3600000");
    cookieEntries.push("channel=MI_APP_STORE");
    cookieEntries.push("sdkVersion=accountsdk-18.8.15");
    cookieEntries.push(`deviceId=${this.deviceId}`);

    // Add any other cookies (but skip EXPIRED ones)
    Object.entries(this.cookies).forEach(([key, value]) => {
      if (
        ![
          "userId",
          "serviceToken",
          "yetAnotherServiceToken",
          "passToken",
          "cUserId",
          "locale",
          "timezone",
          "is_daylight",
          "dst_offset",
          "channel",
          "sdkVersion",
          "deviceId",
        ].includes(key) &&
        value !== "EXPIRED"
      ) {
        cookieEntries.push(`${key}=${value}`);
      }
    });

    const cookieString = cookieEntries.join("; ");
    debug.log("[buildCookieString] Final cookie string keys:", cookieEntries.map(c => c.split('=')[0]));
    return cookieString;
  }

  getSessionData(): SessionData {
    return {
      username: this.username,
      userId: this.userId!,
      serviceToken: this.serviceToken!,
      ssecurity: this.ssecurity!,
      cookies: this.cookies,
      deviceId: this.deviceId,
      savedAt: new Date().toISOString(),
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

  // Get full client state for stateless operation
  getClientState(): any {
    return {
      // Credentials
      username: this.username,
      password: this.password,
      
      // Device info
      agent: this.agent,
      deviceId: this.deviceId,
      
      // Session tokens
      cookies: this.cookies,
      sign: this.sign,
      ssecurity: this.ssecurity,
      userId: this.userId,
      cUserId: this.cUserId,
      passToken: this.passToken,
      location: this.location,
      code: this.code,
      serviceToken: this.serviceToken,
      
      // 2FA state
      verifyUrl: this.verifyUrl,
      identitySession: this.identitySession,
      identityOptions: this.identityOptions
    };
  }

  // Restore full client state from browser storage
  static fromClientState(state: any): XiaomiCloudConnectorBrowser {
    const client = new XiaomiCloudConnectorBrowser(state.username, state.password);
    
    // Restore device info
    client.agent = state.agent;
    client.deviceId = state.deviceId;
    
    // Restore session tokens
    client.cookies = state.cookies || {};
    client.sign = state.sign;
    client.ssecurity = state.ssecurity;
    client.userId = state.userId;
    client.cUserId = state.cUserId;
    client.passToken = state.passToken;
    client.location = state.location;
    client.code = state.code;
    client.serviceToken = state.serviceToken;
    
    // Restore 2FA state
    client.verifyUrl = state.verifyUrl;
    client.identitySession = state.identitySession;
    client.identityOptions = state.identityOptions || [];
    
    return client;
  }

  async validateSession(): Promise<boolean> {
    // console.log("Validating session - serviceToken:", this.serviceToken ? "present" : "missing");
    // console.log("Validating session - ssecurity:", this.ssecurity ? "present" : "missing");
    // console.log("Validating session - userId:", this.userId);

    if (!this.serviceToken || !this.ssecurity) {
      debug.error("Missing required tokens for validation");
      return false;
    }

    try {
      // Use get_dev_cnt like Python for validation
      const result = await this.getDeviceCount("cn");
      return result.success;
    } catch (error) {
      debug.error("Session validation error:", error);
      return false;
    }
  }

  private async getDeviceCount(server: string): Promise<{ success: boolean; error?: string }> {
    const url = this.getApiUrl(server) + "/v2/user/get_device_cnt";
    const params = {
      data: '{ "fetch_own": true, "fetch_share": true}',
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

  private async getDeviceCountDetails(
    server: string
  ): Promise<{ success: boolean; shareFamilies?: any[]; error?: string }> {
    const url = this.getApiUrl(server) + "/v2/user/get_device_cnt";
    const params = {
      data: '{ "fetch_own": true, "fetch_share": true}',
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

  private async getBeaconKey(
    server: string,
    did: string
  ): Promise<{ beaconkey?: string; beaconkey_block4?: string } | null> {
    const url = this.getApiUrl(server) + "/v2/device/blt_get_beaconkey";
    const params = {
      data: `{"did":"${did}","pdid":1}`,
    };

    try {
      const result = await this.executeApiCallEncrypted(url, params);
      if (result && result.code === 0 && result.result) {
        return {
          beaconkey: result.result.beaconkey,
          beaconkey_block4: result.result.beaconkey_block4,
        };
      }
      return null;
    } catch (error: any) {
      debug.error(`Failed to get beacon key for ${did}:`, error.message);
      return null;
    }
  }
}
