import { SessionData, Device } from './types';

export class XiaomiCloudConnector {
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

  constructor(username: string, password: string) {
    this.username = username;
    this.password = password;
    this.agent = this.generateAgent();
    this.deviceId = this.generateDeviceId();
  }

  private generateAgent(): string {
    const agents = [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ];
    return agents[Math.floor(Math.random() * agents.length)];
  }

  private generateDeviceId(): string {
    const chars = "ABCDEF0123456789";
    let deviceId = "";
    for (let i = 0; i < 16; i++) {
      deviceId += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return deviceId;
  }

  private async hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('MD5', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  async loginStep1(): Promise<boolean> {
    const url = "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true";
    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'User-Agent': this.agent,
          'Accept': 'application/json',
          'Cookie': `userId=${this.username}`
        },
        credentials: 'omit' // Don't send credentials cross-origin
      });
      
      if (!response.ok) {
        console.error(`Login step 1 HTTP error: ${response.status}`);
        return false;
      }
      
      const text = await response.text();
      // Handle JSONP response format &&&START&&&{...}
      let jsonStr = text;
      if (text.includes('&&&START&&&')) {
        jsonStr = text.replace('&&&START&&&', '');
      }
      
      const data = JSON.parse(jsonStr);
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
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'User-Agent': this.agent,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams(fields).toString()
      });
      
      const data = await response.json();
      
      if (data.code === 0) {
        this.ssecurity = data.ssecurity;
        this.userId = data.userId;
        this.cUserId = data.cUserId;
        this.passToken = data.passToken;
        this.location = data.location;
        this.code = data.code;
        
        // Extract cookies from response
        const setCookieHeader = response.headers.get('set-cookie');
        if (setCookieHeader) {
          this.parseCookies(setCookieHeader);
        }
        
        return { success: true };
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

  async verify2FATicket(ticket: string): Promise<{ success: boolean; error?: string }> {
    const url = "https://account.xiaomi.com/pass/serviceLogin";
    const params = new URLSearchParams({
      sid: "xiaomiio",
      _json: "true",
      passive: "false",
      hidden: "false",
      ticket: ticket
    });

    try {
      const response = await fetch(`${url}?${params}`, {
        headers: {
          'User-Agent': this.agent
        }
      });
      const data = await response.json();
      
      if (data && data.ssecurity) {
        this.ssecurity = data.ssecurity;
        this.userId = data.userId;
        this.cUserId = data.cUserId;
        this.passToken = data.passToken;
        this.location = data.location;
        
        // Extract cookies
        const setCookieHeader = response.headers.get('set-cookie');
        if (setCookieHeader) {
          this.parseCookies(setCookieHeader);
        }
        
        return { success: true };
      }
      return { success: false, error: "Invalid verification code" };
    } catch (error: any) {
      console.error("2FA verification failed:", error);
      return { success: false, error: error.message };
    }
  }

  async loginStep3(): Promise<boolean> {
    if (!this.location) {
      return false;
    }

    try {
      const response = await fetch(this.location, {
        headers: {
          'User-Agent': this.agent
        }
      });
      
      const setCookieHeader = response.headers.get('set-cookie');
      if (setCookieHeader) {
        this.parseCookies(setCookieHeader);
      }
      
      // Extract serviceToken from cookies
      if (this.cookies.serviceToken) {
        this.serviceToken = this.cookies.serviceToken;
        return true;
      }
    } catch (error) {
      console.error("Login step 3 failed:", error);
    }
    return false;
  }

  private parseCookies(cookieString: string): void {
    const cookies = cookieString.split(';');
    cookies.forEach(cookie => {
      const [key, value] = cookie.trim().split('=');
      if (key && value) {
        this.cookies[key] = value;
      }
    });
  }

  private generateNonce(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let nonce = '';
    for (let i = 0; i < 16; i++) {
      nonce += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return nonce;
  }

  private async signedNonce(nonce: string): Promise<string> {
    const ssecurityDecoded = atob(this.ssecurity!);
    const encoder = new TextEncoder();
    const data = encoder.encode(ssecurityDecoded + nonce);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
  }

  private async generateSignature(method: string, path: string, signedNonce: string, params?: Record<string, any>): Promise<string> {
    const signData = [method.toUpperCase(), path];
    
    if (params) {
      const sortedParams = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
      signData.push(sortedParams);
    }
    
    signData.push(signedNonce);
    const signString = signData.join('&');
    
    const keyDecoded = atob(signedNonce);
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(keyDecoded),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(signString)
    );
    
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
  }

  async getDevices(server: string = 'cn'): Promise<{ success: boolean; devices?: Device[]; error?: string }> {
    const baseUrl = server === 'cn' ? 'https://api.io.mi.com/app' : `https://${server}.api.io.mi.com/app`;
    const path = '/home/device_list';
    const params = {
      getVirtualModel: false,
      getHuamiDevices: 0
    };

    const nonce = this.generateNonce();
    const signedNonce = await this.signedNonce(nonce);
    const signature = await this.generateSignature('GET', path, signedNonce, params);

    const url = `${baseUrl}${path}`;
    const headers = {
      'User-Agent': this.agent,
      'x-xiaomi-protocal-flag-cli': 'PROTOCAL-HTTP2',
      'Cookie': this.buildCookieString()
    };

    const fullParams = new URLSearchParams({
      ...params,
      signature,
      _nonce: nonce
    } as any);

    try {
      const response = await fetch(`${url}?${fullParams}`, { headers });
      const data = await response.json();
      
      if (data.code === 0) {
        return { success: true, devices: data.result.list || [] };
      } else {
        return { success: false, error: data.message || "Failed to get devices" };
      }
    } catch (error: any) {
      console.error("Get devices failed:", error);
      return { success: false, error: error.message };
    }
  }

  private buildCookieString(): string {
    const cookieEntries = [
      `userId=${this.userId}`,
      `serviceToken=${this.serviceToken}`,
      `yetAnotherServiceToken=${this.serviceToken}`
    ];
    
    // Add any other cookies
    Object.entries(this.cookies).forEach(([key, value]) => {
      if (!['userId', 'serviceToken', 'yetAnotherServiceToken'].includes(key)) {
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
    if (!this.serviceToken || !this.ssecurity) {
      return false;
    }

    try {
      const result = await this.getDevices('cn');
      return result.success;
    } catch (error) {
      return false;
    }
  }
}