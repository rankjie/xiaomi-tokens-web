export interface LoginCredentials {
  username: string;
  password: string;
  server?: string;
}

export interface SessionData {
  username: string;
  userId: string;
  serviceToken: string;
  ssecurity: string;
  cookies: Record<string, string>;
  deviceId: string;
  savedAt: string;
}

export interface Device {
  did: string;
  name: string;
  model: string;
  token: string;
  ip?: string;
  mac?: string;
  ssid?: string;
  bssid?: string;
  rssi?: number;
  isOnline: boolean;
  desc?: string;
  extra?: Record<string, any>;
}

export interface LoginResponse {
  success: boolean;
  requires2FA?: boolean;
  verifyUrl?: string;
  error?: string;
  session?: SessionData;
  clientState?: any; // Full client state for stateless operation
}

export interface DevicesResponse {
  success: boolean;
  devices?: Device[];
  error?: string;
}