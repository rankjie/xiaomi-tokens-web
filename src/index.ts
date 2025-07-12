import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { XiaomiCloudConnector } from './xiaomi-client';
import { XiaomiCloudConnectorBrowser } from './xiaomi-client-browser';
import type { LoginCredentials, LoginResponse, DevicesResponse, SessionData } from './types';
import { debug } from './utils/debug';
import { exists } from './utils/sanitize';

const app = new Hono();

// Enable CORS for all routes
app.use('/*', cors());

// Proxy endpoint for Xiaomi API calls
app.post('/api/proxy', async (c) => {
  try {
    const { url, method = 'GET', headers = {}, body } = await c.req.json();
    
    const fetchOptions: RequestInit = {
      method,
      headers: {
        ...headers,
        // Remove host header to avoid conflicts
        'host': undefined
      },
      redirect: 'manual' // Handle redirects manually to preserve cookies
    };
    
    // Handle body based on content type
    if (body && method !== 'GET') {
      if (headers['Content-Type']?.includes('application/x-www-form-urlencoded')) {
        fetchOptions.body = body; // Already form-encoded
      } else {
        fetchOptions.body = JSON.stringify(body);
      }
    }
    
    // Collect all cookies from redirect chain
    const allCookies: string[] = [];
    let currentUrl = url;
    let redirectCount = 0;
    const maxRedirects = 10;
    
    while (redirectCount < maxRedirects) {
      const response = await fetch(currentUrl, fetchOptions);
      
      // Collect cookies from this response
      const setCookieHeaders = response.headers.getAll ? 
        response.headers.getAll('set-cookie') : 
        [response.headers.get('set-cookie')].filter(Boolean);
      
      setCookieHeaders.forEach(cookie => {
        if (cookie) allCookies.push(cookie);
      });
      
      // Check if we need to follow a redirect
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (location) {
          // Handle relative redirects
          currentUrl = new URL(location, currentUrl).toString();
          redirectCount++;
          continue;
        }
      }
      
      // Final response
      const responseText = await response.text();
      const responseHeaders: Record<string, string> = {};
      
      // Include location header if present
      const locationHeader = response.headers.get('location');
      if (locationHeader) {
        responseHeaders['location'] = locationHeader;
      }
      
      // Include all collected cookies
      if (allCookies.length > 0) {
        responseHeaders['set-cookie'] = allCookies.join(', ');
      }
      
      return c.json({
        status: response.status,
        headers: responseHeaders,
        body: responseText
      });
    }
    
    throw new Error('Too many redirects');
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// Serve the HTML interface
app.get('/', (c) => {
  return c.html(getHtmlContent());
});

// Serve favicon
app.get('/favicon.svg', (c) => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" fill="none">
  <!-- Background -->
  <rect width="48" height="48" rx="10" fill="#000000"/>
  
  <!-- Mi Logo inspired design -->
  <path d="M12 16h8v16h-8z" fill="#FF6900"/>
  <path d="M22 20h6v12h-6z" fill="#FF6900"/>
  <path d="M30 24h6v8h-6z" fill="#FF6900"/>
  
  <!-- Key symbol overlay -->
  <circle cx="34" cy="14" r="4" fill="none" stroke="#FFFFFF" stroke-width="2"/>
  <path d="M34 18v6" stroke="#FFFFFF" stroke-width="2"/>
  <path d="M32 24h4" stroke="#FFFFFF" stroke-width="2"/>
</svg>`;
  c.header('Content-Type', 'image/svg+xml');
  return c.body(svg);
});


// Login endpoint
app.post('/api/login', async (c) => {
  try {
    const { username, password, server = 'cn' } = await c.req.json<LoginCredentials>();
    
    const client = new XiaomiCloudConnectorBrowser(username, password);
    
    // Step 1
    const step1Success = await client.loginStep1();
    if (!step1Success) {
      return c.json<LoginResponse>({ success: false, error: 'Login step 1 failed' });
    }
    
    // Step 2
    const step2Result = await client.loginStep2();
    if (!step2Result.success) {
      if (step2Result.requires2FA) {
        // Return client state for browser to store
        const clientState = client.getClientState();
        
        return c.json<LoginResponse>({
          success: false,
          requires2FA: true,
          verifyUrl: step2Result.verifyUrl,
          clientState // Send state to browser
        });
      }
      return c.json<LoginResponse>({ success: false, error: step2Result.error });
    }
    
    // Step 3
    const step3Success = await client.loginStep3();
    if (!step3Success) {
      return c.json<LoginResponse>({ success: false, error: 'Login step 3 failed' });
    }
    
    const session = client.getSessionData();
    return c.json<LoginResponse>({ success: true, session });
  } catch (error: any) {
    return c.json<LoginResponse>({ success: false, error: error.message });
  }
});

// 2FA verification endpoint
app.post('/api/verify-2fa', async (c) => {
  try {
    const { ticket, clientState } = await c.req.json<{ 
      ticket: string; 
      clientState: any;
    }>();
    
    debug.log("[2FA] Received client state keys:", Object.keys(clientState));
    debug.log("[2FA] Client state has sign:", exists(clientState.sign));
    debug.log("[2FA] Client state cookies:", Object.keys(clientState.cookies || {}));
    
    // Recreate client from state
    const client = XiaomiCloudConnectorBrowser.fromClientState(clientState);
    
    // Check identity options and verify ticket
    const identityCheck = await (client as any).checkIdentityOptions();
    if (!identityCheck) {
      debug.error("Failed to check identity options");
    }
    
    debug.log("[2FA] Before verify2FATicket - Client state:", {
      cookies: Object.keys((client as any).cookies),
      sign: exists((client as any).sign),
      identitySession: exists((client as any).identitySession),
      identityOptions: (client as any).identityOptions?.length || 0
    });
    
    const verifyResult = await client.verify2FATicket(ticket);
    if (!verifyResult.success) {
      return c.json<LoginResponse>({ success: false, error: verifyResult.error });
    }
    
    debug.log("[2FA] After verify2FATicket - Client state:", {
      cookies: Object.keys((client as any).cookies),
      ssecurity: exists((client as any).ssecurity),
      userId: (client as any).userId,
      location: exists((client as any).location)
    });
    
    // Clear identity session as per Python implementation
    (client as any).identitySession = null;
    
    // Note: We don't delete the identity_session cookie because Python's session
    // object manages cookies automatically and may still need it
    
    // After 2FA, we need to get the proper ssecurity token
    // The nonce from STS is not the same as ssecurity
    debug.log("[2FA] Need to get proper ssecurity token after 2FA...");
    
    // Always retry loginStep2 to get the ssecurity
    {
      debug.log("[2FA] Retrying login step 2 to get ssecurity...");
      debug.log("[2FA] Current cookies before retry:", Object.keys((client as any).cookies || {}));
      debug.log("[2FA] Current auth state:", {
        userId: (client as any).userId,
        serviceToken: exists((client as any).serviceToken),
        ssecurity: exists((client as any).ssecurity)
      });
      
      // CRITICAL: Ensure we have the sign token before retrying
      if (!(client as any).sign) {
        debug.error("[2FA] ERROR: Missing sign token after 2FA! This is the likely cause of the issue.");
        // The sign might have been lost during client state serialization/deserialization
        // Let's check the original client state
        debug.error("[2FA] Original client state had sign:", exists(clientState.sign));
      }
      
      const step2Result = await client.loginStep2();
      if (!step2Result.success) {
        // Check if it's still asking for 2FA
        if (step2Result.requires2FA) {
          debug.error("[2FA] Still requiring 2FA after verification - session state issue");
          debug.error("[2FA] Final client state:", {
            cookies: Object.keys((client as any).cookies || {}),
            sign: exists((client as any).sign),
            ssecurity: exists((client as any).ssecurity),
            userId: (client as any).userId
          });
          return c.json<LoginResponse>({ success: false, error: 'Session state not properly maintained after 2FA' });
        }
        return c.json<LoginResponse>({ success: false, error: step2Result.error || 'Login failed after 2FA' });
      }
      
      // Complete login with step 3
      const step3Success = await client.loginStep3();
      if (!step3Success) {
        return c.json<LoginResponse>({ success: false, error: 'Login step 3 failed after 2FA' });
      }
    }
    
    const session = client.getSessionData();
    return c.json<LoginResponse>({ success: true, session });
  } catch (error: any) {
    // debug.error("2FA endpoint error:", error);
    return c.json<LoginResponse>({ success: false, error: error.message });
  }
});

// Get devices endpoint with streaming
app.post('/api/devices-stream', async (c) => {
  try {
    const { sessionData, server = 'cn' } = await c.req.json<{ sessionData: SessionData; server?: string }>();
    
    const client = new XiaomiCloudConnectorBrowser(sessionData.username, '');
    client.loadSessionData(sessionData);
    
    // Set up SSE headers
    c.header('Content-Type', 'text/event-stream');
    c.header('Cache-Control', 'no-cache');
    c.header('Connection', 'keep-alive');
    
    const encoder = new TextEncoder();
    const stream = new TransformStream();
    const writer = stream.writable.getWriter();
    
    // Start streaming
    (async () => {
      try {
        // Send initial status
        await writer.write(encoder.encode(`data: ${JSON.stringify({ type: 'status', message: 'Fetching devices...' })}\n\n`));
        
        // Skip validation for fresh login sessions - they should be valid
        // Only validate for loaded sessions from file
        const sessionData = (client as any).getSessionData();
        if (sessionData.savedAt) {
          // This is a loaded session, validate it
          const savedTime = new Date(sessionData.savedAt).getTime();
          const now = Date.now();
          const hoursSinceSaved = (now - savedTime) / (1000 * 60 * 60);
          
          if (hoursSinceSaved > 1) {
            // Only validate if session is older than 1 hour
            await writer.write(encoder.encode(`data: ${JSON.stringify({ type: 'status', message: 'Validating session...' })}\n\n`));
            const isValid = await client.validateSession();
            if (!isValid) {
              await writer.write(encoder.encode(`data: ${JSON.stringify({ type: 'error', message: 'Session expired' })}\n\n`));
              await writer.close();
              return;
            }
          }
        }
        
        let writerClosed = false;
        
        // Set up progress callback
        client.onProgress = async (progress: any) => {
          if (!writerClosed) {
            try {
              await writer.write(encoder.encode(`data: ${JSON.stringify({ type: 'progress', ...progress })}\n\n`));
            } catch (e) {
              debug.error('Failed to write progress:', e);
              writerClosed = true;
            }
          }
        };
        
        // Get devices
        const result = await client.getDevices(server);
        
        if (!writerClosed) {
          if (result.success) {
            await writer.write(encoder.encode(`data: ${JSON.stringify({ type: 'complete', devices: result.devices })}\n\n`));
          } else {
            await writer.write(encoder.encode(`data: ${JSON.stringify({ type: 'error', message: result.error })}\n\n`));
          }
        }
        
      } catch (error: any) {
        debug.error('Stream processing error:', error);
        try {
          await writer.write(encoder.encode(`data: ${JSON.stringify({ type: 'error', message: error.message })}\n\n`));
        } catch (e) {
          debug.error('Failed to write error:', e);
        }
      } finally {
        try {
          await writer.close();
        } catch (e) {
          debug.error('Failed to close writer:', e);
        }
      }
    })();
    
    return c.body(stream.readable);
  } catch (error: any) {
    // debug.error('Stream error:', error);
    return c.json({ error: error.message }, 500);
  }
});

// Keep the original endpoint for compatibility
app.post('/api/devices', async (c) => {
  try {
    const { sessionData, server = 'cn' } = await c.req.json<{ sessionData: SessionData; server?: string }>();
    
    const client = new XiaomiCloudConnectorBrowser(sessionData.username, '');
    client.loadSessionData(sessionData);
    
    // Validate session first
    const isValid = await client.validateSession();
    if (!isValid) {
      return c.json<DevicesResponse>({ success: false, error: 'Session expired' });
    }
    
    const result = await client.getDevices(server);
    return c.json<DevicesResponse>(result);
  } catch (error: any) {
    // debug.error('Get devices error:', error);
    return c.json<DevicesResponse>({ success: false, error: error.message });
  }
});

// Validate session endpoint
app.post('/api/validate-session', async (c) => {
  try {
    const { sessionData } = await c.req.json<{ sessionData: SessionData }>();
    
    const client = new XiaomiCloudConnectorBrowser(sessionData.username, '');
    client.loadSessionData(sessionData);
    
    const isValid = await client.validateSession();
    return c.json({ valid: isValid });
  } catch (error: any) {
    return c.json({ valid: false });
  }
});

function getHtmlContent(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Xiaomi Cloud Tokens Extractor</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="alternate icon" href="/favicon.ico">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #ff6900;
            --primary-dark: #e55a00;
            --primary-light: #ff8533;
            --bg: #000000;
            --bg-secondary: #111111;
            --card-bg: #000000;
            --card-bg-hover: #0a0a0a;
            --text: #ffffff;
            --text-secondary: #888888;
            --text-muted: #666666;
            --border: #333333;
            --border-light: #222222;
            --border-hover: #444444;
            --success: #10b981;
            --error: #ef4444;
            --warning: #f59e0b;
            --info: #3b82f6;
            --shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24);
            --shadow-lg: 0 10px 40px rgba(0,0,0,0.3);
            --shadow-xl: 0 20px 60px rgba(0,0,0,0.5);
            --radius: 0.5rem;
            --radius-lg: 0.75rem;
            --radius-xl: 1rem;
            --gradient: linear-gradient(135deg, #ff6900 0%, #ff8533 100%);
            --gradient-dark: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            min-height: 100vh;
            position: relative;
            overflow-x: hidden;
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(circle at 20% 50%, rgba(255, 105, 0, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(255, 105, 0, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 40% 20%, rgba(255, 133, 51, 0.1) 0%, transparent 50%);
            pointer-events: none;
            z-index: 0;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            position: relative;
            z-index: 1;
        }
        
        .header {
            text-align: center;
            margin-bottom: 4rem;
            position: relative;
        }
        
        h1 {
            font-size: 3.5rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            margin-bottom: 1rem;
            background: linear-gradient(to bottom right, #ffffff 30%, var(--primary) 70%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-fill-color: transparent;
            animation: fadeInUp 0.8s ease-out;
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .subtitle {
            color: var(--text-secondary);
            font-size: 1.25rem;
            font-weight: 400;
            letter-spacing: -0.01em;
            animation: fadeInUp 0.8s ease-out 0.2s both;
        }
        
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-xl);
            padding: 2.5rem;
            margin-bottom: 2rem;
            position: relative;
            transition: all 0.3s ease;
            overflow: hidden;
        }
        
        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--primary), transparent);
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        
        .card:hover {
            border-color: var(--border-hover);
            background: var(--card-bg-hover);
            transform: translateY(-2px);
        }
        
        .card:hover::before {
            opacity: 1;
        }
        
        .card-header {
            display: flex;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-light);
        }
        
        .card-icon {
            width: 48px;
            height: 48px;
            background: var(--gradient);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 1rem;
            font-size: 1.5rem;
            position: relative;
            overflow: hidden;
        }
        
        .card-icon::after {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle, rgba(255,255,255,0.2) 0%, transparent 70%);
            transform: translate(-50%, -50%);
        }
        
        .card h2 {
            font-size: 1.75rem;
            font-weight: 600;
            color: var(--text);
            letter-spacing: -0.01em;
        }
        
        .auth-tabs {
            display: flex;
            gap: 1rem;
            margin-bottom: 2.5rem;
        }
        
        .auth-tab {
            padding: 0.5rem 1rem;
            background: none;
            border: none;
            color: var(--text-muted);
            font-size: 0.875rem;
            font-weight: 400;
            cursor: pointer;
            transition: none;
            display: inline-block;
            box-shadow: none;
            transform: none;
        }
        
        .auth-tab:hover {
            color: var(--text-secondary);
            transform: none;
            box-shadow: none;
        }
        
        .auth-tab:active {
            transform: none;
        }
        
        .auth-tab.active {
            color: var(--text);
            font-weight: 500;
        }
        
        .auth-content {
            display: none;
        }
        
        .auth-content.active {
            display: block;
        }
        
        .drop-zone {
            border: 2px dashed var(--border);
            border-radius: var(--radius-xl);
            padding: 4rem 2rem;
            text-align: center;
            transition: all 0.3s ease;
            cursor: pointer;
            background: var(--bg-secondary);
            position: relative;
            overflow: hidden;
        }
        
        .drop-zone::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, var(--primary) 0%, transparent 70%);
            transform: translate(-50%, -50%) scale(0);
            opacity: 0.1;
            transition: transform 0.5s ease;
        }
        
        .drop-zone:hover::before,
        .drop-zone.drag-over::before {
            transform: translate(-50%, -50%) scale(1);
        }
        
        .drop-zone:hover,
        .drop-zone.drag-over {
            border-color: var(--primary);
            background: var(--bg-secondary);
        }
        
        .drop-zone-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            filter: grayscale(100%);
            opacity: 0.3;
            transition: all 0.3s ease;
        }
        
        .drop-zone:hover .drop-zone-icon {
            filter: grayscale(0%);
            opacity: 1;
            transform: scale(1.1);
        }
        
        /* Mobile Responsive Styles */
        @media (max-width: 768px) {
            body {
                font-size: 14px;
            }
            
            .container {
                padding: 1rem;
                max-width: 100%;
            }
            
            .header {
                margin-bottom: 2rem;
            }
            
            .header h1 {
                font-size: 1.75rem;
            }
            
            .header .subtitle {
                font-size: 0.875rem;
            }
            
            .card {
                padding: 1.25rem;
                margin-bottom: 1rem;
            }
            
            .card-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 1rem;
                margin-bottom: 1rem;
            }
            
            .card-header > div:first-child {
                flex-direction: row;
                align-items: center;
            }
            
            .card-header > div:last-child {
                margin-top: 0;
                width: 100%;
            }
            
            .card-header button {
                width: auto;
                flex: 1;
            }
            
            /* Stack server controls on mobile */
            #devicesSection .card-header > div:last-child {
                flex-direction: column !important;
                gap: 0.75rem !important;
            }
            
            #serverSelector, #refreshDevicesBtn {
                width: 100% !important;
                height: 44px !important;
            }
            
            /* Fix mobile colors */
            @media (prefers-color-scheme: light) {
                select, input {
                    -webkit-appearance: none;
                    appearance: none;
                }
            }
            
            .auth-tabs {
                font-size: 0.875rem;
            }
            
            .form-group {
                margin-bottom: 1rem;
            }
            
            input, select, button {
                font-size: 16px; /* Prevents zoom on iOS */
                padding: 0.875rem 1rem;
            }
            
            .devices-grid {
                grid-template-columns: 1fr;
                gap: 0.75rem;
            }
            
            .device-item {
                padding: 1rem;
            }
            
            .device-info {
                grid-template-columns: 1fr;
                gap: 0.5rem;
            }
            
            .device-detail {
                padding: 0.5rem;
                font-size: 0.8125rem;
            }
            
            .privacy-notice {
                padding: 1.25rem;
            }
            
            .privacy-section h4 {
                font-size: 1rem;
            }
            
            /* Make buttons touch-friendly */
            button {
                min-height: 44px;
                touch-action: manipulation;
            }
            
            /* Fix alert positioning on mobile */
            #alerts {
                right: 1rem;
                left: 1rem;
                width: auto;
                max-width: none;
            }
            
            /* Make dropzone more mobile-friendly */
            .drop-zone {
                padding: 2rem 1rem;
            }
            
            /* Fix verify URL box */
            .verify-url {
                font-size: 0.75rem;
                padding: 0.75rem;
            }
            
            /* Adjust loading spinner */
            .loading {
                width: 16px;
                height: 16px;
            }
            
            /* Stack authenticated session info */
            .card-header div[style*="display: flex; gap: 1.5rem"] {
                flex-direction: column !important;
                gap: 0.5rem !important;
                align-items: flex-start !important;
            }
        }
        
        /* Smaller mobile devices */
        @media (max-width: 480px) {
            .header h1 {
                font-size: 1.5rem;
            }
            
            .card {
                padding: 1rem;
            }
            
            .privacy-notice {
                padding: 1rem;
            }
            
            .drop-zone {
                padding: 1.5rem 1rem;
            }
            
            .drop-zone-icon {
                font-size: 2rem;
            }
            
            .devices-grid {
                margin: 0 -0.5rem;
            }
            
            .device-item {
                margin: 0 0.5rem;
                padding: 0.875rem;
            }
            
            .info-row {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.25rem;
            }
            
            .info-row dt {
                min-width: auto;
                margin-bottom: 0.25rem;
            }
            
            .info-row dd {
                width: 100%;
                font-size: 0.75rem;
                padding: 0.5rem 0.75rem;
                word-break: break-all;
                hyphens: auto;
            }
            
            .copy-hint {
                display: none;
            }
            
            /* Footer links on mobile */
            .privacy-notice div[style*="display: flex"] {
                flex-direction: column !important;
                gap: 0.75rem !important;
            }
        }
        
        .form-group {
            margin-bottom: 1.25rem;
        }
        
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--text-secondary);
            font-size: 0.875rem;
            letter-spacing: -0.01em;
        }
        
        input, select {
            width: 100%;
            padding: 0.875rem 1rem;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            font-size: 1rem;
            font-weight: 400;
            transition: all 0.2s ease;
            background-color: var(--bg-secondary);
            color: var(--text);
            -webkit-appearance: none;
            appearance: none;
        }
        
        select {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23888' d='M10.293 3.293L6 7.586 1.707 3.293A1 1 0 00.293 4.707l5 5a1 1 0 001.414 0l5-5a1 1 0 10-1.414-1.414z'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 1rem center;
            padding-right: 2.5rem;
        }
        
        select option {
            background-color: var(--bg-secondary);
            color: var(--text);
        }
        
        input::placeholder {
            color: var(--text-muted);
        }
        
        input:hover, select:hover {
            border-color: var(--border-hover);
        }
        
        input:focus, select:focus {
            outline: none;
            border-color: var(--primary);
            background-color: var(--card-bg);
            box-shadow: 0 0 0 1px var(--primary);
        }
        
        button {
            background: var(--gradient);
            color: white;
            border: none;
            padding: 0.875rem 2rem;
            border-radius: var(--radius);
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            letter-spacing: -0.01em;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            position: relative;
            overflow: hidden;
        }
        
        button::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            background: rgba(255,255,255,0.2);
            border-radius: 50%;
            transform: translate(-50%, -50%);
            transition: width 0.6s, height 0.6s;
        }
        
        button:hover::before {
            width: 300px;
            height: 300px;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(255, 105, 0, 0.3);
        }
        
        button:active {
            transform: translateY(0);
        }
        
        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .button-group {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .button-secondary {
            background: transparent;
            color: var(--text-secondary);
            border: 1px solid var(--border);
            box-shadow: none;
            font-weight: 400;
        }
        
        .button-secondary::before {
            background: transparent;
        }
        
        .button-secondary:hover {
            color: var(--text);
            border-color: var(--primary);
            background: transparent;
            box-shadow: none;
        }
        
        .button-secondary:hover::before {
            width: 0;
            height: 0;
        }
        
        #alerts {
            position: fixed;
            top: 2rem;
            right: 2rem;
            z-index: 1000;
            display: flex;
            flex-direction: column;
            gap: 1rem;
            max-width: 400px;
        }
        
        .alert {
            padding: 1rem 1.5rem;
            border-radius: var(--radius-lg);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            background: rgba(0,0,0,0.8);
            border: 1px solid var(--border-light);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            animation: slideInRight 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        @keyframes slideInRight {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        .alert::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            width: 4px;
            height: 100%;
        }
        
        .alert-success {
            border-left: 3px solid var(--success);
            color: var(--success);
        }
        
        .alert-error {
            border-left: 3px solid var(--error);
            color: var(--error);
        }
        
        .alert-warning {
            border-left: 3px solid var(--warning);
            color: var(--warning);
        }
        
        .alert-info {
            border-left: 3px solid var(--info);
            color: var(--info);
        }
        
        .device-list {
            display: grid;
            gap: 15px;
        }
        
        .devices-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 1.5rem;
        }
        
        .device-item {
            background: var(--card-bg);
            padding: 1.5rem;
            border-radius: var(--radius-xl);
            border: 1px solid var(--border-light);
            transition: all 0.3s ease;
            animation: slideIn 0.5s ease;
            position: relative;
            overflow: hidden;
        }
        
        .device-item::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--primary), transparent);
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .device-item:hover {
            border-color: var(--border-hover);
            background: var(--card-bg-hover);
            transform: translateY(-4px);
        }
        
        .device-item:hover::before {
            opacity: 1;
        }
        
        .device-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1.5rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-light);
        }
        
        .device-name {
            font-weight: 600;
            color: var(--text);
            font-size: 1.125rem;
            line-height: 1.2;
            letter-spacing: -0.01em;
        }
        
        .device-status {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.75rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
        }
        
        .status-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: var(--text-muted);
            position: relative;
        }
        
        .status-dot.online {
            background: var(--success);
        }
        
        .status-dot.online::before {
            content: '';
            position: absolute;
            top: -3px;
            left: -3px;
            right: -3px;
            bottom: -3px;
            border-radius: 50%;
            background: var(--success);
            opacity: 0.3;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); opacity: 0.3; }
            50% { transform: scale(1.5); opacity: 0; }
            100% { transform: scale(1); opacity: 0.3; }
        }
        
        .device-info {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            min-width: 0;
            width: 100%;
        }
        
        .info-row {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            position: relative;
            min-width: 0;
        }
        
        .info-row dt {
            font-weight: 500;
            color: var(--text-muted);
            font-size: 0.6875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            min-width: 60px;
        }
        
        .info-row dd {
            flex: 1;
            font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
            font-size: 0.8125rem;
            color: var(--text-secondary);
            margin: 0;
            padding: 0.625rem 0.875rem;
            background: var(--bg-secondary);
            border-radius: var(--radius);
            border: 1px solid transparent;
            word-break: break-word;
            overflow-wrap: break-word;
            cursor: pointer;
            transition: all 0.15s ease;
            position: relative;
            overflow: hidden;
            min-width: 0;
        }
        
        .info-row dd:hover {
            background: var(--card-bg);
            border-color: var(--border);
            color: var(--text);
            transform: translateX(2px);
        }
        
        .info-row dd:active {
            transform: translateX(0);
        }
        
        .info-row dd.token {
            background: rgba(255, 105, 0, 0.1);
            border-color: rgba(255, 105, 0, 0.2);
            color: var(--primary-light);
            font-weight: 500;
        }
        
        .info-row dd.token:hover {
            background: rgba(255, 105, 0, 0.15);
            border-color: rgba(255, 105, 0, 0.3);
        }
        
        .copy-hint {
            position: absolute;
            right: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            font-size: 0.625rem;
            color: var(--text-muted);
            opacity: 0;
            transition: opacity 0.15s;
            pointer-events: none;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 500;
        }
        
        .info-row dd:hover .copy-hint {
            opacity: 1;
        }
        
        
        .progress-container {
            background: var(--bg-secondary);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-lg);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        .progress-message {
            color: var(--text-secondary);
            margin-bottom: 1rem;
            font-size: 0.875rem;
        }
        
        .progress-bar {
            width: 100%;
            height: 2px;
            background: var(--border);
            border-radius: 2px;
            overflow: hidden;
            position: relative;
        }
        
        .progress-bar-fill {
            height: 100%;
            background: var(--gradient);
            transition: width 0.3s ease;
            position: relative;
        }
        
        .progress-bar-fill::after {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            bottom: 0;
            width: 100px;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3));
            animation: shimmer 1.5s infinite;
        }
        
        @keyframes shimmer {
            0% { transform: translateX(-100px); }
            100% { transform: translateX(100px); }
        }
        
        .file-actions {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }
        
        .hidden {
            display: none;
        }
        
        #verifySection {
            border: 1px solid var(--warning);
            background: rgba(245, 158, 11, 0.1);
        }
        
        #verifySection .card-icon {
            background: var(--warning);
        }
        
        #verifySection ol {
            color: var(--text-secondary);
            line-height: 2;
            margin: 1.5rem 0;
        }
        
        #verifySection strong {
            color: var(--error);
            font-weight: 600;
        }
        
        .verify-url {
            background: var(--bg-secondary);
            padding: 1rem;
            border-radius: var(--radius);
            word-break: break-all;
            margin: 0.5rem 0;
            font-family: monospace;
            overflow-x: auto;
            white-space: nowrap;
            border: 1px solid var(--border);
        }
        
        .verify-url a {
            color: var(--primary);
            text-decoration: none;
            font-size: 0.875rem;
        }
        
        .verify-url a:hover {
            text-decoration: underline;
        }
        
        .loading {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255,255,255,.2);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 0.8s linear infinite;
            vertical-align: middle;
            margin: 0;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .privacy-notice {
            background: var(--gradient-dark);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-xl);
            padding: 3rem;
            margin-top: 4rem;
            position: relative;
            overflow: hidden;
        }
        
        .privacy-notice::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255, 105, 0, 0.1) 0%, transparent 70%);
            animation: rotate 20s linear infinite;
        }
        
        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        .privacy-notice h3 {
            color: var(--text);
            margin-bottom: 2rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.5rem;
            font-weight: 600;
            letter-spacing: -0.01em;
            position: relative;
            z-index: 1;
        }
        
        .privacy-notice .icon {
            font-size: 1.75rem;
            filter: grayscale(100%);
            opacity: 0.5;
        }
        
        .privacy-content {
            color: var(--text-secondary);
            line-height: 1.8;
            position: relative;
            z-index: 1;
        }
        
        .privacy-section {
            margin-bottom: 1.5rem;
        }
        
        .privacy-section h4 {
            color: var(--text);
            font-size: 1.125rem;
            margin-bottom: 0.75rem;
            font-weight: 600;
            letter-spacing: -0.01em;
        }
        
        .privacy-section p {
            margin-bottom: 0.5rem;
        }
        
        .privacy-list {
            list-style: none;
            padding: 0;
            margin: 0.5rem 0;
        }
        
        .privacy-list li {
            position: relative;
            padding-left: 1.5rem;
            margin-bottom: 0.5rem;
        }
        
        .privacy-list li::before {
            content: '→';
            position: absolute;
            left: 0;
            color: var(--text-muted);
        }
        
        a:hover {
            color: var(--text-secondary) !important;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Xiaomi Cloud Tokens Extractor</h1>
            <p class="subtitle">Extract device tokens and keys from your Xiaomi account</p>
        </div>
        
        <div class="card">
            <div class="card-header">
                <div class="card-icon">🔐</div>
                <h2>Authentication</h2>
            </div>
            
            <div class="auth-tabs">
                <button class="auth-tab active" onclick="switchAuthTab('login')">Login with Credentials</button>
                <button class="auth-tab" onclick="switchAuthTab('session')">Use Saved Session</button>
            </div>
            
            <div id="loginTab" class="auth-content active">
                <form id="loginForm">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" required placeholder="Email, phone number, or Xiaomi ID">
                        <small style="color: var(--text-secondary); font-size: 0.75rem; margin-top: 0.25rem; display: block;">
                            Accepts: Email address, phone number (mostly CN accounts), or Xiaomi account ID
                        </small>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <div class="form-group">
                        <label for="server">Server Region</label>
                        <select id="server" name="server" title="Select the region where you registered your Xiaomi account">
                            <option value="cn">🇨🇳 China (cn) - Mainland China</option>
                            <option value="de">🇩🇪 Germany (de) - Europe</option>
                            <option value="us">🇺🇸 United States (us) - Americas</option>
                            <option value="ru">🇷🇺 Russia (ru) - Russia/CIS</option>
                            <option value="tw">🇹🇼 Taiwan (tw) - Taiwan</option>
                            <option value="sg">🇸🇬 Singapore (sg) - Southeast Asia</option>
                            <option value="in">🇮🇳 India (in) - India</option>
                            <option value="i2">🌍 International (i2) - Other regions</option>
                        </select>
                        <small style="color: var(--text-secondary); font-size: 0.75rem; margin-top: 0.25rem; display: block;">
                            💡 Choose the region where you created your Xiaomi account or where your devices were purchased<br>
                            You can switch to other regions after login without re-authenticating
                        </small>
                    </div>
                    <button type="submit" id="loginBtn">Login</button>
                </form>
            </div>
            
            <div id="sessionTab" class="auth-content">
                <div id="dropZone" class="drop-zone">
                    <div class="drop-zone-icon">📁</div>
                    <h3 style="margin-bottom: 0.5rem;">Drop session file here</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 1rem;">or click to browse</p>
                    <input type="file" id="loadSession" accept=".json" style="display: none;">
                    <button class="button-secondary" onclick="document.getElementById('loadSession').click()">
                        Choose File
                    </button>
                </div>
                <div id="sessionInfo" style="margin-top: 1rem;"></div>
            </div>
            
        </div>
        
        <div id="verifySection" class="card hidden">
            <div class="card-header">
                <div class="card-icon">🔐</div>
                <h2>Two-Factor Authentication</h2>
            </div>
            <p>Please follow these steps:</p>
            <ol style="line-height: 2; margin: 1rem 0;">
                <li>Open this URL in your browser:
                    <div class="verify-url" style="margin: 0.5rem 0;">
                        <a id="verifyUrl" href="#" target="_blank"></a>
                    </div>
                </li>
                <li>Choose your verification method (SMS or Email)</li>
                <li>You'll receive a 6-digit verification code</li>
                <li><strong style="color: var(--error);">DO NOT enter the code on Xiaomi's website!</strong></li>
                <li>Close the browser and enter the code below:</li>
            </ol>
            <form id="verifyForm" autocomplete="off">
                <div class="form-group">
                    <label for="verifyCode">Verification Code</label>
                    <input type="text" id="verifyCode" name="xiaomi-digits" pattern="[0-9]{6}" maxlength="6" required placeholder="Enter 6 digits" autocomplete="nope" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true" data-form-type="other" style="font-size: 1.5rem; text-align: center; letter-spacing: 0.5rem;">
                </div>
                <button type="submit" style="width: 100%;">Verify</button>
            </form>
        </div>
        
        
        <div id="devicesSection" class="card hidden">
            <div class="card-header" style="margin-bottom: 0; justify-content: space-between; align-items: center;">
                <div style="display: flex; align-items: center;">
                    <div class="card-icon">📱</div>
                    <h2 style="margin-bottom: 0;">Devices</h2>
                </div>
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <select id="serverSelector" style="padding: 0.5rem 1rem; padding-right: 2.5rem; font-size: 0.875rem; border: 1px solid var(--border); border-radius: var(--radius); background-color: var(--bg-secondary); color: var(--text); height: 36px; -webkit-appearance: none; appearance: none; background-image: url(&quot;data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23888' d='M10.293 3.293L6 7.586 1.707 3.293A1 1 0 00.293 4.707l5 5a1 1 0 001.414 0l5-5a1 1 0 10-1.414-1.414z'/%3E%3C/svg%3E&quot;); background-repeat: no-repeat; background-position: right 0.5rem center;" onchange="loadDevices(false)" title="Select the server region where your devices are registered">
                        <option value="cn">🇨🇳 China (cn) - Mainland China</option>
                        <option value="de">🇩🇪 Germany (de) - Europe</option>
                        <option value="us">🇺🇸 United States (us) - Americas</option>
                        <option value="ru">🇷🇺 Russia (ru) - Russia/CIS</option>
                        <option value="tw">🇹🇼 Taiwan (tw) - Taiwan</option>
                        <option value="sg">🇸🇬 Singapore (sg) - Southeast Asia</option>
                        <option value="in">🇮🇳 India (in) - India</option>
                        <option value="i2">🌍 International (i2) - Other regions</option>
                    </select>
                    <button id="refreshDevicesBtn" class="button-secondary" style="padding: 0.5rem 1rem; font-size: 0.875rem; white-space: nowrap; height: 36px;" onclick="loadDevices(false)">🔄 Refresh</button>
                </div>
            </div>
            <div id="currentServerInfo" style="margin: 1rem 0; padding: 0.75rem; background: var(--bg); border-radius: var(--radius); font-size: 0.875rem; color: var(--text-secondary); text-align: center;"></div>
            <div id="devicesList" class="devices-grid"></div>
        </div>
        
        <div id="alerts"></div>
        
        <div class="privacy-notice">
            <h3><span class="icon">🔒</span> Privacy & Security Disclosure</h3>
            <div class="privacy-content">
                <div class="privacy-section">
                    <h4>What This Tool Does</h4>
                    <p>This tool extracts device tokens and authentication keys from your Xiaomi account. These tokens are used to locally control your Xiaomi smart home devices without going through Xiaomi's cloud servers.</p>
                </div>
                
                <div class="privacy-section">
                    <h4>How It Works</h4>
                    <ul class="privacy-list">
                        <li>Authenticates with Xiaomi's servers using your credentials</li>
                        <li>Retrieves a list of all devices linked to your account</li>
                        <li>Extracts device tokens and BLE keys for local control</li>
                    </ul>
                </div>
                
                <div class="privacy-section">
                    <h4>Data Handling</h4>
                    <ul class="privacy-list">
                        <li><strong>No storage:</strong> Your credentials are never stored on the server</li>
                        <li><strong>Session files:</strong> Saved locally on your device only</li>
                        <li><strong>Direct communication:</strong> All API calls go directly to Xiaomi servers</li>
                        <li><strong>Open source:</strong> Code is fully auditable on GitHub</li>
                    </ul>
                </div>
                
                <div class="privacy-section">
                    <h4>Security Recommendations</h4>
                    <ul class="privacy-list">
                        <li>Use HTTPS when deploying this tool</li>
                        <li>Keep session files secure - they contain authentication tokens</li>
                        <li>Enable 2FA on your Xiaomi account</li>
                        <li>Consider using app-specific passwords if available</li>
                    </ul>
                </div>
                
                <div class="privacy-section" style="margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border-light);">
                    <p style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 1rem;">
                        <strong>Disclaimer:</strong> This is an unofficial tool not affiliated with Xiaomi. Use at your own risk. 
                        The tool replicates the functionality of the Python-based Xiaomi-cloud-tokens-extractor project in a web interface.
                    </p>
                    <div style="text-align: center; padding-top: 1rem; border-top: 1px solid var(--border-light);">
                        <p style="font-size: 0.75rem; color: var(--text-muted); margin: 0; font-weight: 500; letter-spacing: 0.05em;">
                            VERSION 1.2.0
                        </p>
                        <div style="margin-top: 0.5rem; display: flex; justify-content: center; gap: 1.5rem;">
                            <a href="https://github.com/rankjie/xiaomi-tokens-web" target="_blank" rel="noopener noreferrer" style="color: var(--text-muted); text-decoration: none; font-size: 0.75rem; display: inline-flex; align-items: center; gap: 0.25rem; transition: color 0.2s;">
                                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                                    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                                </svg>
                                <span>GitHub</span>
                            </a>
                            <a href="https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor" target="_blank" rel="noopener noreferrer" style="color: var(--text-muted); text-decoration: none; font-size: 0.75rem; display: inline-flex; align-items: center; gap: 0.25rem; transition: color 0.2s;">
                                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                                    <path d="M8.75 1.75a.75.75 0 00-1.5 0v2.5h-2.5a.75.75 0 000 1.5h2.5v2.5a.75.75 0 001.5 0v-2.5h2.5a.75.75 0 000-1.5h-2.5v-2.5z"/>
                                    <path d="M8 13A5 5 0 108 3a5 5 0 000 10zm0 1.5A6.5 6.5 0 108 1.5a6.5 6.5 0 000 13z"/>
                                </svg>
                                <span>Original Python Version</span>
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let currentSession = null;
        let tempClientState = null; // Store client state for stateless 2FA
        let selectedServer = 'cn'; // Store selected server
        let sessionLoadedFromFile = false; // Track if session was loaded from file
        
        // Tab switching
        function switchAuthTab(tab) {
            const tabs = document.querySelectorAll('.auth-tab');
            const contents = document.querySelectorAll('.auth-content');
            
            tabs.forEach(t => t.classList.remove('active'));
            contents.forEach(c => c.classList.remove('active'));
            
            if (tab === 'login') {
                tabs[0].classList.add('active');
                document.getElementById('loginTab').classList.add('active');
            } else {
                tabs[1].classList.add('active');
                document.getElementById('sessionTab').classList.add('active');
            }
        }
        
        // Drag and drop setup
        const dropZone = document.getElementById('dropZone');
        const loadSessionInput = document.getElementById('loadSession');
        
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('drag-over');
        });
        
        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('drag-over');
        });
        
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
            
            const files = e.dataTransfer.files;
            if (files.length > 0 && files[0].type === 'application/json') {
                handleSessionFile(files[0]);
            } else {
                showAlert('Please drop a JSON file', 'error');
            }
        });
        
        dropZone.addEventListener('click', (e) => {
            // Don't trigger if clicking on the button or its children
            if (e.target.closest('button')) {
                return;
            }
            loadSessionInput.click();
        });
        
        // Alert functions
        function showAlert(message, type = 'info') {
            const alertsDiv = document.getElementById('alerts');
            const alert = document.createElement('div');
            alert.className = \`alert alert-\${type}\`;
            
            // Add icon based on type
            const icons = {
                success: '✓',
                error: '×',
                warning: '!',
                info: 'i'
            };
            
            alert.innerHTML = \`
                <span style="font-size: 1.25rem; font-weight: bold;">\${icons[type] || icons.info}</span>
                <span>\${message}</span>
            \`;
            
            alertsDiv.appendChild(alert);
            
            // Auto-dismiss after 5 seconds
            setTimeout(() => {
                alert.style.animation = 'slideOutRight 0.3s ease';
                setTimeout(() => alert.remove(), 300);
            }, 5000);
        }
        
        // Add slide out animation
        const style = document.createElement('style');
        style.textContent = \`
            @keyframes slideOutRight {
                from {
                    transform: translateX(0);
                    opacity: 1;
                }
                to {
                    transform: translateX(100%);
                    opacity: 0;
                }
            }
        \`;
        document.head.appendChild(style);
        
        // Login form handler
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const credentials = {
                username: formData.get('username'),
                password: formData.get('password'),
                server: formData.get('server')
            };
            
            // Store selected server
            selectedServer = credentials.server;
            
            const loginBtn = document.getElementById('loginBtn');
            loginBtn.disabled = true;
            loginBtn.innerHTML = '<span class="loading"></span> Logging in...';
            
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(credentials)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    currentSession = result.session;
                    currentSession.server = credentials.server; // Store server selection
                    sessionLoadedFromFile = false; // Not loaded from file
                    showAlert('Login successful!', 'success');
                    updateSessionUI();
                    // Set server selector to match login selection
                    const serverSelector = document.getElementById('serverSelector');
                    if (serverSelector) {
                        serverSelector.value = credentials.server;
                    }
                    await loadDevices();
                } else if (result.requires2FA) {
                    // Store the client state for 2FA verification
                    tempClientState = result.clientState;
                    
                    const verifyUrlElement = document.getElementById('verifyUrl');
                    verifyUrlElement.textContent = result.verifyUrl;
                    verifyUrlElement.href = result.verifyUrl;
                    
                    // Clear the verification code input
                    const verifyCodeInput = document.getElementById('verifyCode');
                    verifyCodeInput.value = '';
                    
                    // Generate a unique name to prevent autocomplete
                    verifyCodeInput.setAttribute('name', 'verifyCode-' + Date.now());
                    
                    // Hide login form and show verification section
                    document.getElementById('loginForm').classList.add('hidden');
                    document.getElementById('verifySection').classList.remove('hidden');
                    
                    // Focus on the input after a short delay
                    setTimeout(() => verifyCodeInput.focus(), 100);
                    
                    showAlert('2FA verification required', 'warning');
                } else {
                    showAlert(\`Login failed: \${result.error}\`, 'error');
                }
            } catch (error) {
                showAlert(\`Error: \${error.message}\`, 'error');
            } finally {
                loginBtn.disabled = false;
                loginBtn.textContent = 'Login';
            }
        });
        
        // 2FA verification handler
        document.getElementById('verifyForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const code = document.getElementById('verifyCode').value;
            
            if (!tempClientState) {
                showAlert('Session not found. Please login again.', 'error');
                document.getElementById('verifySection').classList.add('hidden');
                document.getElementById('loginForm').classList.remove('hidden');
                return;
            }
            
            try {
                const response = await fetch('/api/verify-2fa', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ticket: code,
                        clientState: tempClientState
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    currentSession = result.session;
                    currentSession.server = selectedServer; // Store server selection
                    sessionLoadedFromFile = false; // Not loaded from file
                    document.getElementById('verifySection').classList.add('hidden');
                    document.getElementById('loginForm').classList.remove('hidden');
                    showAlert('2FA verification successful!', 'success');
                    updateSessionUI();
                    // Set server selector to match original selection
                    const serverSelector = document.getElementById('serverSelector');
                    if (serverSelector) {
                        serverSelector.value = selectedServer;
                    }
                    await loadDevices();
                } else {
                    showAlert(\`Verification failed: \${result.error}\`, 'error');
                }
            } catch (error) {
                showAlert(\`Error: \${error.message}\`, 'error');
            }
        });
        
        // Load session file
        document.getElementById('loadSession').addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            handleSessionFile(file);
        });
        
        // Handle session file
        async function handleSessionFile(file) {
            try {
                const text = await file.text();
                const session = JSON.parse(text);
                
                // Convert Python session format to web format
                if (session.timestamp && !session.savedAt) {
                    session.savedAt = new Date(session.timestamp * 1000).toISOString();
                }
                if (session.device_id && !session.deviceId) {
                    session.deviceId = session.device_id;
                }
                
                currentSession = session;
                sessionLoadedFromFile = true; // Mark as loaded from file
                updateSessionUI();
                
                // Validate and load devices
                showAlert('Session loaded, validating...', 'info');
                const response = await fetch('/api/validate-session', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sessionData: currentSession })
                });
                
                const result = await response.json();
                if (result.valid) {
                    showAlert('Session is valid!', 'success');
                    // Set server selector to loaded session's server if available
                    const serverSelector = document.getElementById('serverSelector');
                    if (serverSelector && currentSession.server) {
                        serverSelector.value = currentSession.server;
                    }
                    await loadDevices();
                } else {
                    showAlert('Session expired, please login again', 'error');
                    currentSession = null;
                    updateSessionUI();
                }
            } catch (error) {
                showAlert('Invalid session file', 'error');
            }
        }
        
        // Logout function
        function logout() {
            currentSession = null;
            tempClientState = null;
            selectedServer = 'cn';
            sessionLoadedFromFile = false;
            location.reload();
        }
        
        // Save session
        function saveSession() {
            if (!currentSession) return;
            
            const filename = \`\${currentSession.username}_xiaomi_session_\${new Date().toISOString().split('T')[0]}.json\`;
            const blob = new Blob([JSON.stringify(currentSession, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
            
            URL.revokeObjectURL(url);
            showAlert('Session saved successfully', 'success');
        }
        
        // Update session UI
        function updateSessionUI() {
            const sessionInfo = document.getElementById('sessionInfo');
            const authCard = document.querySelector('.card');
            const authTabs = document.querySelector('.auth-tabs');
            const authContents = document.querySelectorAll('.auth-content');
            
            if (currentSession) {
                // Hide tabs and auth content when logged in
                authTabs.style.display = 'none';
                authContents.forEach(content => content.style.display = 'none');
                
                // Create collapsed session view
                const savedAt = currentSession.savedAt ? new Date(currentSession.savedAt).toLocaleString() : 'Unknown';
                authCard.innerHTML = \`
                    <div class="card-header" style="margin-bottom: 0; justify-content: space-between; align-items: center;">
                        <div style="display: flex; align-items: center;">
                            <div class="card-icon">🔐</div>
                            <div style="margin-left: 1rem;">
                                <h2 style="margin-bottom: 0.25rem;">Authenticated Session</h2>
                                <div style="display: flex; gap: 1.5rem; font-size: 0.8125rem; color: var(--text-secondary); font-weight: 400;">
                                    <span style="display: flex; align-items: center; gap: 0.25rem;">
                                        <span style="color: var(--text-muted); text-transform: uppercase; font-size: 0.6875rem; letter-spacing: 0.05em;">USER</span>
                                        <span style="color: var(--text-secondary);">\${currentSession.username}</span>
                                    </span>
                                    <span style="display: flex; align-items: center; gap: 0.25rem;">
                                        <span style="color: var(--text-muted); text-transform: uppercase; font-size: 0.6875rem; letter-spacing: 0.05em;">ID</span>
                                        <span style="color: var(--text-secondary);">\${currentSession.userId}</span>
                                    </span>
                                    <span style="display: flex; align-items: center; gap: 0.25rem;">
                                        <span style="color: var(--text-muted); text-transform: uppercase; font-size: 0.6875rem; letter-spacing: 0.05em;">SESSION</span>
                                        <span style="color: var(--text-secondary);">\${savedAt}</span>
                                    </span>
                                </div>
                            </div>
                        </div>
                        <div style="display: flex; gap: 0.5rem;">
                            \${!sessionLoadedFromFile ? \`
                                <button id="saveSessionBtnTop" class="button-secondary" style="padding: 0.5rem 1rem; font-size: 0.875rem;" onclick="saveSession()">
                                    💾 Save Session
                                </button>
                            \` : ''}
                            <button class="button-secondary" style="padding: 0.5rem 1rem; font-size: 0.875rem;" onclick="logout()">
                                🔄 Change Account
                            </button>
                        </div>
                    </div>
                \`;
                document.getElementById('devicesSection').classList.remove('hidden');
            } else {
                // Restore original auth card structure
                location.reload(); // Simple way to restore the original state
            }
        }
        
        // Track if devices are currently loading
        let isLoadingDevices = false;
        
        // All available regions
        const allRegions = ['cn', 'de', 'us', 'ru', 'tw', 'sg', 'in', 'i2'];
        
        // Load devices with streaming
        async function loadDevices(autoScan = true) {
            if (!currentSession) return;
            
            // Prevent multiple simultaneous loads
            if (isLoadingDevices) {
                debug.log('Already loading devices, skipping...');
                return;
            }
            
            const btn = document.getElementById('refreshDevicesBtn');
            const devicesList = document.getElementById('devicesList');
            const devicesSection = document.getElementById('devicesSection');
            const serverSelector = document.getElementById('serverSelector');
            
            // Get selected server
            const selectedServer = serverSelector.value;
            
            // Update server info
            const serverInfo = document.getElementById('currentServerInfo');
            serverInfo.textContent = \`Loading devices from \${selectedServer.toUpperCase()} server...\`;
            
            isLoadingDevices = true;
            btn.disabled = true;
            serverSelector.disabled = true;
            btn.innerHTML = '<span class="loading"></span> Loading...';
            devicesList.innerHTML = '';
            
            // Add progress container
            const progressContainer = document.createElement('div');
            progressContainer.className = 'progress-container';
            progressContainer.innerHTML = \`
                <div class="progress-message">Initializing...</div>
                <div class="progress-bar">
                    <div class="progress-bar-fill" style="width: 0%"></div>
                </div>
            \`;
            devicesList.appendChild(progressContainer);
            devicesSection.classList.remove('hidden');
            
            const progressMessage = progressContainer.querySelector('.progress-message');
            const progressBar = progressContainer.querySelector('.progress-bar-fill');
            
            try {
                const response = await fetch('/api/devices-stream', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        sessionData: currentSession,
                        server: selectedServer
                    })
                });
                
                if (!response.ok) {
                    throw new Error(\`HTTP error! status: \${response.status}\`);
                }
                
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let buffer = '';
                let devices = [];
                
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    
                    buffer += decoder.decode(value, { stream: true });
                    const lines = buffer.split('\\n');
                    buffer = lines.pop() || '';
                    
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            try {
                                const data = JSON.parse(line.slice(6));
                                
                                switch (data.type) {
                                    case 'status':
                                        progressMessage.textContent = data.message;
                                        break;
                                        
                                    case 'progress':
                                        progressMessage.textContent = data.message;
                                        if (data.totalHomes) {
                                            const percent = (data.currentHome / data.totalHomes) * 100;
                                            progressBar.style.width = \`\${percent}%\`;
                                        }
                                        if (data.device) {
                                            devices.push(data.device);
                                            displayDevice(data.device, devicesList);
                                        }
                                        break;
                                        
                                    case 'complete':
                                        progressContainer.remove();
                                        if (devices.length === 0 && data.devices) {
                                            displayDevices(data.devices);
                                        }
                                        const deviceCount = data.devices?.length || devices.length;
                                        
                                        // If no devices found and autoScan is enabled, try other regions
                                        if (deviceCount === 0 && autoScan) {
                                            progressContainer.remove();
                                            await scanAllRegions(selectedServer);
                                        } else {
                                            showAlert(\`Found \${deviceCount} device(s)\`, 'success');
                                            serverInfo.textContent = \`Showing \${deviceCount} device(s) from \${selectedServer.toUpperCase()} server\`;
                                        }
                                        break;
                                        
                                    case 'error':
                                        progressContainer.remove();
                                        showAlert(\`Error: \${data.message}\`, 'error');
                                        break;
                                }
                            } catch (e) {
                                // debug.error('Failed to parse SSE data:', e);
                            }
                        }
                    }
                }
            } catch (error) {
                progressContainer.remove();
                showAlert(\`Error loading devices: \${error.message}\`, 'error');
                serverInfo.textContent = \`Error loading from \${selectedServer.toUpperCase()} server\`;
            } finally {
                isLoadingDevices = false;
                btn.disabled = false;
                serverSelector.disabled = false;
                btn.innerHTML = '🔄 Refresh';
            }
        }
        
        // Scan all regions for devices
        async function scanAllRegions(currentRegion) {
            const serverInfo = document.getElementById('currentServerInfo');
            const devicesList = document.getElementById('devicesList');
            const serverSelector = document.getElementById('serverSelector');
            const btn = document.getElementById('refreshDevicesBtn');
            
            // Get regions to scan (exclude current region)
            const regionsToScan = allRegions.filter(r => r !== currentRegion);
            
            serverInfo.innerHTML = \`<strong>No devices found in \${currentRegion.toUpperCase()}. Scanning other regions...</strong>\`;
            
            // Disable controls during scan
            btn.disabled = true;
            serverSelector.disabled = true;
            
            let foundDevices = false;
            
            for (let i = 0; i < regionsToScan.length; i++) {
                const region = regionsToScan[i];
                serverInfo.innerHTML = \`<strong>Scanning \${region.toUpperCase()} region... (\${i + 1}/\${regionsToScan.length})</strong>\`;
                
                // Update the select box to show current scanning region
                serverSelector.value = region;
                
                try {
                    const response = await fetch('/api/devices', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            sessionData: currentSession,
                            server: region
                        })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success && result.devices && result.devices.length > 0) {
                        // Found devices in this region!
                        foundDevices = true;
                        serverSelector.value = region; // Update selector to found region
                        displayDevices(result.devices);
                        showAlert(\`Found \${result.devices.length} device(s) in \${region.toUpperCase()} region!\`, 'success');
                        serverInfo.textContent = \`Showing \${result.devices.length} device(s) from \${region.toUpperCase()} server\`;
                        break;
                    }
                } catch (error) {
                    debug.error(\`Error scanning \${region}:\`, error);
                }
            }
            
            if (!foundDevices) {
                serverInfo.innerHTML = '<span style="color: var(--error);">No devices found in any region. Your devices might be offline or not yet registered.</span>';
                showAlert('No devices found in any region', 'warning');
                // Restore original region selection
                serverSelector.value = currentRegion;
            }
            
            // Re-enable controls
            btn.disabled = false;
            serverSelector.disabled = false;
            btn.innerHTML = '🔄 Refresh';
        }
        
        // Display single device (for streaming)
        function displayDevice(device, container) {
            const deviceEl = createDeviceElement(device);
            container.appendChild(deviceEl);
        }
        
        // Display all devices
        function displayDevices(devices) {
            const devicesList = document.getElementById('devicesList');
            devicesList.innerHTML = '';
            
            if (!devices || devices.length === 0) {
                devicesList.innerHTML = '<p>No devices found</p>';
                return;
            }
            
            devices.forEach(device => {
                displayDevice(device, devicesList);
            });
        }
        
        // Create device element
        function createDeviceElement(device) {
            const deviceEl = document.createElement('div');
            deviceEl.className = 'device-item';
            
            // Build device info rows
            const infoRows = [];
            
            // Helper to create copyable row
            function createInfoRow(label, value, isToken = false) {
                if (!value || value === 'N/A') return '';
                const rowId = Math.random().toString(36).substr(2, 9);
                return \`
                    <div class="info-row">
                        <dt>\${label}</dt>
                        <dd class="\${isToken ? 'token' : ''}" onclick="copyToClipboard('\${value}', '\${rowId}')" id="\${rowId}">
                            \${value}
                            <span class="copy-hint">Click to copy</span>
                        </dd>
                    </div>
                \`;
            }
            
            // Always show these fields
            infoRows.push(createInfoRow('Model', device.model));
            infoRows.push(createInfoRow('DID', device.did));
            
            // Token - special styling
            if (device.token) {
                infoRows.push(createInfoRow('Token', device.token, true));
            }
            
            // Network info - only if available
            if (device.ip && device.ip !== 'undefined') {
                infoRows.push(createInfoRow('IP', device.ip));
            }
            if (device.mac) {
                infoRows.push(createInfoRow('MAC', device.mac));
            }
            
            // BLE Key - only if available
            if (device.extra?.ble_key) {
                infoRows.push(createInfoRow('BLE Key', device.extra.ble_key, true));
            }
            
            // WiFi info - only if available
            if (device.ssid) {
                infoRows.push(createInfoRow('WiFi', device.ssid));
            }
            
            deviceEl.innerHTML = \`
                <div class="device-header">
                    <div class="device-name">\${device.name || 'Unknown Device'}</div>
                    <div class="device-status">
                        <span class="status-dot \${device.isOnline ? 'online' : ''}"></span>
                        <span>\${device.isOnline ? 'Online' : 'Offline'}</span>
                    </div>
                </div>
                <div class="device-info">
                    \${infoRows.join('')}
                </div>
            \`;
            
            return deviceEl;
        }
        
        // Copy to clipboard function
        function copyToClipboard(text, elementId) {
            navigator.clipboard.writeText(text).then(() => {
                const element = document.getElementById(elementId);
                
                // Add visual feedback to the element
                element.style.transition = 'all 0.3s ease';
                element.style.background = 'rgba(40, 167, 69, 0.2)';
                element.style.borderColor = 'var(--success)';
                
                // Reset after animation
                setTimeout(() => {
                    element.style.background = '';
                    element.style.borderColor = '';
                }, 1500);
            }).catch(err => {
                // debug.error('Failed to copy:', err);
                showAlert('Failed to copy to clipboard', 'error');
            });
        }
        
        
        // Make functions available globally
        window.copyToClipboard = copyToClipboard;
        window.saveSession = saveSession;
        window.switchAuthTab = switchAuthTab;
        window.logout = logout;
        window.loadDevices = loadDevices;
    </script>
</body>
</html>`;
}

export default app;