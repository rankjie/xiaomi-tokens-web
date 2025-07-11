import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { XiaomiCloudConnector } from './xiaomi-client';
import { XiaomiCloudConnectorBrowser } from './xiaomi-client-browser';
import type { LoginCredentials, LoginResponse, DevicesResponse, SessionData } from './types';

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
    
    // Recreate client from state
    const client = XiaomiCloudConnectorBrowser.fromClientState(clientState);
    
    // Check identity options and verify ticket
    const identityCheck = await (client as any).checkIdentityOptions();
    if (!identityCheck) {
      // console.error("Failed to check identity options");
    }
    
    const verifyResult = await client.verify2FATicket(ticket);
    if (!verifyResult.success) {
      return c.json<LoginResponse>({ success: false, error: verifyResult.error });
    }
    
    // Clear identity session as per Python implementation
    (client as any).identitySession = null;
    
    // Retry login step 2 after successful 2FA (as per Python implementation)
    // console.log("Retrying login step 2 after 2FA verification...");
    // console.log("Current cookies before retry:", (client as any).cookies);
    // console.log("Current sign:", (client as any).sign);
    
    const step2Result = await client.loginStep2();
    if (!step2Result.success) {
      // Check if it's still asking for 2FA
      if (step2Result.requires2FA) {
        // console.error("Still requiring 2FA after verification - session state issue");
        return c.json<LoginResponse>({ success: false, error: 'Session state not properly maintained after 2FA' });
      }
      return c.json<LoginResponse>({ success: false, error: step2Result.error || 'Login failed after 2FA' });
    }
    
    // Complete login with step 3
    const step3Success = await client.loginStep3();
    if (!step3Success) {
      return c.json<LoginResponse>({ success: false, error: 'Login step 3 failed after 2FA' });
    }
    
    const session = client.getSessionData();
    return c.json<LoginResponse>({ success: true, session });
  } catch (error: any) {
    // console.error("2FA endpoint error:", error);
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
        await writer.write(encoder.encode(`data: ${JSON.stringify({ type: 'status', message: 'Validating session...' })}\n\n`));
        
        // Validate session
        const isValid = await client.validateSession();
        if (!isValid) {
          await writer.write(encoder.encode(`data: ${JSON.stringify({ type: 'error', message: 'Session expired' })}\n\n`));
          await writer.close();
          return;
        }
        
        await writer.write(encoder.encode(`data: ${JSON.stringify({ type: 'status', message: 'Session validated. Fetching devices...' })}\n\n`));
        
        let writerClosed = false;
        
        // Set up progress callback
        client.onProgress = async (progress: any) => {
          if (!writerClosed) {
            try {
              await writer.write(encoder.encode(`data: ${JSON.stringify({ type: 'progress', ...progress })}\n\n`));
            } catch (e) {
              console.error('Failed to write progress:', e);
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
        console.error('Stream processing error:', error);
        try {
          await writer.write(encoder.encode(`data: ${JSON.stringify({ type: 'error', message: error.message })}\n\n`));
        } catch (e) {
          console.error('Failed to write error:', e);
        }
      } finally {
        try {
          await writer.close();
        } catch (e) {
          console.error('Failed to close writer:', e);
        }
      }
    })();
    
    return c.body(stream.readable);
  } catch (error: any) {
    // console.error('Stream error:', error);
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
    // console.error('Get devices error:', error);
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
    <style>
        :root {
            --primary: #ff6900;
            --primary-dark: #e55a00;
            --primary-light: #ff8533;
            --bg: #f8f9fa;
            --card-bg: white;
            --text: #212529;
            --text-secondary: #6c757d;
            --border: #dee2e6;
            --border-light: #e9ecef;
            --success: #28a745;
            --error: #dc3545;
            --warning: #ffc107;
            --info: #17a2b8;
            --shadow: 0 0.125rem 0.25rem rgba(0,0,0,0.075);
            --shadow-lg: 0 0.5rem 1rem rgba(0,0,0,0.15);
            --radius: 0.375rem;
            --radius-lg: 0.5rem;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .header {
            text-align: center;
            margin-bottom: 3rem;
        }
        
        h1 {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }
        
        .subtitle {
            color: var(--text-secondary);
            font-size: 1.125rem;
        }
        
        .card {
            background: var(--card-bg);
            border-radius: var(--radius-lg);
            padding: 2rem;
            margin-bottom: 1.5rem;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-light);
            transition: box-shadow 0.3s ease;
        }
        
        .card:hover {
            box-shadow: var(--shadow-lg);
        }
        
        .card-header {
            display: flex;
            align-items: center;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-light);
        }
        
        .card-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            border-radius: var(--radius);
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 1rem;
            color: white;
            font-size: 1.25rem;
        }
        
        .card h2 {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--text);
        }
        
        .auth-tabs {
            display: flex;
            border-bottom: 2px solid var(--border-light);
            margin-bottom: 2rem;
        }
        
        .auth-tab {
            flex: 1;
            padding: 1rem;
            background: none;
            border: none;
            border-bottom: 3px solid transparent;
            color: var(--text-secondary);
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s;
            box-shadow: none;
            border-radius: 0;
            display: block;
            gap: 0;
        }
        
        .auth-tab:hover {
            color: var(--text);
            background: var(--bg);
            transform: none;
            box-shadow: none;
        }
        
        .auth-tab.active {
            color: var(--primary);
            border-bottom-color: var(--primary);
            background: transparent;
        }
        
        .auth-content {
            display: none;
        }
        
        .auth-content.active {
            display: block;
        }
        
        .drop-zone {
            border: 2px dashed var(--border);
            border-radius: var(--radius-lg);
            padding: 3rem 2rem;
            text-align: center;
            transition: all 0.3s;
            cursor: pointer;
            background: var(--bg);
        }
        
        .drop-zone:hover,
        .drop-zone.drag-over {
            border-color: var(--primary);
            background: rgba(255, 105, 0, 0.05);
        }
        
        .drop-zone-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .devices-grid {
                grid-template-columns: 1fr;
            }
            
            h1 {
                font-size: 2rem;
            }
            
            .card {
                padding: 1.5rem;
            }
            
            .card-header > div:first-child {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .card-header > div:last-child {
                margin-top: 1rem;
                width: 100%;
            }
            
            .card-header button {
                width: 48%;
            }
        }
        
        .form-group {
            margin-bottom: 1.25rem;
        }
        
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--text);
            font-size: 0.875rem;
        }
        
        input, select {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 2px solid var(--border-light);
            border-radius: var(--radius);
            font-size: 1rem;
            transition: border-color 0.3s, box-shadow 0.3s;
            background-color: var(--bg);
        }
        
        input:focus, select:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(255, 105, 0, 0.1);
        }
        
        button {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: var(--radius);
            cursor: pointer;
            font-size: 1rem;
            font-weight: 500;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 2px 4px rgba(255, 105, 0, 0.2);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }
        
        button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(255, 105, 0, 0.3);
        }
        
        button:active {
            transform: translateY(0);
        }
        
        button:disabled {
            opacity: 0.6;
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
            color: var(--primary);
            border: 2px solid var(--primary);
            box-shadow: none;
        }
        
        .button-secondary:hover {
            background: var(--primary);
            color: white;
        }
        
        #alerts {
            position: fixed;
            top: 1rem;
            right: 1rem;
            z-index: 1000;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            max-width: 400px;
        }
        
        .alert {
            padding: 1rem 1.5rem;
            border-radius: var(--radius);
            box-shadow: var(--shadow-lg);
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
            background: white;
            color: var(--success);
            border: 1px solid #d4edda;
        }
        
        .alert-success::before {
            background: var(--success);
        }
        
        .alert-error {
            background: white;
            color: var(--error);
            border: 1px solid #f8d7da;
        }
        
        .alert-error::before {
            background: var(--error);
        }
        
        .alert-warning {
            background: white;
            color: var(--warning);
            border: 1px solid #fff3cd;
        }
        
        .alert-warning::before {
            background: var(--warning);
        }
        
        .device-list {
            display: grid;
            gap: 15px;
        }
        
        .devices-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
            gap: 1.5rem;
        }
        
        .device-item {
            background: var(--card-bg);
            padding: 1.5rem;
            border-radius: var(--radius-lg);
            border: 1px solid var(--border-light);
            transition: all 0.3s ease;
            animation: slideIn 0.3s ease;
            box-shadow: var(--shadow);
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
            box-shadow: var(--shadow-lg);
            transform: translateY(-2px);
        }
        
        .device-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-light);
        }
        
        .device-name {
            font-weight: 600;
            color: var(--text);
            font-size: 1.125rem;
            line-height: 1.2;
        }
        
        .device-status {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--border);
        }
        
        .status-dot.online {
            background: var(--success);
            box-shadow: 0 0 0 2px rgba(40, 167, 69, 0.2);
        }
        
        .device-info {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }
        
        .info-row {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            position: relative;
        }
        
        .info-row dt {
            font-weight: 500;
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            min-width: 60px;
        }
        
        .info-row dd {
            flex: 1;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 0.875rem;
            color: var(--text);
            margin: 0;
            padding: 0.5rem 0.75rem;
            background: var(--bg);
            border-radius: var(--radius);
            border: 2px solid var(--border-light);
            word-break: break-all;
            cursor: pointer;
            transition: all 0.2s ease;
            position: relative;
            overflow: hidden;
        }
        
        .info-row dd:hover {
            background: white;
            border-color: var(--primary);
            transform: translateY(-1px);
            box-shadow: 0 2px 8px rgba(255, 105, 0, 0.15);
        }
        
        .info-row dd:active {
            transform: translateY(0);
            box-shadow: 0 1px 4px rgba(255, 105, 0, 0.15);
        }
        
        .info-row dd.token {
            background: #fff5e6;
            border-color: #ffd4a3;
            font-weight: 500;
        }
        
        .copy-hint {
            position: absolute;
            right: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            font-size: 0.75rem;
            color: var(--text-secondary);
            opacity: 0;
            transition: opacity 0.2s;
            pointer-events: none;
        }
        
        .info-row dd:hover .copy-hint {
            opacity: 1;
        }
        
        
        .progress-container {
            background: #fff;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .progress-message {
            color: #666;
            margin-bottom: 10px;
        }
        
        .progress-bar {
            width: 100%;
            height: 4px;
            background: #f0f0f0;
            border-radius: 2px;
            overflow: hidden;
        }
        
        .progress-bar-fill {
            height: 100%;
            background: var(--primary);
            transition: width 0.3s ease;
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
            background: #fff3e0;
            padding: 20px;
            border-radius: 4px;
            margin-top: 20px;
        }
        
        .verify-url {
            background: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            word-break: break-all;
            margin: 10px 0;
            font-family: monospace;
            overflow-x: auto;
            white-space: nowrap;
        }
        
        .verify-url a {
            color: var(--primary);
            text-decoration: none;
        }
        
        .verify-url a:hover {
            text-decoration: underline;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 1s ease-in-out infinite;
            vertical-align: middle;
            margin: 0;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .privacy-notice {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 2rem;
            margin-top: 3rem;
            position: relative;
            overflow: hidden;
        }
        
        .privacy-notice::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: linear-gradient(180deg, var(--primary) 0%, var(--primary-dark) 100%);
        }
        
        .privacy-notice h3 {
            color: var(--text);
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.25rem;
        }
        
        .privacy-notice .icon {
            font-size: 1.5rem;
        }
        
        .privacy-content {
            color: var(--text-secondary);
            line-height: 1.8;
        }
        
        .privacy-section {
            margin-bottom: 1.5rem;
        }
        
        .privacy-section h4 {
            color: var(--text);
            font-size: 1rem;
            margin-bottom: 0.5rem;
            font-weight: 600;
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
            color: var(--primary);
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
                        <label for="username">Username (Email/Phone)</label>
                        <input type="text" id="username" name="username" required placeholder="email@example.com or phone number">
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <div class="form-group">
                        <label for="server">Server Region</label>
                        <select id="server" name="server">
                            <option value="cn">China (cn)</option>
                            <option value="de">Germany (de)</option>
                            <option value="us">United States (us)</option>
                            <option value="ru">Russia (ru)</option>
                            <option value="tw">Taiwan (tw)</option>
                            <option value="sg">Singapore (sg)</option>
                            <option value="in">India (in)</option>
                            <option value="i2">International (i2)</option>
                        </select>
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
            <div class="card-header" style="justify-content: space-between; align-items: center;">
                <div style="display: flex; align-items: center;">
                    <div class="card-icon">📱</div>
                    <h2>Devices</h2>
                </div>
                <button id="refreshDevicesBtn" class="button-secondary" style="padding: 0.5rem 1rem; font-size: 0.875rem;" onclick="loadDevices()">
                    🔄 Refresh Devices
                </button>
            </div>
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
                    <p style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 0.5rem;">
                        <strong>Disclaimer:</strong> This is an unofficial tool not affiliated with Xiaomi. Use at your own risk. 
                        The tool replicates the functionality of the Python-based Xiaomi-cloud-tokens-extractor project in a web interface.
                    </p>
                    <p style="font-size: 0.75rem; color: var(--text-secondary); text-align: center; margin: 0;">
                        Version 1.0.0
                    </p>
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
                                <div style="display: flex; gap: 1.5rem; font-size: 0.875rem; color: var(--text-secondary);">
                                    <span><strong>User:</strong> \${currentSession.username}</span>
                                    <span><strong>ID:</strong> \${currentSession.userId}</span>
                                    <span><strong>Session:</strong> \${savedAt}</span>
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
        
        // Load devices with streaming
        async function loadDevices() {
            if (!currentSession) return;
            
            const btn = document.getElementById('refreshDevicesBtn');
            const devicesList = document.getElementById('devicesList');
            const devicesSection = document.getElementById('devicesSection');
            
            btn.disabled = true;
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
                const serverElement = document.getElementById('server');
                const server = serverElement ? serverElement.value : (currentSession.server || 'cn');
                
                const response = await fetch('/api/devices-stream', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        sessionData: currentSession,
                        server: server
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
                                        showAlert(\`Found \${data.devices?.length || devices.length} device(s)\`, 'success');
                                        break;
                                        
                                    case 'error':
                                        progressContainer.remove();
                                        showAlert(\`Error: \${data.message}\`, 'error');
                                        break;
                                }
                            } catch (e) {
                                // console.error('Failed to parse SSE data:', e);
                            }
                        }
                    }
                }
            } catch (error) {
                progressContainer.remove();
                showAlert(\`Error loading devices: \${error.message}\`, 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = 'Refresh Devices';
            }
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
                // console.error('Failed to copy:', err);
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