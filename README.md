# Xiaomi Token Web

Web version of Xiaomi Cloud Tokens Extractor built with TypeScript, Hono.js, and deployable to Cloudflare Workers, Vercel, and other edge platforms.

## Quick Deploy

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/rankjie/xiaomi-tokens-web)

## Features

- 🔐 Xiaomi account login with 2FA support
- 💾 Session save/load functionality
- 📱 Device information extraction
- 🌐 Multi-region server support
- ⚡ Edge-ready with Hono.js
- 📝 TypeScript for type safety

## Development

### Prerequisites
- Node.js 18+
- npm or yarn

### Install dependencies
```bash
npm install
```

### Local development
```bash
# Run with tsx (Node.js)
npm run serve

# Run with Wrangler (Cloudflare Workers emulation)
npm run dev
```

## Deployment

### Deploy to Vercel (Recommended)
Click the deploy button above or run:
```bash
vercel
```

### Deploy to Cloudflare Workers
Click the deploy button above or run:
```bash
npm run deploy
```

### Deploy to Cloudflare Pages
1. Fork this repository
2. Go to [Cloudflare Pages](https://pages.cloudflare.com/)
3. Connect your GitHub account
4. Click "Create a project"
5. Select your forked repository
6. Set the following build settings:
   - Framework preset: `None`
   - Build command: `npm install && npm run build`
   - Build output directory: `/`
   - Environment variables: None required

### Deploy to other platforms
The app is built with Hono.js which supports multiple platforms. Check [Hono's documentation](https://hono.dev/) for platform-specific deployment guides.

## Usage

1. Open the web interface
2. Enter your Xiaomi account credentials
3. Select your server region
4. If 2FA is required:
   - Open the provided URL in a browser
   - Get the verification code
   - **DO NOT** complete verification on Xiaomi's website
   - Enter the code in the web interface
5. Save your session for future use
6. View your devices and their tokens

## Session Management

- **Save Session**: Download your session as a JSON file
- **Load Session**: Upload a previously saved session file
- **Validate Session**: Check if your session is still valid

## Security Notes

- Sessions are stored locally in your browser
- No data is stored on the server
- All API calls are made directly to Xiaomi's servers
- Use at your own risk

## Current Status

### ✅ Working Features
- Login with username/password
- 2FA verification flow  
- Session persistence (save/load)
- Compatible with Python-saved sessions
- **Device listing with RC4 encrypted API** (✅ NEW!)
- Retrieves all owned and shared devices
- Extracts device tokens, IPs, MACs, and other info

### Technical Implementation

1. **Authentication**: Matches Python implementation exactly
   - Three-step login process
   - 2FA support with identity verification
   - Session cookie management

2. **RC4 Encrypted API**: Full implementation of Python's encrypted API calls
   - RC4 encryption/decryption for requests and responses
   - SHA1-based signature generation for encrypted calls
   - Supports all v2 API endpoints

3. **Signature Generation**:
   - Nonce: 8 random bytes + 4 time bytes (big-endian)
   - Signed nonce: SHA256(base64_decode(ssecurity) + base64_decode(nonce))
   - Regular signature: HMAC-SHA256 with signed_nonce as key
   - Encrypted signature: SHA1 hash of method|path|params|signed_nonce

4. **API Endpoints**:
   - `/v2/homeroom/gethome` - Get user's homes
   - `/v2/home/home_device_list` - Get devices for a home
   - `/v2/user/get_device_cnt` - Validate session and get device counts

5. **Required Headers & Cookies**:
   - `MIOT-ENCRYPT-ALGORITHM: ENCRYPT-RC4`
   - `x-xiaomi-protocal-flag-cli: PROTOCAL-HTTP2`
   - userId, serviceToken, yetAnotherServiceToken
   - locale, timezone, is_daylight, dst_offset, channel
   - sdkVersion: accountsdk-18.8.15
   - deviceId

## License

MIT