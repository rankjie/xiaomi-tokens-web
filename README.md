# Xiaomi Token Web

[中文版](README_CN.md) | English

A modern web interface for extracting device tokens from your Xiaomi account. Built with TypeScript, Hono.js, and deployable to Cloudflare Workers and other edge platforms.

🚀 **Live Demo**: [https://xiaomi-token-web.asd.workers.dev/](https://xiaomi-token-web.asd.workers.dev/)

## Features

- 🔐 Xiaomi account login with 2FA support
- 💾 Session save/load functionality
- 📱 Device information extraction with tokens
- 🌐 Multi-region server support with auto-discovery
- ⚡ Edge-ready deployment with Hono.js
- 🔍 Automatic region scanning

## Important Notice

⚠️ **Privacy Warning**: The hosted version processes your credentials through a third-party server. For maximum privacy and security, it is **HIGHLY RECOMMENDED** to deploy your own instance.

## Quick Start

### Deploy Your Own (Recommended)

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/rankjie/xiaomi-tokens-web)

### Use the Hosted Version (Use at Your Own Risk)
Visit [https://xiaomi-token-web.asd.workers.dev/](https://xiaomi-token-web.asd.workers.dev/) - Not recommended for privacy-sensitive users.

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

# Enable debug logging (sensitive data is automatically sanitized)
DEBUG=true npm run serve
# or
DEBUG=1 npm run dev
```

## Deployment Options

### Deploy to Cloudflare Workers
```bash
npm run deploy
```

### Deploy to Cloudflare Pages
1. Fork this repository
2. Go to [Cloudflare Pages](https://pages.cloudflare.com/)
3. Connect your GitHub account
4. Create a new project and select your fork
5. Use these build settings:
   - Framework preset: `None`
   - Build command: `npm install && npm run build`
   - Build output directory: `/`

### Deploy to other platforms
The app is built with Hono.js which supports multiple platforms. Check [Hono's documentation](https://hono.dev/) for platform-specific deployment guides.

## Usage Guide

1. **Login**
   - Enter your Xiaomi account credentials (email, phone, or Xiaomi ID)
   - Select your server region (or let auto-discovery find your devices)
   - Click Login

2. **Two-Factor Authentication (if enabled)**
   - Open the provided URL in a browser
   - Request a verification code via SMS or email
   - **Important**: DO NOT complete verification on Xiaomi's website
   - Enter the 6-digit code in the web interface

3. **View Devices**
   - After successful login, your devices will be displayed
   - Click on any value to copy it to clipboard
   - Switch regions using the dropdown if needed

4. **Session Management**
   - Save your session for future use (avoids repeated login)
   - Load previously saved sessions
   - Sessions are compatible with the Python version

## Security & Privacy

- ✅ **No server storage**: All data stays in your browser
- ✅ **Direct API calls**: Communicates directly with Xiaomi servers
- ✅ **Open source**: Fully auditable code
- ✅ **Session encryption**: Uses Xiaomi's official encryption methods
- ⚠️ **Use at your own risk**: This is an unofficial tool

## Technical Details

### Authentication Flow
- Three-step login process matching Xiaomi's official flow
- 2FA support with SMS/email verification
- Proper session cookie management

### API Implementation
- RC4 encryption/decryption for secure API calls
- SHA1/SHA256-based signature generation
- Support for all required Xiaomi IoT v2 endpoints

### Supported Endpoints
- `/v2/homeroom/gethome` - Retrieve user's homes
- `/v2/home/home_device_list` - Get devices for each home
- `/v2/user/get_device_cnt` - Validate session status

### Device Information Retrieved
- Device name and model
- Device ID (DID)
- Token (for local control)
- IP address and MAC address
- BLE key (for Bluetooth devices)
- Online/offline status

## Related Projects

- [Original Python Version](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor) by PiotrMachowski
- [Home Assistant Xiaomi Integration](https://github.com/al-one/hass-xiaomi-miot)

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).

### Important License Requirements:
- ❌ **No commercial use** - This project cannot be used for commercial purposes
- 📖 **Open source required** - Any derivative work must also be open-sourced under GPL-3.0
- 🔗 **Share alike** - If you modify and distribute this project, you must use the same license

See the [LICENSE](LICENSE) file for full details.

## Disclaimer

### NO WARRANTY

THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. 

- ❌ **NO GUARANTEE** that this will work for your account or devices
- ❌ **NO GUARANTEE** of continued functionality or maintenance
- ❌ **NO SUPPORT** - Issues may or may not be addressed
- ❌ **USE AT YOUR OWN RISK** - You are solely responsible for any consequences

This is an unofficial tool not affiliated with Xiaomi. The author(s) assume no responsibility for:
- Account security issues
- Data loss or exposure
- Service disruptions
- Any damages arising from use of this software

**STRONGLY RECOMMENDED**: Deploy your own instance to maintain control over your credentials and data.