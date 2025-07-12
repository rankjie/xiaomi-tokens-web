# Xiaomi Token Web

中文版 | [English](README.md)

用于从小米账户提取设备令牌的现代化 Web 界面。基于 TypeScript 和 Hono.js 构建，可部署到 Cloudflare Workers 及其他边缘平台。

🚀 **在线演示**: [https://xiaomi-token-web.asd.workers.dev/](https://xiaomi-token-web.asd.workers.dev/)

## 功能特性

- 🔐 支持小米账户登录及两步验证
- 💾 会话保存/加载功能
- 📱 提取设备信息和令牌
- 🌐 多区域服务器支持及自动发现
- ⚡ 支持边缘部署（基于 Hono.js）
- 🔍 自动区域扫描

## 重要提示

⚠️ **隐私警告**：在线版本会通过第三方服务器处理您的登录凭据。为了最大程度保护隐私和安全，**强烈建议** 您部署自己的实例。

## 快速开始

### 部署您自己的实例（推荐）

[![部署到 Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/rankjie/xiaomi-tokens-web)

### 使用在线版本（风险自负）
访问 [https://xiaomi-token-web.asd.workers.dev/](https://xiaomi-token-web.asd.workers.dev/) - 不建议对隐私敏感的用户使用。

## 开发

### 环境要求
- Node.js 18+
- npm 或 yarn

### 安装依赖
```bash
npm install
```

### 本地开发
```bash
# 使用 tsx 运行（Node.js）
npm run serve

# 使用 Wrangler 运行（Cloudflare Workers 模拟）
npm run dev

# 启用调试日志（敏感数据会自动脱敏）
DEBUG=true npm run serve
# 或
DEBUG=1 npm run dev
```

## 部署选项

### 部署到 Cloudflare Workers
```bash
npm run deploy
```

### 部署到 Cloudflare Pages
1. Fork 本仓库
2. 访问 [Cloudflare Pages](https://pages.cloudflare.com/)
3. 连接您的 GitHub 账户
4. 创建新项目并选择您 fork 的仓库
5. 使用以下构建设置：
   - 框架预设：`None`
   - 构建命令：`npm install && npm run build`
   - 构建输出目录：`/`

### 部署到其他平台
本应用基于 Hono.js 构建，支持多个平台。请查看 [Hono 文档](https://hono.dev/) 了解特定平台的部署指南。

## 使用指南

1. **登录**
   - 输入您的小米账户凭据（邮箱、手机号或小米 ID）
   - 选择您的服务器区域（或让系统自动发现您的设备）
   - 点击登录

2. **两步验证（如已启用）**
   - 在浏览器中打开提供的 URL
   - 通过短信或邮箱获取验证码
   - **重要**：请勿在小米官网完成验证
   - 在 Web 界面中输入 6 位验证码

3. **查看设备**
   - 登录成功后，您的设备将会显示
   - 点击任意值可复制到剪贴板
   - 如需要可使用下拉菜单切换区域

4. **会话管理**
   - 保存您的会话以供将来使用（避免重复登录）
   - 加载之前保存的会话文件
   - 会话与 Python 版本兼容

## 安全与隐私

- ✅ **无服务器存储**：所有数据保留在您的浏览器中
- ✅ **直接 API 调用**：直接与小米服务器通信
- ✅ **开源代码**：代码完全可审计
- ✅ **会话加密**：使用小米官方加密方法
- ⚠️ **风险自负**：这是非官方工具

## 技术细节

### 认证流程
- 三步登录流程，与小米官方流程一致
- 支持短信/邮箱验证的两步验证
- 正确的会话 cookie 管理

### API 实现
- RC4 加密/解密用于安全 API 调用
- 基于 SHA1/SHA256 的签名生成
- 支持所有必需的小米 IoT v2 端点

### 支持的端点
- `/v2/homeroom/gethome` - 获取用户的家庭
- `/v2/home/home_device_list` - 获取每个家庭的设备
- `/v2/user/get_device_cnt` - 验证会话状态

### 获取的设备信息
- 设备名称和型号
- 设备 ID (DID)
- 令牌（用于本地控制）
- IP 地址和 MAC 地址
- BLE 密钥（用于蓝牙设备）
- 在线/离线状态

## 相关项目

- [原始 Python 版本](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor) 作者：PiotrMachowski
- [Home Assistant 小米集成](https://github.com/al-one/hass-xiaomi-miot)

## 许可证

本项目采用 GNU 通用公共许可证 v3.0 (GPL-3.0) 授权。

### 重要许可证要求：
- ❌ **禁止商业使用** - 本项目不能用于商业目的
- 📖 **必须开源** - 任何衍生作品也必须在 GPL-3.0 下开源
- 🔗 **相同方式共享** - 如果您修改并分发本项目，必须使用相同的许可证

详情请参阅 [LICENSE](LICENSE) 文件。

## 免责声明

### 无任何保证

本软件按"原样"提供，不附带任何明示或暗示的保证。

- ❌ **不保证** 能够适用于您的账户或设备
- ❌ **不保证** 持续功能或维护
- ❌ **不提供支持** - 问题可能会或可能不会得到解决
- ❌ **风险自负** - 您对使用后果承担全部责任

这是一个非官方工具，与小米公司无关。作者对以下情况不承担任何责任：
- 账户安全问题
- 数据丢失或泄露
- 服务中断
- 使用本软件产生的任何损害

**强烈建议**：部署您自己的实例以保持对您的凭据和数据的控制。