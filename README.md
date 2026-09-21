<h1 align="center">
  <img src="./public/icons/auto.svg" alt="CloudflareSub Logo" height="40" align="absmiddle" /> CloudflareSub
</h1>

<p align="center"><em>一个轻量化的优选IP订阅器</em></p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-2ea44f" alt="License MIT" />
  <img src="https://img.shields.io/badge/platform-Windows-0078D6" alt="Windows" />
  <img src="https://img.shields.io/badge/platform-macOS-111111" alt="macOS" />
  <img src="https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black" alt="Linux" />
  <img src="https://img.shields.io/badge/runtime-Cloudflare%20Workers-F38020?logo=cloudflare&logoColor=white" alt="Cloudflare Workers" />
  <img src="https://img.shields.io/badge/status-active-00C853" alt="Status Active" />
</p>

## 功能特性

- 支持 `vmess`、`vless`、`trojan` 节点解析
- 支持 Base64 订阅文本自动展开
- 支持 `host[:port][#remark]` 格式的优选地址
- 结果写入 Workers KV，生成 `/sub/:id` 短链
- 相同输入自动去重；新订阅默认长期保存，直到主动吊销/删除
- 每条订阅使用独立 HMAC 访问令牌，可单独吊销或重新签发
- 支持 `SUB_ACCESS_TOKEN` 作为订阅签名主密钥
- 支持 `SUB_ADMIN_TOKEN` 保护生成与管理 API
- 支持导出：Raw（Base64）/ Clash（YAML）/ Surge（文本）

## 项目结构

```text
cloudflaresub/
├─ src/
│  ├─ worker.js      # Worker 入口（API + 订阅输出）
│  └─ core.js        # 解析/渲染核心函数（测试使用）
├─ public/           # 前端静态资源
├─ tests/smoke.mjs   # Smoke test
├─ wrangler.toml
└─ package.json
```

## 快速开始（Cloudflare 网页端）
```text
视频部署流程：https://youtu.be/E5PI0LsQ43M
```
下面按 Cloudflare Dashboard 流程操作，尽量不依赖命令行。

### 1) 准备代码

- 把本项目代码放到本地（你现在已经有）
- 确认 `wrangler.toml` 中 `name`、`main`、`assets` 路径与项目一致

### 2) 在 Dashboard 创建 Worker

- 打开 Cloudflare Dashboard
- 进入 `Workers & Pages`
- 点击 `Create application` -> `Create Worker`
- 先创建一个 Worker（用于初始化项目）

### 3) 绑定到 GitHub 仓库（推荐）

- 在 `Workers & Pages` 点击 `Create` -> `Import a repository`
- 授权 GitHub，并选择仓库 `InfiCheesy/cloudflaresub`
- 构建设置建议：
  - Framework preset: `None`
  - Build command: 留空
  - Build output directory: 留空
- 保存并开始部署

说明：这个项目是 Worker 项目，入口在 `src/worker.js`，静态资源在 `public/`。

### 4) 创建 KV Namespace

- 进入 `Storage & Databases` -> `KV`
- 点击 `Create namespace`
- 名称建议：`SUB_STORE`

### 5) 给 Worker 绑定 KV

- 回到 Worker 项目页面
- 进入 `Settings` -> `Bindings`
- 点击 `Add binding`，类型选择 `KV namespace`
- Variable name 填：`SUB_STORE`
- Namespace 选择上一步创建的 KV
- 保存并重新部署

### 6) 配置两个 Secret

在 Worker 项目中进入 `Settings` -> `Variables`，在 Secrets 中添加：

- `SUB_ACCESS_TOKEN`：订阅访问令牌的 HMAC 签名主密钥。建议至少 32 字节随机值。
- `SUB_ADMIN_TOKEN`：生成/查看/吊销/重新签发/删除订阅时使用的管理员密钥。建议与 `SUB_ACCESS_TOKEN` 完全不同。

说明：

- 新订阅的 URL Token 是按“订阅 ID + 随机 nonce”独立派生的，不直接暴露 `SUB_ACCESS_TOKEN`。
- 轮换 `SUB_ACCESS_TOKEN` 可以一次性使所有新格式订阅 URL 失效（全局紧急开关）。
- `SUB_ADMIN_TOKEN` 只用于管理 API，不会写入订阅 URL。
- 网页端只把管理员 Token 保存在当前标签页的 `sessionStorage`，关闭标签页后清除。
- 如果未配置 `SUB_ADMIN_TOKEN`，生成和管理 API 会返回 503。

### 7) 验证线上服务

- 打开 Worker 域名（如 `https://<name>.<subdomain>.workers.dev`）
- 访问首页 `/`，应看到前端表单
- 在页面输入节点和优选地址，点击生成
- 拿到 `/sub/:id` 后测试：
  - `?target=raw&token=...`
  - `?target=clash&token=...`
  - `?target=surge&token=...`

### 8) 后续更新代码

- 如果你使用 GitHub 自动部署：直接 push 到对应分支，Cloudflare 会自动重新部署
- 如果你不用 GitHub 自动部署：可在 Dashboard 在线编辑器中修改后手动部署

## API 说明

### `POST /api/generate`

输入原始节点与优选地址，返回短链订阅。

请求体示例：

```json
{
  "nodeLinks": "vmess://...\nvless://...",
  "preferredIps": "104.16.1.2#HK\n104.17.2.3:2053#US",
  "namePrefix": "CF",
  "keepOriginalHost": true
}
```

字段说明：
- `nodeLinks`: 多行节点链接
- `preferredIps`: 多行优选地址，格式 `host[:port][#remark]`
- `namePrefix`: 节点名附加前缀
- `keepOriginalHost`: 是否保留原始 Host/SNI（默认 `true`）

返回示例（节选）：

```json
{
  "ok": true,
  "shortId": "AbC123xYz9",
  "urls": {
    "auto": "https://<worker>/sub/AbC123xYz9?token=...",
    "raw": "https://<worker>/sub/AbC123xYz9?target=raw&token=...",
    "clash": "https://<worker>/sub/AbC123xYz9?target=clash&token=...",
    "surge": "https://<worker>/sub/AbC123xYz9?target=surge&token=..."
  }
}
```

### `GET /sub/:id`

按 `target` 返回订阅内容：
- `target=raw`（默认）
- `target=clash`
- `target=surge`

示例：

```bash
curl "https://<worker>/sub/<id>?target=clash&token=<SUB_ACCESS_TOKEN>"
```

## 前端页面

根路径 `/` 提供网页表单（来自 `public/`）：
- 粘贴节点链接
- 粘贴优选 IP / 域名
- 生成并展示各客户端订阅链接
- 一键复制 / 生成二维码


## 注意事项

- `src/worker.js` 当前是 KV 短链方案，不依赖 `SUB_LINK_SECRET`
- 新格式订阅默认不设置 TTL，会一直保存到主动吊销或删除
- Surge 导出当前仅包含 `vmess` / `trojan`


## 订阅安全与吊销

新版本把“固定 7 天 TTL”改成“长期有效 + 可主动吊销”：

- 每条订阅都有独立访问 Token。
- KV 中不保存订阅访问 Token 明文；Token 由 `SUB_ACCESS_TOKEN`、订阅 ID 与随机 nonce 通过 HMAC 派生。
- “吊销”会让旧订阅 URL 立即返回 `410 Gone`。
- “重新签发”会吊销旧 ID，并生成新的 ID 与新的访问 Token。
- “删除”会永久删除对应 KV 记录。

管理 API：

```text
GET    /api/subscriptions
POST   /api/subscriptions/:id/revoke
POST   /api/subscriptions/:id/reissue
DELETE /api/subscriptions/:id
```

这些接口，以及 `POST /api/generate`，都要求请求头：

```text
X-Admin-Token: <SUB_ADMIN_TOKEN>
```

也支持：

```text
Authorization: Bearer <SUB_ADMIN_TOKEN>
```

### 重要安全边界

吊销订阅 URL 只能阻止“再次下载订阅”。如果链接已经泄漏且他人已经把 VLESS UUID、Trojan 密码等节点凭据保存到客户端，仍需要在真实节点端轮换 UUID/密码，才能让已下载的旧节点彻底失效。

### 旧记录兼容

代码仍兼容旧版 KV 记录；旧记录继续使用历史的全局 `SUB_ACCESS_TOKEN` 校验。重新签发旧记录后会迁移到新格式。

## License

MIT
