# ZeppBridge Cloud

[English](README.md)

ZeppBridge「推送到你自己的站点」（设置 › Beta 实验室 › Personal Agent 选项）用的站点模板。
ZeppBridge 每次同步后在你的电脑上把数据加密，推到你自己的站点；手机或 Personal Agent 再用只读密钥从那里读。

- **站点上只有密文**：数据密钥只在你的电脑和你发出的只读密钥里，Worker 自己解不开存储。
- **不推 GPS**：带坐标的对象 ZeppBridge 不会发出去。
- **缺的数据是 `null`**：不补零、不插值。
- **哪个系统都能搭**：部署站点和生成密钥在 Windows、macOS、Linux 上做法一样。上传由 ZeppBridge（3.2 起）在各平台自己完成，搭好以后本仓库没有任何东西在你电脑上运行。

## 目录

| 目录 | 是什么 |
|---|---|
| `worker/` | Cloudflare Worker：只存密文，凭只读密钥返回 |
| `uploader/keys.mjs` | 建租户、生成连接码、发和作废只读密钥 |
| `shared/crypto.mjs` | Worker、`keys.mjs` 和 ZeppBridge 共用的加密格式（WebCrypto：AES-GCM / HKDF / ECDH） |
| `tests/` | `npm test`（node:test，不联网） |

## 搭建

需要 Node 20 以上、一个 Cloudflare 账号和一个放在 Cloudflare 上的域名。Workers 免费版就够。

### 1. 安装并登录

```sh
npm install
npx wrangler login
```

### 2. 建存储

```sh
npx wrangler kv namespace create zeppbridge-cloud
```

把输出的 `id` 填进 `worker/wrangler.jsonc`，替换 `<YOUR_KV_NAMESPACE_ID>`。账号开了 R2 的话也可以改用存储桶，`wrangler.jsonc` 的注释里写了怎么换。

### 3. 填域名并部署

把 `worker/wrangler.jsonc` 里的 `health.example.com` 换成 `health.<你的域名>`，然后：

```sh
npm run worker:deploy
```

### 4. 生成连接码

```sh
node uploader/keys.mjs init
```

它输出一行 JSON，里面有 `tenant`、`dk`、`writeKey`、`readKey`。

- **整行就是连接码**：和站点地址一起填进 ZeppBridge（推送到你自己的站点 › 连接码），它会存进系统凭据库。
- **`readKey` 是只读密钥**，给手机或 Personal Agent 用。
- 这些都等于密码：别存进文件、别提交、别发给别人。还没贴进去就弄丢了，再跑一次 `init`，用新的那行。

### 5. 读数据

每个请求带 `Authorization: Bearer <只读密钥>`，返回 JSON（gzip）。先读 `GET https://health.<你的域名>/v1`，它列出全部路由。

| 路由 | 内容 |
|---|---|
| `/v1/summary` | 近些天每个本地日一行；单位在 `units`，缺失为 `null` |
| `/v1/contract` | 单位、时区、来源、缺失值规则 |
| `/v1/status` | ZeppBridge 上次推送、上次从 Zepp 同步的时间 |
| `/v1/index` | 存了哪些天和哪些运动 |
| `/v1/days/<YYYY-MM-DD>`、`/v1/workouts/<id>` | 某一天、某次运动 |
| `/v1/profile`、`/v1/context`、`/v1/plan`、`/v1/baselines`、`/v1/data-health` | 和本机 AI 经 MCP 看到的同一份 |

## 再发只读密钥

一个读者一把，可以单独作废。两条命令都从标准输入读密钥，不会留在命令历史里：

```sh
echo '{"dk":"…","writeKey":"zbw_…"}' | node uploader/keys.mjs add-reader --label phone
echo '{"writeKey":"zbw_…"}' | node uploader/keys.mjs revoke-reader --label phone
```

作废要在发密钥的那台电脑上做：`keys.mjs` 把每个名字和密钥哈希（不含密钥本身）记在 `readers.json`，位置在 Windows 的 `%LOCALAPPDATA%\ZeppBridgeCloud`、macOS 的 `~/Library/Application Support/ZeppBridgeCloud`、Linux 的 `~/.local/state/zeppbridge-cloud`。

## 安全

- 密钥只打印到标准输出；`keys.mjs` 写存储记录时经过一个用完即删的临时文件。
- `wrangler.jsonc` 里关着 Workers Logs，否则它会记下 `Authorization` 请求头。
- 写入密钥只能在白名单路径下放或删密文，什么都读不了；认证失败一律同一个 `401`。
- 在 ZeppBridge 里移除推送不会删站点上已有的数据；要清掉就删 KV 命名空间或 R2 存储桶。

## 许可

MIT
