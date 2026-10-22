# yice-sso

一个父域下多个 Web 共用的**飞书单点登录**服务。登录一次，`a.example.com`、`b.example.com` 都认。它只回答「你是谁、是不是允许企业的人」；「能不能用这个应用、能做什么」仍由各应用自己决定。

- **多企业**：每家企业一个飞书企业自建应用。主企业按在职名单放行，离职一小时内失效；合作企业按租户放行。
- **会话在服务端**：cookie 只装一个随机 token，应用只拿 `sha256(token)` 来问；会话滑动 30 天，可随时撤销。
- **应用接入很薄**：跳转登录、调一个 `verify` 接口、登出时调 `revoke`。不用每个应用各接一遍飞书 OAuth。
- **可审计**：登录、登出、撤会话都写进只追加的 `login_event`，数据库触发器拒绝改删；请求日志是 JSONL。
- **一条命令部署**：建新版本、自检通过才切换，不健康就自动回滚。

```text
 浏览器 ──https──▶ nginx（父域）──/sso/*──▶ yice-sso :8773 ──OAuth──▶ 飞书开放平台
   │  cookie: yice_sso（Domain=父域）           │ ▲
   ▼                                            │ │ /v1/sessions/verify|revoke
 Web A / Web B ──────────内网 Bearer token────────┘ │（调用方 token + 来源网段）
                                                    ▼
                                      MySQL yice_sso（会话、OAuth state、登录审计）
                                      + 只读在职名单（member / dept）
```

## 目录

| 路径 | 内容 |
| --- | --- |
| `sso_service/` | FastAPI 服务与 CLI：`api` 路由、`service` 登录与会话规则、`store` MySQL、`feishu` OAuth、`providers` / `callers` 目录 |
| `config/` | `providers.v1.json`（登录企业）、`callers.v1.json`（接入的 Web）：只写变量名，值在 `.env` |
| `schema/` | 建库 DDL 与运行账号的最小授权 |
| `deploy/` | 一键部署脚本、systemd unit、探活 timer、logrotate、nginx 片段、生产 env 模板 |
| `docs/` | [飞书企业应用与告警 bot 设计](docs/feishu-apps.md)、[一键部署](docs/deploy.md) |
| `tests/` | 服务规则、HTTP 合同、目录校验、部署脚本漂移检查，以及临时 `mysqld` 上的真实 SQL 与权限 |

## 快速开始（本地）

```bash
uv sync --locked
uv run --locked pytest -q             # 不读真实凭证、不发外部请求；本机没有 mysqld 时跳过 MySQL 用例
cp .env.example .env                  # 填本地 MySQL 与一个飞书测试应用
bin/yice-sso --self-check             # 配置、企业凭证、调用方 token、数据库表与名单权限
bin/yice-sso serve --port 8773
```

`SSO_WEB_URL` 用 `http://` 时 cookie 不带 `Secure`、只对本机有效，方便本地调试；生产必须是 `https://`。

## 接入合同

接入的 Web 在 `config/callers.v1.json` 里登记为一个调用方（caller），部署时自动生成它的 token。

- **Cookie**：`yice_sso`，`Domain=<父域>; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=400 天`。有效期只看服务端会话（滑动 30 天），cookie 只是载体。应用只用 `token_hash = sha256(cookie 值)`，原值不外传、不记日志。
- **登录**：跳转 `{SSO_WEB_URL}/login?caller=<id>&next=<本应用的绝对 URL>`。`next` 不在该调用方 `origins` 内时，回落到它的第一个 origin，不会被拿来做开放跳转。调用方只允许一个企业时直接跳飞书，允许多个时先显示选择页。
- **校验**：`POST /v1/sessions/verify`，请求头 `Authorization: Bearer <调用方 token>`，请求体 `{"token_hash": "<64 位十六进制>", "fresh": false}`。
  - `200`：`session` 含 `subject_id`、`open_id`、`provider_id`、`company`、`directory`、`app_id`、`tenant_key`、`name`、`avatar`、`dept`。
  - `401 session_invalid`：未登录、已过期或已离职，按未登录处理。
  - `403 provider_not_allowed`：登录企业不在该调用方允许范围，提示切换账号。
  - 其他 401/403（`token_required` / `unauthorized` / `source_forbidden`）、422、503、超时：都按**认证服务不可用**处理，应用返回 503，不能当成未登录。
- **复核**：在职名单企业的成员每小时复核一次，并滑动续期 30 天；`fresh=true` 立即复核，写操作建议带上。离职、企业配置变化、会话已撤销，都按 `session_invalid` 返回。
- **缓存**：应用可以缓存成功结果 60 秒（`fresh` 不走缓存，失败不缓存），所以一处登出，最长 60 秒后在其他应用生效。
- **登出**：应用调 `POST /v1/sessions/revoke {"token_hash"}`，成功后清除 `Domain=<父域>` 的 `yice_sso`；撤销失败返回 503，不清 cookie。浏览器入口 `{SSO_WEB_URL}/logout?caller=<id>&next=…` 只显示确认页，真正撤销是同源 POST（校验 `Origin` / `Sec-Fetch-Site`），跨站链接不能强制登出。
- **自检**：`GET /v1/whoami` 返回当前 token 对应的调用方，接入时用来确认 token 和来源网段配对。

## 飞书企业应用与告警 bot

每家允许登录的企业在自己的飞书租户里建一个**企业自建应用**：只加「网页应用」能力，只开「获取用户基本信息」权限，重定向 URL 填 `https://<父域>/sso/callback`。登录应用不加机器人、不申请消息权限。

健康告警交给独立的通知服务和它的**企业 bot**：yice-sso 只持有通知服务给的调用方 token，按小时幂等，同一小时最多一条。登录凭证和发消息凭证因此完全分开。完整的创建步骤、两种放行方式、轮换规则见 [docs/feishu-apps.md](docs/feishu-apps.md)。

## 部署

```bash
export SSO_DEPLOY_HOST=root@<服务器>
deploy/deploy.sh             # 预演：远端只读预检 + 文件差异 + 将生成的 token（只列变量名）
deploy/deploy.sh --execute   # 测试 → 新版本目录与 venv → 生成缺失 token → 自检 → 原子切换 → 重启 → 回读；不健康自动回滚
```

第一次上线要先准备数据库、服务器 `.env`、nginx 片段和飞书应用，步骤见 [docs/deploy.md](docs/deploy.md)。

## 安全设计

- **cookie 原值不落库**：库里只存 `sha256`，应用之间也只传哈希；OAuth `state` 同样只存哈希、单次消费、10 分钟过期，并发登录各用各的 state cookie。
- **企业配置绑定会话**：会话记录登录时企业配置的摘要（不含 secret），换 App ID 或 `tenant_key` 后旧会话一律失效。
- **内部 API 不出内网**：nginx 只转发 `/sso/`；`/v1` 要求调用方 token，而且请求必须来自声明的网段。浏览器入口只接受本机 nginx 转发的请求。
- **最小权限**：运行账号只能读写会话表、追加审计表、读名单表的几列；systemd 用 `DynamicUser`、`ProtectSystem=strict`，并限制内存和 CPU。
- **失败显式**：认证服务不可用时，应用返回 503，不把用户当成未登录踢走；探活失败但告警没配置时，返回 `BLOCKED`，不报成功。
- **凭证不进仓库**：`config/` 只写变量名；调用方 token 在服务器上生成，追加进服务器 `.env`，不回传。

## CLI

`bin/yice-sso`（JSON 输出；退出码 `0` 成功 · `1` 失败 · `2` 用法错误 · `3` 阻塞）：

- `--self-check`：配置、企业凭证、调用方 token、MySQL 表与名单权限
- `serve [--host --port]`：启动服务（单进程）
- `health`、`verify --token-hash H [--fresh]`：经 `SSO_API_URL` / `SSO_API_TOKEN` 调内部 API
- `events --since YYYY-MM-DD [--subject ID]`：读 `login_event`
- `probe`：探本机 `/health`，失败经通知服务告警

## 数据与日志

| 内容 | 位置 |
| --- | --- |
| 会话、OAuth state | `yice_sso.session`、`yice_sso.oauth_state` |
| 登录 / 登出 / 撤会话（含被拒和失败，看 `outcome`） | `yice_sso.login_event`，只追加 |
| 请求日志 | `/var/log/yice-sso/access.jsonl`，每天轮转、保留 180 天；成功的 `verify` 和 `/health` 不记，回调不记 query |

## License

MIT，见 [LICENSE](LICENSE)。
