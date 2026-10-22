# 飞书企业应用与告警 bot 设计

yice-sso 只用飞书做一件事：网页登录（OAuth 授权码流程），确认「这个人是谁、属于哪家允许的企业」。消息、通讯录、群聊等能力都不在这里，所以登录应用只开最小权限、不开机器人能力；告警消息交给一个飞书群自定义机器人（或你已有的通知服务）。

## 一个企业，一个登录应用

每家允许登录的企业，在自己的飞书租户里建一个**企业自建应用**，在 [`config/providers.v1.json`](../config/providers.v1.json) 里登记为一个 provider。provider 有两种放行方式：

| 方式 | 声明 | 放行条件 | 复核 | `subject_id` |
| --- | --- | --- | --- | --- |
| 在职名单 | `"directory": true` | 飞书身份的 `open_id` 在名单库 `member` 表且 `enabled=1` | 每小时复核在职；`fresh=true` 立即复核 | 等于 `open_id` |
| 租户 | `"directory": false` + `tenant_key_env` | 飞书返回的 `tenant_key` 与声明一致 | 不查名单，会话滑动 30 天 | `fs:` + `sha256([app_id, tenant_key, open_id])` 前 60 位 |

- 主企业用在职名单：员工离职后最长一小时（写操作立即）失去登录态，不依赖飞书侧停用。
- 合作企业用租户：不需要对方的通讯录，只确认授权来自对方企业；对方自己管理谁能用（应用可用范围）。
- 名单是可选的：只有声明了 `"directory": true` 的企业才需要。表合同是 `member(open_id, name, avatar, enabled, dept_id)`、`dept(dept_id, name)`，运行账号只有这几列的 `SELECT`（[`schema/grants.directory.sql`](../schema/grants.directory.sql)）。还没有名单表，用 [`schema/directory.example.sql`](../schema/directory.example.sql) 建，再由你自己的同步任务（例如每天拉一次飞书通讯录）维护。
- 不想维护名单：把主企业也写成租户方式（`"directory": false` + `tenant_key_env`），自检和授权都不会再碰名单表；代价是离职要靠飞书侧停用账号或调整应用可用范围，SSO 不会主动收回会话。
- 一个调用方（接入的 Web）可以允许多个 provider：只允许一个时直接跳飞书，允许多个时先显示选择页。

## 在飞书开放平台创建登录应用

由该企业的管理员在 [飞书开放平台](https://open.feishu.cn/app) 操作：

1. **创建企业自建应用**：名称写清用途，例如「XX 统一登录」。
2. **添加应用能力 → 网页应用**：只要网页登录，不添加机器人。
3. **安全设置 → 重定向 URL**：添加 `https://<父域>/sso/callback`，例如 `https://example.com/sso/callback`。必须与 `SSO_WEB_URL` + `/callback` 完全一致；迁移时新旧回调可以并存。
4. **权限管理**：开通「获取用户基本信息」（`authen/v1/user_info` 需要它）。不申请通讯录、消息等其他权限。
5. **可用范围**：设为需要登录的人（全员或指定部门）。不在范围内的人，飞书会直接拒绝授权。
6. **发布版本**：创建版本并经企业管理员审核通过。未发布的应用只有开发者本人能登录。
7. **取值**：凭证与基础信息页的 App ID、App Secret 填进服务器 `.env`；租户方式还要对方企业的 `tenant_key`（飞书开放平台接口返回的租户标识，由对方管理员提供）。

`config/providers.v1.json` 只写变量名，值只在服务器 `.env`：

```json
"partner": {
  "label": "示例合作企业",
  "directory": false,
  "app_id_env": "SSO_FEISHU_PARTNER_APP_ID",
  "app_secret_env": "SSO_FEISHU_PARTNER_APP_SECRET",
  "tenant_key_env": "SSO_FEISHU_PARTNER_TENANT_KEY"
}
```

`label` 会显示在选择页和应用拿到的 `company` 字段里。缺任何一个值时该 provider 视为「未配置」：不能登录，但不影响其他 provider；`--self-check` 会标出来。

## 变更与轮换

- **只换 App Secret**：改 `.env` 后重启（或重新部署），已有会话不受影响。
- **换 App ID、`tenant_key`、放行方式**：provider 摘要（`id`、`app_id`、`tenant_key`、`directory` 的哈希，不含 secret）随之改变，该企业已有会话在下一次校验时一律失效，所有人重新登录。这是有意的：给某人担保的企业配置已经不是当初那个了。
- **下线一个企业**：从调用方的 `providers` 里移除即可拒绝它登录该应用（应用收到 403 `provider_not_allowed`）；从 provider 目录删除前，先从所有调用方移除。

## 告警 bot：飞书群自定义机器人

`yice-sso-probe.timer` 每 5 分钟跑一次 `yice-sso probe`：探本机 `/health`，失败就告警，同一小时最多一条，服务一直挂着也不会刷屏。告警渠道两种，配一种或两种都行：

| 渠道 | 配置 | 一小时一条靠什么 |
| --- | --- | --- |
| 飞书群自定义机器人（推荐，几分钟配好） | `SSO_ALERT_WEBHOOK`，可选 `SSO_ALERT_WEBHOOK_SECRET` | 探活 unit 的 `StateDirectory` 记下已发的小时；发送失败不记，下次重试 |
| 自己的通知服务 | `NOTIFICATION_API_URL`、`NOTIFICATION_API_TOKEN`、`SSO_ALERT_TARGET` | 通知服务按幂等键 `yice-sso-health-YYYYMMDDHH` 去重（接口见 [yice-feishu-notice](https://github.com/DaxDing/yice-feishu-notice)） |

### 注册群机器人

1. 在飞书建一个运维群（或用已有的），把要收告警的人拉进来。
2. **群设置 → 群机器人 → 添加机器人 → 自定义机器人**，起名例如「yice-sso 告警」，添加。
3. 复制 **webhook 地址**（`https://open.feishu.cn/open-apis/bot/v2/hook/…`，海外版是 `open.larksuite.com`）。这个地址本身就是凭证：拿到它的人都能往群里发消息，只放服务器 `.env`，不进仓库、不贴聊天。
4. **安全设置**勾选「签名校验」，复制密钥（推荐；不开也能用，但地址泄露后任何人都能冒充告警）。不要勾「自定义关键词」或「IP 白名单」，除非你确认告警文本和服务器出口 IP 都满足它们。
5. 填进服务器 `/opt/yice/yice-sso/.env`：

   ```bash
   SSO_ALERT_WEBHOOK='https://open.feishu.cn/open-apis/bot/v2/hook/<你的 hook id>'
   SSO_ALERT_WEBHOOK_SECRET='<签名密钥>'
   ```

6. 自测一次（故意探一个不存在的端口；用临时状态目录，不占用正式的「本小时已发」记录）：

   ```bash
   cd /opt/yice/yice-sso && SSO_PYTHON=current/.venv/bin/python SSO_ENV_FILE=.env \
     SSO_ALERT_STATE_DIR="$(mktemp -d)" current/bin/yice-sso probe --url http://127.0.0.1:9/health
   ```

   输出 `"alerts": {"webhook": "sent"}` 且群里收到一条「yice-sso 健康检查失败」就配好了。签名不对会是 `failed: feishu code 19021`。

### 设计

- **凭证分开**：登录应用永远只有「获取用户基本信息」一个权限；群机器人只能往这一个群发消息。换告警渠道不碰登录配置，登录应用泄露也发不了消息。
- **地址不外泄**：webhook 地址和密钥只在服务器 `.env`；`probe` 的输出、日志里都不出现。只接受 `open.feishu.cn` / `open.larksuite.com` 的 https 地址，填错会明确报错，不会往别处发。
- **失败显式**：两种渠道都没配时，健康检查失败返回 `BLOCKED`（`alerts: not configured`）；发送失败如实报 `failed: …`，不会假装已发送。不需要告警时不配即可，或不启用 `yice-sso-probe.timer`。
