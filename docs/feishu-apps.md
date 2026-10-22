# 飞书企业应用与告警 bot 设计

yice-sso 只用飞书做一件事：网页登录（OAuth 授权码流程），确认「这个人是谁、属于哪家允许的企业」。消息、通讯录、群聊等能力都不在这里，所以登录应用只开最小权限、不开机器人能力；告警消息交给独立的通知服务和它的企业 bot。

## 一个企业，一个登录应用

每家允许登录的企业，在自己的飞书租户里建一个**企业自建应用**，在 [`config/providers.v1.json`](../config/providers.v1.json) 里登记为一个 provider。provider 有两种放行方式：

| 方式 | 声明 | 放行条件 | 复核 | `subject_id` |
| --- | --- | --- | --- | --- |
| 在职名单 | `"directory": true` | 飞书身份的 `open_id` 在名单库 `member` 表且 `enabled=1` | 每小时复核在职；`fresh=true` 立即复核 | 等于 `open_id` |
| 租户 | `"directory": false` + `tenant_key_env` | 飞书返回的 `tenant_key` 与声明一致 | 不查名单，会话滑动 30 天 | `fs:` + `sha256([app_id, tenant_key, open_id])` 前 60 位 |

- 主企业用在职名单：员工离职后最长一小时（写操作立即）失去登录态，不依赖飞书侧停用。
- 合作企业用租户：不需要对方的通讯录，只确认授权来自对方企业；对方自己管理谁能用（应用可用范围）。
- 名单表合同：`member(open_id, name, avatar, enabled, dept_id)`、`dept(dept_id, name)`，运行账号只有这几列的 `SELECT`（见 [`schema/grants.sql`](../schema/grants.sql)）。名单由你自己的同步任务维护。
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

## 告警 bot：不在登录应用里

`yice-sso-probe.timer` 每 5 分钟跑一次 `yice-sso probe`：探本机 `/health`，失败时调用通知服务的 `POST /v1/notifications`，发给 `SSO_ALERT_TARGET`。幂等键按小时生成（`yice-sso-health-YYYYMMDDHH`），同一小时最多一条，服务一直挂着也不会刷屏。

- 机器人凭证只在通知服务里（参考实现 [yice-feishu-notice](https://github.com/DaxDing/yice-feishu-notice)：用企业 bot 发 Markdown / 富文本，按人名、open_id 或群发送，带幂等回放）。
- yice-sso 只持有通知服务给它的调用方 token（`NOTIFICATION_API_TOKEN`），只能发通知，拿不到 bot 的 App Secret。
- 这样拆分，登录应用永远只有「获取用户基本信息」一个权限；换 bot、换通知渠道都不用碰登录配置。
- 不需要告警时，三个 `NOTIFICATION_*` / `SSO_ALERT_TARGET` 留空，或不启用 `yice-sso-probe.timer`；健康检查失败时 `probe` 返回 `BLOCKED`（`notification not configured`），不会假装已发送。
