# yice-sso

飞书单点登录：同一父域下的多个 Web 登录一次、全部认。只管「你是谁」，权限归各应用。

## 是什么

- **登录**：浏览器走 `/sso/*`，飞书授权后在父域写 cookie `yice_sso`。
- **校验**：应用用 `sha256(cookie)` 调内部接口 `POST /v1/sessions/verify`，拿到用户。
- **会话**：存 MySQL，滑动 30 天，可撤销；登录、退出写只追加的审计表 `login_event`。
- **企业**：每家企业一个飞书应用；按租户放行，或按在职名单放行（可选，离职后最长一小时失效）。

## 部署

需要：Linux + systemd + `/usr/bin/python3.11` 的服务器（root SSH）、MySQL、父域 HTTPS 的 nginx、飞书管理员。

1. **飞书应用**（人做）：开放平台建企业自建应用 → 加「网页应用」 → 重定向 URL 填 `https://<父域>/sso/callback` → 开「获取用户基本信息」权限 → 设可用范围 → 发布版本。记下 App ID、App Secret；合作企业另要 tenant_key。
2. **数据库**：

   ```bash
   mysql -u <admin> -p < schema/yice_sso.sql
   mysql -u <admin> -p -e "CREATE USER 'yice_sso_app'@'%' IDENTIFIED BY '<密码>';"
   mysql -u <admin> -p < schema/grants.sql
   ```

   用在职名单时，再执行 `schema/directory.example.sql`（还没有名单表时）和 `schema/grants.directory.sql`。
3. **配置**：改 `config/providers.v1.json`（企业）和 `config/callers.v1.json`（接入的 Web、内网来源 IP），提交到 Git。
4. **服务器 env**：按 `deploy/production.env.example` 建 `/opt/yice/yice-sso/.env`，`chmod 600`。
5. **nginx**：把 `deploy/nginx-sso.locations.conf` 加进父域的 server 块；http 块加 `limit_req_zone $binary_remote_addr zone=yice_sso_authorize:10m rate=10r/m;`；reload。
6. **部署**：

   ```bash
   SSO_DEPLOY_HOST=root@<服务器> deploy/deploy.sh             # 预演
   SSO_DEPLOY_HOST=root@<服务器> deploy/deploy.sh --execute   # 测试 → 建版本 → 自检 → 切换；不健康自动回滚
   ```

7. **验收**：服务器上 `curl -s http://127.0.0.1:8773/health` 返回 `"ok":true`；浏览器打开 `https://<父域>/sso/login?caller=<调用方>&next=https://<父域>/` 能登录。

可选：探活失败经 HTTP 通知服务告警（`NOTIFICATION_*`），不配则不告警。

## 接入一个 Web

1. **登记**：在 `config/callers.v1.json` 加调用方；部署后服务器 `.env` 自动生成 `SSO_CALLER_<ID>_TOKEN`，配给该应用。
2. **登录**：未登录时跳 `https://<父域>/sso/login?caller=<id>&next=<当前页>`。
3. **校验**：每个请求取 cookie `yice_sso`，调：

   ```http
   POST http://<内网地址>:8773/v1/sessions/verify
   Authorization: Bearer <token>

   {"token_hash": "<sha256(cookie)>", "fresh": false}
   ```

   - `200`：返回用户（`subject_id`、`name`、`company`、`dept`…）。
   - `401 session_invalid`：未登录，跳登录。
   - `403 provider_not_allowed`：该企业无权访问。
   - 其他错误：返回 503，不当未登录。
   - 成功结果可缓存 60 秒；写操作传 `"fresh": true`。
4. **退出**：跳 `https://<父域>/sso/logout?caller=<id>&next=<页面>`，用户确认后撤销。

## 命令

```bash
uv run --locked pytest -q          # 测试
bin/yice-sso --self-check          # 配置、凭证、数据库
bin/yice-sso serve                 # 启动
bin/yice-sso events --since <日期>  # 登录审计
```

## License

MIT
