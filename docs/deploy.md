# 一键部署

日常发布只用一条命令：`deploy/deploy.sh --execute`。它跑完测试，建新版本，自检通过才切换，切换后不健康就自动回滚。第一次上线先做下面的「一次性准备」，以后每次升级都只跑这一条。

## 需要什么

| 位置 | 要求 |
| --- | --- |
| 服务器 | Linux + systemd，`/usr/bin/python3.11`，root SSH 免密登录；已有 nginx 为父域提供 HTTPS |
| 数据库 | MySQL 5.7 / 8.0，能建库、建账号 |
| 本机（发布机） | `git`、`uv`、`rsync`、`ssh`；在本仓库的 Git 工作区里执行（只发布已提交的代码） |
| 飞书 | 每家允许登录的企业一个企业自建应用，见 [飞书企业应用设计](feishu-apps.md) |

固定约定：代码在 `/opt/yice/yice-sso/releases/<提交>-<时间>/`，`current` 软链指向在用版本，保留最近 3 个；服务 `yice-sso` 监听 `8773`；凭证 `/opt/yice/yice-sso/.env`（root 600）；请求日志 `/var/log/yice-sso/access.jsonl`。

## 一次性准备

1. **飞书应用**：按 [feishu-apps.md](feishu-apps.md) 建应用，重定向 URL 填 `https://<父域>/sso/callback`。
2. **数据库**：用管理账号执行建库脚本，再建运行账号并授权：
   ```bash
   mysql -h <db-host> -u <admin> -p < schema/yice_sso.sql
   mysql -h <db-host> -u <admin> -p -e "CREATE USER 'yice_sso_app'@'%' IDENTIFIED BY '<强密码>';"
   mysql -h <db-host> -u <admin> -p < schema/grants.sql
   ```
   运行账号只能读写 `session` / `oauth_state`，只能追加 `login_event`（触发器拒绝改删）。

   **有企业用在职名单方式**（`"directory": true`）时再加两步，没有就跳过，自检也不会检查名单：
   ```bash
   mysql -h <db-host> -u <admin> -p < schema/directory.example.sql   # 还没有名单表时；库名与 SSO_DIRECTORY_DB 一致
   mysql -h <db-host> -u <admin> -p < schema/grants.directory.sql    # 名单库不叫 yice_information 时先改库名
   ```
3. **声明**：编辑 [`config/providers.v1.json`](../config/providers.v1.json)（登录企业）和 [`config/callers.v1.json`](../config/callers.v1.json)（接入的 Web：origin、允许的企业、token 变量名、内网来源网段），提交。
4. **服务器 `.env`**：按 [`deploy/production.env.example`](../deploy/production.env.example) 在服务器上新建 `/opt/yice/yice-sso/.env`，`chmod 600`。调用方 token 不用手填，部署时自动生成。要告警就按 [注册群机器人](feishu-apps.md#注册群机器人) 填 `SSO_ALERT_WEBHOOK`（部署后自测一次）。
5. **nginx**：把 [`deploy/nginx-sso.locations.conf`](../deploy/nginx-sso.locations.conf) 放进父域的 `server` 块（在 `location /` 之前），`http` 块加一行 `limit_req_zone $binary_remote_addr zone=yice_sso_authorize:10m rate=10r/m;`，然后 `nginx -t && systemctl reload nginx`。只转发 `/sso/`，内部 API `/v1` 永远不经过 nginx。

## 一键部署

```bash
export SSO_DEPLOY_HOST=root@<服务器>
deploy/deploy.sh             # 预演：远端只读预检、文件差异、将生成的 token（只列变量名）
deploy/deploy.sh --execute   # 正式部署
```

`--execute` 依次做这些事：

1. 本机检查：工作区无未提交改动，`uv run --locked pytest` 全部通过。
2. 上传到新的版本目录，在服务器上建独立 venv 并安装锁定依赖。
3. 给 `callers.v1.json` 里还没有 token 的调用方生成 token，追加进服务器 `.env`；值只在服务器上，不回传。
4. 用与 systemd 相同的环境跑 `--self-check`（配置、企业凭证、调用方 token、数据库表；有名单方式的企业时还查名单权限）。
5. 原子切换 `current`，安装 / 更新 systemd unit 与 logrotate，重启 `yice-sso`，30 秒内等 `/health` 正常。
6. 不健康就切回上一版本并重启；启用 `yice-sso-probe.timer`；清理旧版本。

退出码：`0` PASS，`1` FAIL（有上一版本时已自动回滚），`2` 用法错误，`3` BLOCKED（什么都没切换）。第 1～4 步任何一步失败都会删掉新版本目录，在用版本不受影响。

## 验收

```bash
ssh $SSO_DEPLOY_HOST 'curl -s http://127.0.0.1:8773/health'                      # ok=true，storage=ok
curl -s -o /dev/null -w '%{http_code}\n' https://<父域>/sso/me                    # 未登录 401
ssh $SSO_DEPLOY_HOST 'systemctl is-active yice-sso yice-sso-probe.timer'
```

浏览器打开 `https://<父域>/sso/login?caller=<调用方>&next=https://<父域>/`，登录后访问 `/sso/me` 应看到本人；服务器上查登录审计能看到这次 `login / accepted`：

```bash
ssh $SSO_DEPLOY_HOST 'cd /opt/yice/yice-sso && SSO_PYTHON=current/.venv/bin/python SSO_ENV_FILE=.env current/bin/yice-sso events --since <今天>'
```

## 接入一个 Web

1. 在 `config/callers.v1.json` 加一条：`origins`（该应用的 https 源，必须在父域内）、允许的 `providers`、`token_env`、该应用访问内部 API 的来源网段 `sources`。
2. `deploy/deploy.sh --execute`：自动生成该调用方的 token。
3. 把服务器 `.env` 里对应的 token 配到该应用（机器间直接传，不经过聊天或工单），应用配 `SSO_API_URL=http://<内网地址>:8773`。
4. 在该应用的主机上验证：`curl -H "Authorization: Bearer $SSO_API_TOKEN" $SSO_API_URL/v1/whoami` 返回自己的调用方 id。
5. 应用按 [README 的接入合同](../README.md#接入合同) 实现登录跳转、`verify`、登出。

## 回滚与停用

- 发布中失败：脚本已自动回滚，看输出最后一行。
- 发布后要退回：`ssh $SSO_DEPLOY_HOST`，`ls -1t /opt/yice/yice-sso/releases` 找上一版本，`ln -sfn releases/<上一版本> /opt/yice/yice-sso/current.next && mv -Tf /opt/yice/yice-sso/current.next /opt/yice/yice-sso/current && systemctl restart yice-sso`；然后在本地 `git revert` 对应提交，避免下次部署又带上。
- 停用：`systemctl disable --now yice-sso yice-sso-probe.timer`，nginx 移除 `/sso/` 片段并 reload。数据库保留，删库是单独的决定。
