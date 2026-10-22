"""Server-rendered login and error pages: static HTML, links only, no script."""

from __future__ import annotations

import html
import urllib.parse

from .providers import Provider

ERROR_MESSAGES = {
    "oauth_state_invalid": "登录状态已失效，请重新登录",
    "oauth_provider_changed": "企业登录配置已变化，请重新登录",
    "oauth_token_exchange_failed": "飞书授权码换取失败，请重新登录",
    "oauth_user_info_failed": "无法读取飞书身份，请重新登录",
    "oauth_upstream_unavailable": "飞书暂时无法访问，请稍后重试",
    "oauth_denied": "已取消飞书授权",
    "member_not_allowed": "当前飞书账号不在公司在职名单内（通讯录每天 08:00 同步）",
    "tenant_not_allowed": "飞书授权企业与登录入口不一致",
    "provider_unavailable": "该企业登录入口未启用",
    "provider_not_allowed": "当前登录的企业账号无权访问此应用，请切换账号",
    "caller_unavailable": "发起登录的应用未声明或已停用",
    "auth_unavailable": "认证服务暂不可用，请稍后重试",
    "logged_out": "已退出登录",
    "logout_forbidden": "退出请求来源无效，请在登录页重新操作",
}
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
    "form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
)
LOGOUT_FORM_POLICY = CONTENT_SECURITY_POLICY.replace("form-action 'none'", "form-action 'self'")
PAGE_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}

# Same look as the apps' own sign-in page (yice-information login.html): card, logo block, Feishu buttons.
_STYLE = """
:root{--bg:#f9f8f5;--card:#fff;--fg:#1e2024;--muted:#6b7078;--muted2:#8a8f97;--line:#e5e2db;
--acc:#3f6ea8;--acc-hover:#335c8f;--acc-soft:#e9f1fa;--err:#b3422d;--err-soft:#f8e7e2;
--shadow:0 1px 2px rgba(30,32,36,.04),0 14px 44px rgba(30,32,36,.09)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:var(--bg);
min-height:100vh;display:flex;align-items:center;justify-content:center;color:var(--fg)}
main{width:min(400px,92vw);background:var(--card);border:1px solid var(--line);border-radius:18px;
box-shadow:var(--shadow);padding:44px 40px 36px;text-align:center}
.logo{width:52px;height:52px;border-radius:15px;margin:0 auto 18px;
background:linear-gradient(135deg,var(--acc),#6f9bd0);display:flex;align-items:center;justify-content:center;
box-shadow:0 4px 14px rgba(63,110,168,.32)}
.logo::after{content:"";width:19px;height:19px;border-radius:5px;background:#fff}
h1{font-size:17px;font-weight:700;letter-spacing:.02em;margin-bottom:28px}
.sub{font-size:12.5px;color:var(--muted);line-height:1.7;margin:-14px 0 26px}
.btns{display:grid;gap:12px}
.fs-btn{display:flex;align-items:center;justify-content:center;gap:9px;width:100%;height:46px;
background:var(--acc);color:#fff;border:0;border-radius:11px;font-size:14px;font-weight:600;
cursor:pointer;font-family:inherit;transition:.15s;text-decoration:none}
.fs-btn:hover{background:var(--acc-hover)}
.fs-btn.alt{background:var(--acc-soft);color:var(--acc)}
.fs-btn.alt:hover{background:#dce8f5}
.fs-btn svg{width:19px;height:19px;flex:none}
.err{margin-bottom:18px;padding:10px 14px;background:var(--err-soft);color:var(--err);
border-radius:9px;font-size:12px;line-height:1.6;text-align:left}
.tip{margin-top:22px;font-size:11.5px;color:var(--muted2);line-height:1.8}
.icp{position:fixed;left:0;right:0;bottom:18px;text-align:center;font-size:11.5px}
.icp a{color:var(--muted2);text-decoration:none}
.icp a:hover{color:var(--muted)}
"""
_FEISHU_ICON = (
    '<svg viewBox="0 0 24 24" fill="currentColor" stroke="none" aria-hidden="true">'
    '<path d="M3.4 11.05 20.2 3.7c.85-.37 1.72.5 1.35 1.35l-7.35 16.8c-.4.9-1.7.83-2-.1l-2.06-6.2a1.2 1.2 0 0 0'
    '-.76-.76L3.5 13.05c-.93-.3-1-1.6-.1-2z"/><path d="m10.8 13.2 4.6-4.6" stroke="#fff" stroke-width="1.6" '
    'stroke-linecap="round" fill="none" opacity=".55"/></svg>'
)


def _page(title: str, body: str, icp: str = "") -> str:
    footer = (
        '<footer class="icp"><a href="https://beian.miit.gov.cn/" target="_blank" rel="noopener noreferrer">'
        f"{html.escape(icp)}</a></footer>"
        if icp
        else ""
    )
    return (
        '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{_STYLE}</style></head>"
        f'<body><main><div class="logo"></div>{body}</main>{footer}</body></html>'
    )


def error_text(code: str | None) -> str:
    return ERROR_MESSAGES.get(code or "", "登录失败，请重新登录") if code else ""


def login_page(
    *,
    base: str,
    caller_id: str,
    caller_label: str,
    next_url: str,
    providers: list[Provider],
    error: str | None,
    icp: str = "",
) -> str:
    rows = []
    for provider in providers:
        query = urllib.parse.urlencode({"caller": caller_id, "provider": provider.id, "next": next_url})
        rows.append(f'<a class="fs-btn" href="{html.escape(base)}/authorize?{html.escape(query)}">'
                    f"{_FEISHU_ICON}{html.escape(provider.label)} · 飞书登录</a>")
    if error == "provider_not_allowed":
        query = urllib.parse.urlencode({"caller": caller_id})
        rows.append(f'<a class="fs-btn alt" href="{html.escape(base)}/logout?{html.escape(query)}">退出当前账号</a>')
    message = f'<div class="err">{html.escape(error_text(error))}</div>' if error else ""
    return _page(
        "登录",
        f"<h1>{html.escape(caller_label.upper())}</h1>{message}<div class=\"btns\">{''.join(rows)}</div>"
        '<div class="tip">选择企业，使用该企业的飞书账号授权登录</div>',
        icp,
    )


def logout_page(*, base: str, caller_id: str, caller_label: str, next_url: str, icp: str = "") -> str:
    """Confirmation form: a cross-site GET can no longer end the shared session (logout CSRF)."""
    return _page(
        "退出登录",
        "<h1>退出登录</h1>"
        f'<div class="sub">将退出 {html.escape(caller_label.upper())} 及所有共用登录的应用</div>'
        f'<form method="post" action="{html.escape(base)}/logout">'
        f'<input type="hidden" name="caller" value="{html.escape(caller_id)}">'
        f'<input type="hidden" name="next" value="{html.escape(next_url)}">'
        '<button class="fs-btn" type="submit">退出登录</button></form>',
        icp,
    )


def error_page(code: str, icp: str = "") -> str:
    return _page("登录失败", f'<h1>登录失败</h1><div class="err">{html.escape(error_text(code))}</div>', icp)
