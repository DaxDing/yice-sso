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

_STYLE = """
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;background:#f5f6f8;color:#1f2329}
main{width:min(360px,calc(100vw - 32px));background:#fff;border-radius:12px;padding:32px 28px;
box-shadow:0 1px 3px rgba(0,0,0,.08)}
h1{font-size:20px;margin:0 0 4px}p{margin:0 0 20px;color:#646a73;font-size:14px}
a.btn,button.btn{display:block;width:100%;border:0;cursor:pointer;text-align:center;padding:11px 0;margin-top:12px;border-radius:8px;background:#3370ff;
color:#fff;text-decoration:none;font-size:15px;font-family:inherit}a.btn.alt{background:#eef0f3;color:#1f2329}
.err{background:#fff1f0;color:#c0392b;border-radius:8px;padding:10px 12px;font-size:13px;margin-bottom:8px}
@media (prefers-color-scheme:dark){body{background:#17181a;color:#e8e9eb}main{background:#232427;box-shadow:none}
p{color:#a2a6ad}a.btn.alt{background:#34363a;color:#e8e9eb}.err{background:#3a2422;color:#ff8f84}}
"""


def _page(title: str, body: str) -> str:
    return (
        '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{_STYLE}</style></head>"
        f"<body><main>{body}</main></body></html>"
    )


def error_text(code: str | None) -> str:
    return ERROR_MESSAGES.get(code or "", "登录失败，请重新登录") if code else ""


def login_page(
    *, base: str, caller_id: str, caller_label: str, next_url: str, providers: list[Provider], error: str | None
) -> str:
    rows = []
    for provider in providers:
        query = urllib.parse.urlencode({"caller": caller_id, "provider": provider.id, "next": next_url})
        rows.append(f'<a class="btn" href="{html.escape(base)}/authorize?{html.escape(query)}">'
                    f"{html.escape(provider.label)} · 飞书登录</a>")
    if error == "provider_not_allowed":
        query = urllib.parse.urlencode({"caller": caller_id})
        rows.append(f'<a class="btn alt" href="{html.escape(base)}/logout?{html.escape(query)}">退出当前账号</a>')
    message = f'<div class="err">{html.escape(error_text(error))}</div>' if error else ""
    return _page(
        "登录",
        f"<h1>登录 {html.escape(caller_label)}</h1><p>使用企业飞书账号登录</p>{message}{''.join(rows)}",
    )


def logout_page(*, base: str, caller_id: str, caller_label: str, next_url: str) -> str:
    """Confirmation form: a cross-site GET can no longer end the shared session (logout CSRF)."""
    return _page(
        "退出登录",
        f"<h1>退出登录</h1><p>将退出 {html.escape(caller_label)} 及所有共用登录的应用</p>"
        f'<form method="post" action="{html.escape(base)}/logout">'
        f'<input type="hidden" name="caller" value="{html.escape(caller_id)}">'
        f'<input type="hidden" name="next" value="{html.escape(next_url)}">'
        '<button class="btn" type="submit">退出登录</button></form>',
    )


def error_page(code: str) -> str:
    return _page("登录失败", f"<h1>登录失败</h1><p>{html.escape(error_text(code))}</p>")
