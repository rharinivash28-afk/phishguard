"""HTTP middleware — security headers on every response."""
import os

_IS_PROD = bool(os.environ.get("RENDER") or os.environ.get("PORT") or os.environ.get("FLY_APP_NAME"))

# Scripts are self-hosted only. Styles allow Google Fonts' stylesheet host and the
# inline styles Tailwind's build / React style props emit; font files come from
# fonts.gstatic.com. Everything else is same-origin.
_CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "script-src 'self'; "
    "connect-src 'self'; "
    "font-src 'self' data: https://fonts.gstatic.com; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": _CSP,
}


async def security_headers(request, call_next):
    response = await call_next(request)
    for k, v in _HEADERS.items():
        response.headers.setdefault(k, v)
    if _IS_PROD:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response
