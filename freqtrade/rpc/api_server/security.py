"""
Optional request screening for the REST API, backed by fastapi-guard.
Disabled by default - nothing from fastapi-guard is imported unless it's enabled.
"""

import logging

from fastapi import FastAPI

from freqtrade.exceptions import OperationalException


logger = logging.getLogger(__name__)


def add_security_middleware(app: FastAPI, api_config: dict) -> None:
    """
    Add the fastapi-guard middleware to the app if `api_server.security.enabled` is true.
    Must be called before CORSMiddleware is added, so CORS stays the outermost layer
    and the browser can read 403 / 429 responses from the guard.

    :param app: FastAPI app to add the middleware to
    :param api_config: The `api_server` section of the configuration
    :raises OperationalException: if enabled but fastapi-guard is not installed
    """
    security = api_config.get("security", {})
    if not security.get("enabled", False):
        return

    try:
        from guard import PureASGISecurityMiddleware, SecurityConfig
    except ImportError as e:
        raise OperationalException(
            "`api_server.security.enabled` is set, but fastapi-guard is not installed. "
            "Install it with `pip install -r requirements-security.txt`."
        ) from e

    config = SecurityConfig(
        enable_redis=False,
        rate_limit=security.get("rate_limit", 300),
        rate_limit_window=security.get("rate_limit_window", 60),
        whitelist=security.get("whitelist") or None,
        blacklist=security.get("blacklist", []),
        trusted_proxies=security.get("trusted_proxies", ["127.0.0.1", "::1"]),
        trusted_proxy_depth=security.get("trusted_proxy_depth", 1),
        enable_penetration_detection=security.get("enable_penetration_detection", True),
        # Request bodies carry strategy code and config values - never scan them.
        detection_scan_body=False,
        # FreqUI is served by the bot itself, don't add headers to its responses.
        security_headers={"enabled": False},
    )
    # Pure ASGI: websocket and streaming scopes pass through untouched.
    app.add_middleware(PureASGISecurityMiddleware, config=config)
    logger.info("fastapi-guard request screening enabled for the REST API.")
