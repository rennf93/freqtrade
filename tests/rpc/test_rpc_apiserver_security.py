"""
Unit test file for the optional fastapi-guard integration in rpc/api_server/security.py
"""

import builtins
import itertools
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, WebSocketDisconnect
from fastapi.testclient import TestClient
from requests.auth import _basic_auth_str

from freqtrade.configuration.config_validation import validate_config_schema
from freqtrade.enums import RunMode
from freqtrade.exceptions import ConfigurationError, OperationalException
from freqtrade.rpc import RPC
from freqtrade.rpc.api_server import ApiServer
from freqtrade.rpc.api_server.security import add_security_middleware
from tests.conftest import get_patched_freqtradebot


pytest.importorskip("guard")

BASE_URI = "/api/v1"
_TEST_USER = "FreqTrader"
_TEST_PASS = "SuperSecurePassword1!"
_TEST_WS_TOKEN = "secret_Ws_t0ken"
_JWT_SECRET_KEY = "99980ff8fcf77f21ef610adb46b788c505b8483897bc26203b5591eefe0d15"
# The guard keeps rate limit and ban state per IP in process-wide singletons,
# so every client gets its own peer address to keep the tests independent.
_peer_counter = itertools.count(1)


def _security_client(default_conf, mocker, security, peer):
    default_conf["runmode"] = RunMode.DRY_RUN
    api_server = {
        "enabled": True,
        "listen_ip_address": "127.0.0.1",
        "listen_port": 8080,
        "jwt_secret_key": _JWT_SECRET_KEY,
        "username": _TEST_USER,
        "password": _TEST_PASS,
        "ws_token": _TEST_WS_TOKEN,
    }
    if security is not None:
        api_server["security"] = security
    default_conf["api_server"] = api_server

    ftbot = get_patched_freqtradebot(mocker, default_conf)
    mocker.patch("freqtrade.rpc.api_server.ApiServer.start_api", MagicMock())
    apiserver = ApiServer(default_conf)
    apiserver.add_rpc_handler(RPC(ftbot))
    return apiserver, TestClient(apiserver.app, client=peer)


@pytest.fixture
def make_client(default_conf, mocker):
    # ApiServer is a singleton, so only one client is alive at a time.
    current = []

    def _close():
        while current:
            apiserver, client = current.pop()
            client.__exit__(None, None, None)
            apiserver.cleanup()
            ApiServer.shutdown()

    def _make(security, peer=None):
        _close()
        peer = peer or (f"203.0.113.{next(_peer_counter)}", 50000)
        apiserver, client = _security_client(default_conf, mocker, security, peer)
        client.__enter__()
        client.peer_ip = peer[0]
        current.append((apiserver, client))
        return client

    yield _make
    _close()


def test_security_config_schema(default_conf):
    default_conf["api_server"] = {
        "enabled": True,
        "listen_ip_address": "127.0.0.1",
        "listen_port": 8080,
        "jwt_secret_key": _JWT_SECRET_KEY,
        "username": _TEST_USER,
        "password": _TEST_PASS,
    }
    validate_config_schema(default_conf)

    default_conf["api_server"]["security"] = {"enabled": True, "rate_limit": 60, "whitelist": []}
    validate_config_schema(default_conf)

    default_conf["api_server"]["security"] = {"enabled": True, "rate_limit": 0}
    with pytest.raises(ConfigurationError, match=r"0 is less than the minimum of 1"):
        validate_config_schema(default_conf)

    default_conf["api_server"]["security"] = {"enabled": True, "unknown_option": 1}
    with pytest.raises(ConfigurationError, match=r"unknown_option"):
        validate_config_schema(default_conf)


def test_security_disabled_adds_nothing(monkeypatch):
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "guard" or name.startswith("guard."):
            raise AssertionError("fastapi-guard must not be imported when disabled")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    for api_config in ({}, {"security": {}}, {"security": {"enabled": False}}):
        app = FastAPI()
        add_security_middleware(app, api_config)
        assert app.user_middleware == []


def test_security_missing_dependency(monkeypatch):
    real_import = builtins.__import__

    def failing_import(name, *args, **kwargs):
        if name == "guard":
            raise ImportError("No module named 'guard'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", failing_import)
    with pytest.raises(OperationalException, match=r"fastapi-guard is not installed"):
        add_security_middleware(FastAPI(), {"security": {"enabled": True}})


def test_security_middleware_below_cors(make_client):
    client = make_client({"enabled": True})
    names = [m.cls.__name__ for m in client.app.user_middleware]
    # user_middleware is outermost first: CORS must come before the guard
    assert names == ["CORSMiddleware", "PureASGISecurityMiddleware"]


def test_security_rate_limit(make_client):
    client = make_client({"enabled": True, "rate_limit": 3, "rate_limit_window": 60})
    codes = [client.get(f"{BASE_URI}/ping").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]


def test_security_whitelist(make_client):
    client = make_client({"enabled": True, "whitelist": ["198.51.100.0/24"]})
    assert client.get(f"{BASE_URI}/ping").status_code == 403

    client = make_client({"enabled": True, "whitelist": ["203.0.113.0/24"]})
    assert client.get(f"{BASE_URI}/ping").status_code == 200


def test_security_whitelisted_ip_not_rate_limited(make_client):
    client = make_client({"enabled": True, "whitelist": ["203.0.113.0/24"], "rate_limit": 2})
    codes = [client.get(f"{BASE_URI}/ping").status_code for _ in range(5)]
    assert codes == [200] * 5


def test_security_blacklist(make_client):
    client = make_client({"enabled": True, "blacklist": ["203.0.113.0/24"]})
    assert client.get(f"{BASE_URI}/ping").status_code == 403


def test_security_spoofed_forwarded_for_ignored(make_client):
    # Peer is not a trusted proxy, so X-Forwarded-For must not be believed.
    client = make_client({"enabled": True, "whitelist": ["198.51.100.0/24"]})
    rc = client.get(f"{BASE_URI}/ping", headers={"X-Forwarded-For": "198.51.100.5"})
    assert rc.status_code == 403

    client = make_client({"enabled": True, "blacklist": ["203.0.113.0/24"]})
    rc = client.get(f"{BASE_URI}/ping", headers={"X-Forwarded-For": "198.51.100.5"})
    assert rc.status_code == 403


def test_security_trusted_proxy_forwarded_for(make_client):
    security = {"enabled": True, "whitelist": ["198.51.100.0/24"]}
    # Default trusted proxies are loopback only
    client = make_client(security, peer=("127.0.0.1", 50000))
    ok = client.get(f"{BASE_URI}/ping", headers={"X-Forwarded-For": "198.51.100.5"})
    assert ok.status_code == 200
    bad = client.get(f"{BASE_URI}/ping", headers={"X-Forwarded-For": "192.0.2.9"})
    assert bad.status_code == 403


def test_security_attack_in_query_blocked(make_client):
    client = make_client({"enabled": True})
    rc = client.get(f"{BASE_URI}/ping", params={"q": "<script>alert(1)</script>"})
    assert rc.status_code == 400
    assert client.get(f"{BASE_URI}/ping").status_code == 200


def test_security_body_not_scanned(make_client):
    client = make_client({"enabled": True})
    rc = client.post(
        f"{BASE_URI}/token/login",
        content=b'{"note": "<script>alert(1)</script>"}',
        headers={
            "Authorization": _basic_auth_str(_TEST_USER, _TEST_PASS),
            "content-type": "application/json",
        },
    )
    assert rc.status_code == 200


def test_security_login_still_works(make_client):
    client = make_client({"enabled": True})
    rc = client.post(
        f"{BASE_URI}/token/login",
        headers={"Authorization": _basic_auth_str(_TEST_USER, _TEST_PASS)},
    )
    assert rc.status_code == 200
    token = rc.json()["access_token"]
    assert "refresh_token" in rc.json()

    rc = client.get(f"{BASE_URI}/count", headers={"Authorization": f"Bearer {token}"})
    assert rc.status_code == 200

    rc = client.post(
        f"{BASE_URI}/token/login",
        headers={"Authorization": _basic_auth_str(_TEST_USER, "wrong")},
    )
    assert rc.status_code == 401


def test_security_websocket_unaffected(make_client):
    # The guard blocks this peer for plain HTTP, the websocket scope passes through.
    client = make_client({"enabled": True, "blacklist": ["203.0.113.0/24"]})
    assert client.get(f"{BASE_URI}/ping").status_code == 403

    with client.websocket_connect(f"{BASE_URI}/message/ws?token={_TEST_WS_TOKEN}"):
        pass
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"{BASE_URI}/message/ws?token=bad"):
            pass
