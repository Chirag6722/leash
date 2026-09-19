"""GET /policies relays common.authz.list_policies with CORS, and surfaces failures as 500."""

import json

import common.authz
from api import handler as h


def test_policies_route_relays_rows(monkeypatch):
    rows = [{"id": "ForbidProd", "effect": "forbid", "description": "", "statement": "forbid (...)"}]
    monkeypatch.setattr(common.authz, "list_policies_with_version", lambda: (rows, "s3:test"))
    resp = h.handler({"routeKey": "GET /policies"}, None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["items"] == rows and body["policy_version"] == "s3:test"
    assert body["floor"]["count"] == 10 and body["floor"]["holds"] is True  # the floor rides along
    assert resp["headers"]["Access-Control-Allow-Origin"] == "*"


def test_policies_route_failure_is_500_with_message(monkeypatch):
    def boom():
        raise RuntimeError("avp down")

    monkeypatch.setattr(common.authz, "list_policies_with_version", boom)
    resp = h.handler({"routeKey": "GET /policies"}, None)
    assert resp["statusCode"] == 500
    assert "avp down" in json.loads(resp["body"])["error"]
