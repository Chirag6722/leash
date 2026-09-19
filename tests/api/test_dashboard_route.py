"""GET / serves the dashboard over https with the config inlined for this API's origin."""

import io
import json

from api import handler as h

PAGE = '<html><head><script src="config.js"></script></head><body>Leash</body></html>'


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_root_serves_page_with_inline_config(monkeypatch):
    import urllib.request

    monkeypatch.setenv("DASHBOARD_BUCKET_URL", "http://bucket.s3-website-us-east-1.amazonaws.com")
    monkeypatch.setenv("DEV_INSTANCE_ID", "i-dev1")
    monkeypatch.setenv("PROD_INSTANCE_ID", "i-prod1")
    monkeypatch.setenv("ASG_NAME", "leash-dev-asg")
    monkeypatch.setattr(h, "_PAGE", {"html": "", "at": 0.0})
    fetched = []
    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout=10: fetched.append(url) or FakeResp(PAGE.encode()))
    ev = {"routeKey": "GET /", "requestContext": {"domainName": "abc.execute-api.us-east-1.amazonaws.com"}}
    resp = h.handler(ev, None)
    assert resp["statusCode"] == 200 and resp["headers"]["Content-Type"].startswith("text/html")
    assert fetched == ["http://bucket.s3-website-us-east-1.amazonaws.com/index.html"]
    assert '<script src="config.js">' not in resp["body"]
    cfg = json.loads(resp["body"].split("window.LEASH_CONFIG = ")[1].split(";</script>")[0])
    assert cfg == {"apiUrl": "https://abc.execute-api.us-east-1.amazonaws.com", "devInstanceId": "i-dev1",
                   "prodInstanceId": "i-prod1", "asgName": "leash-dev-asg"}
    # second call within 60 s is served from the cache
    h.handler(ev, None)
    assert len(fetched) == 1


def test_root_without_bucket_is_404(monkeypatch):
    monkeypatch.delenv("DASHBOARD_BUCKET_URL", raising=False)
    assert h.handler({"routeKey": "GET /index.html"}, None)["statusCode"] == 404
