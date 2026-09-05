#!/usr/bin/env python3
"""Bounded Coordinator health and optional scan acceptance check."""

import argparse
import json
import time
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def request(url, path, token=None, data=None, content_type=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url.rstrip("/") + path, data=data, headers=headers)
    try:
        with OPENER.open(req, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8090")
    parser.add_argument("--key-file")
    args = parser.parse_args()
    for path in ("/healthz", "/readyz"):
        status, _ = request(args.url, path)
        if status != 200:
            raise SystemExit(f"{path} returned HTTP {status}")
    report = {"health": "ok", "ready": "ok"}
    if args.key_file:
        token = open(args.key_file, encoding="utf-8").read().strip()
        boundary = "ark-coordinator-smoke"
        body = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"config\"\r\n\r\n"
            '{"categories":["injection"],"max_level":"L2"}'
            f"\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\n"
            f"A short ordinary sentence.\r\n--{boundary}--\r\n"
        ).encode()
        status, payload = request(
            args.url,
            "/v1/scan",
            token,
            body,
            f"multipart/form-data; boundary={boundary}",
        )
        if status != 202:
            raise SystemExit(f"scan submit returned HTTP {status}")
        jobs = json.loads(payload)["jobs"]
        if len(jobs) != 1 or not jobs[0].get("status_url"):
            raise SystemExit("scan submit returned an invalid job contract")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            status, payload = request(args.url, jobs[0]["status_url"], token)
            if status != 200:
                raise SystemExit(f"scan poll returned HTTP {status}")
            result = json.loads(payload)
            if result.get("status") in {"completed", "failed"}:
                if result.get("status") != "completed" or result.get("completion", {}).get("state") != "complete":
                    raise SystemExit("scan did not complete successfully")
                report["scan"] = "completed"
                break
            time.sleep(0.05)
        else:
            raise SystemExit("scan did not complete within 60 seconds")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
