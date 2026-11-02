import json
import os
import re
import shutil
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import llm
import pins
from scanner import scan, scan_each

PORT = int(os.environ.get("SKILL_SCAN_PORT", 8000))
HOME = os.path.realpath(os.path.expanduser("~"))
SKILLS = os.path.join(HOME, ".claude", "skills")
GH_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+?(\.git)?/?$")
BLOCKED_PARTS = {".ssh", ".aws", ".gnupg", ".kube", "Keychains", ".config", ".docker"}

PAGE = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"), encoding="utf-8").read()


def resolve(target):
    """Return (list of report dicts, cleanup path|None) or raise ValueError with a user message."""
    here = os.path.dirname(os.path.abspath(__file__))
    if target == "@sample":
        return [scan(os.path.join(here, "samples", "evil-skill"))], None
    if target == "@installed":
        return scan_each(SKILLS), None
    if GH_RE.match(target):
        tmp = tempfile.mkdtemp(prefix="skillscan-")
        try:
            subprocess.run(["git", "clone", "--depth", "1", "--no-tags", "--quiet",
                            "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", target, tmp + "/r"],
                           timeout=60, check=True, stdin=subprocess.DEVNULL, capture_output=True,
                           env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        except (subprocess.SubprocessError, OSError):
            shutil.rmtree(tmp, ignore_errors=True)
            raise ValueError("저장소를 내려받지 못했습니다 (비공개이거나 주소 오류)")
        return [scan(tmp + "/r")], tmp
    path = os.path.realpath(os.path.expanduser(target))
    parts = set(path.split(os.sep))
    if not (path == HOME or path.startswith(HOME + os.sep)) or parts & BLOCKED_PARTS or not os.path.isdir(path):
        raise ValueError("홈 폴더 안의 폴더 경로 또는 GitHub 저장소 주소만 입력할 수 있습니다")
    return [scan(path)], None


def view(r):
    return {"name": os.path.basename(r["root"]) if not r["root"].endswith("/r") else "repository",
            "score": r["score"], "level": r["level"], "files": r["files"], "findings": r["findings"][:25],
            "diff": r.get("diff")}


class H(BaseHTTPRequestHandler):
    def _send(self, body, ct, code=200):
        self.send_response(code)
        self.send_header("Content-Type", ct + "; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def _host_ok(self):
        # blocks DNS rebinding: a web page cannot reach this server under its own hostname
        return self.headers.get("Host") in (f"127.0.0.1:{PORT}", f"localhost:{PORT}")

    def do_GET(self):
        self._send(PAGE, "text/html") if self._host_ok() else self._send("bad host", "text/plain", 403)

    def do_POST(self):
        if not self._host_ok() or self.path != "/api/scan" or self.headers.get("Content-Type") != "application/json":
            return self._send("bad request", "text/plain", 400)
        try:
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(min(n, 2000)))
            target = str(req.get("target", "")).strip()
            results, tmp = resolve(target)
        except ValueError as e:
            return self._send(json.dumps({"error": str(e)}), "application/json")
        except (TypeError, AttributeError):
            return self._send("bad json", "text/plain", 400)
        try:
            if target != "@sample":
                for r in results:
                    # a clone lives in a fresh temp dir each time, so key repos by their URL
                    r["diff"] = pins.check(target if GH_RE.match(target) else r["root"], r["hashes"], bool(req.get("pin")))
            judged = llm.enrich(results) if req.get("llm") else None
            self._send(json.dumps({"results": [view(r) for r in results], "judged": judged}), "application/json")
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
