import json
import os
import re
import shutil
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanner import scan, scan_each

HOME = os.path.realpath(os.path.expanduser("~"))
SKILLS = os.path.join(HOME, ".claude", "skills")
GH_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+?(\.git)?/?$")
BLOCKED_PARTS = {".ssh", ".aws", ".gnupg", ".kube", "Keychains", ".config", ".docker"}

PAGE = """<!doctype html><meta charset=utf-8><title>Skill Scan</title>
<style>body{font:15px system-ui;max-width:860px;margin:36px auto;padding:0 16px}input{width:70%;padding:8px}
button{padding:8px 12px;margin:2px}.c{border:1px solid #ddd;border-radius:8px;padding:8px 14px;margin:8px 0}
.b{height:10px;background:#eee;border-radius:5px;width:140px;display:inline-block;vertical-align:middle}.b i{display:block;height:100%;border-radius:5px}
code{background:#f4f4f4;padding:1px 4px;border-radius:3px;font-size:13px}small{color:#666}summary{cursor:pointer}</style>
<h1>Skill Scan <small>AI skill·플러그인 공급망 보안 검사기</small></h1>
<p>설치 전에 SKILL.md·스크립트를 정적 분석해 숨은 프롬프트 인젝션, 데이터 유출, 자격증명 접근, 원격 코드 실행, 지속성 설치를 찾습니다. 코드는 실행하지 않습니다.</p>
<input id=t placeholder="https://github.com/owner/repo  또는  ~/내폴더/skill"> <button onclick="go(t.value)">점검</button><br>
<button onclick="go('@installed')">내 PC에 설치된 skill 전체 점검</button>
<button onclick="go('@sample')">악성 샘플 점검 (데모)</button>
<div id=r></div>
<script>
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const col=s=>s>=60?'#d33':s>=20?'#e90':'#2a2';
async function go(t){r.textContent='점검 중... (GitHub 저장소는 내려받는 데 시간이 걸립니다)';
const d=await (await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:t})})).json();
if(d.error){r.textContent=d.error;return}
r.innerHTML=d.results.map(x=>`<div class=c><details><summary><b style="color:${col(x.score)}">${esc(x.level)} ${x.score}</b>
<span class=b><i style="width:${x.score}%;background:${col(x.score)}"></i></span> <b>${esc(x.name)}</b> <small>파일 ${x.files}개 · 탐지 ${x.findings.length}건</small></summary>`+
(x.findings.map(f=>`<p><b>[${esc(f.id)}]</b> ${esc(f.cat)} — ${esc(f.desc)} <small>${esc(f.file)}:${f.line} (${f.count}곳)</small><br><code>${esc(f.snippet)}</code><br><small>조치: ${esc(f.fix)}</small></p>`).join('')||'<p>탐지된 신호 없음 (안전을 보장하지는 않음)</p>')+'</details></div>').join('');}
</script>"""


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
            "score": r["score"], "level": r["level"], "files": r["files"], "findings": r["findings"][:25]}


class H(BaseHTTPRequestHandler):
    def _send(self, body, ct, code=200):
        self.send_response(code)
        self.send_header("Content-Type", ct + "; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def _host_ok(self):
        # blocks DNS rebinding: a web page cannot reach this server under its own hostname
        return self.headers.get("Host") in ("127.0.0.1:8000", "localhost:8000")

    def do_GET(self):
        self._send(PAGE, "text/html") if self._host_ok() else self._send("bad host", "text/plain", 403)

    def do_POST(self):
        if not self._host_ok() or self.path != "/api/scan" or self.headers.get("Content-Type") != "application/json":
            return self._send("bad request", "text/plain", 400)
        try:
            n = int(self.headers.get("Content-Length", 0))
            target = str(json.loads(self.rfile.read(min(n, 2000))).get("target", "")).strip()
            results, tmp = resolve(target)
        except ValueError as e:
            return self._send(json.dumps({"error": str(e)}), "application/json")
        except (TypeError, AttributeError):
            return self._send("bad json", "text/plain", 400)
        try:
            self._send(json.dumps({"results": [view(r) for r in results]}), "application/json")
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8000), H).serve_forever()
