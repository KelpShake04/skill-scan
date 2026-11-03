import bisect
import hashlib
import json
import os
import re

TEXT_EXT = {".md", ".json", ".py", ".sh", ".js", ".ts", ".mjs", ".yml", ".yaml", ".toml", ".txt", ".bash", ".zsh"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}
DENY_NAMES = re.compile(r"^(\.env.*|id_(rsa|ed25519|ecdsa).*|.*\.(pem|key|p12)|\.npmrc|\.netrc|credentials)$", re.I)
MAX_BYTES = 4 * 1024 * 1024  # bigger files are reported as SIZE-SKIP, never skipped silently
# "do not forget to ..." is a double negative: it still tells the agent to act
NEG = re.compile(r"\b(never|not|don't|do not|must not|avoid|reject|treat)\b(?!\s+(forget|fail|hesitate|neglect)\b)|하지 ?마", re.I)
CODE_CATS = {"데이터 유출", "자격증명 접근", "원격 코드 실행", "지속성", "파괴적 명령"}
SECRET_RE = re.compile(r"(sk-[A-Za-z0-9_-]{10,}|ghp_\w{10,}|AKIA\w{12,}|xox[bp]-[\w-]{10,})")
INLINE_RISK = re.compile(r"environ|process\.env|https?://|socket|base64|subprocess|child_process|exec|eval|urllib|requests|fetch\(")

# (id, category, weight, regex, 한국어 설명, 조치)
R = [
    ("PI-IGNORE", "프롬프트 인젝션", 35,
     r"ignore (all |any )?(the )?(previous|prior|above) (instructions|rules)|disregard (all |any )?(previous|prior|the above)|이전 (지시|명령)(을|를)? 무시",
     "이전 지시를 무시하라는 문구", "해당 문구 삭제, 출처 불명이면 설치 금지"),
    ("PI-HIDE", "프롬프트 인젝션", 35,
     r"\b(silently|secretly|covertly|quietly)\b[^.\n]{0,15}\b(?<!\ba )(?<!\bthe )(run|execute|send|upload|download|install|curl)\b|(do not|don't|never) (tell|inform|mention|reveal|disclose)[^.\n]{0,25}(this|that|it|the \w+( step| script| command)?) to the user|사용자(에게)? (알리지|말하지) ?(말|마)",
     "사용자 몰래 실행/숨기라는 지시", "사용자 몰래 동작하는 skill은 신뢰 불가"),
    ("PI-COMMENT", "프롬프트 인젝션", 25,
     r"<!--[^>]{0,400}?(ignore|instruction|execute|run |curl|send|upload|secret|token)[^>]{0,400}?-->",
     "HTML 주석에 숨긴 지시 (렌더링 시 안 보임)", "원문 전체를 열어 주석 내용을 확인"),
    ("PI-INVISIBLE", "프롬프트 인젝션", 30, r"[\u200b\u200e\u200f\u2060\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]",
     "보이지 않는 유니코드 문자 (숨은 지시 은닉에 사용)", "해당 문자 제거 후 내용 재확인"),
    ("EXF-HOOK", "데이터 유출", 40,
     r"discord(app)?\.com/api/webhooks|webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|transfer\.sh|pastebin\.com/api|interact\.sh|oast\.",
     "데이터 수집용으로 흔한 외부 수신 주소", "해당 주소로의 전송 제거"),
    ("EXF-POST", "데이터 유출", 25,
     r"curl[^\n]{0,80}(-d|--data|-F|--upload-file|-T)\b|requests\.post\(|urllib\.request\.urlopen\([^)]*data=|fetch\([^)]*method:\s*['\"]POST",
     "외부로 데이터를 전송하는 코드", "전송 대상과 내용이 설명과 일치하는지 확인"),
    ("CRED-FILE", "자격증명 접근", 35,
     r"\b(cat|open\(|read\w*|cp|scp|tar|zip|base64|curl|upload|send)\b[^\n]{0,80}(~/\.ssh|\.aws/credentials|\.config/gcloud|\.kube/config|\.docker/config\.json|\.netrc|id_rsa|\.gnupg|Library/Keychains|(?-i:Login Data)|(?-i:/Cookies\b))",
     "SSH 키·클라우드 자격증명·브라우저 쿠키 등 민감 파일을 읽거나 전송", "skill이 이런 파일에 접근할 이유가 없다면 삭제"),
    ("CRED-CMD", "자격증명 접근", 35,
     r"security (find|dump)-(generic|internet)-password|printenv\b|\benv\s*\|\s*(curl|nc|base64)|cat\s+[^\n|]*\.env\b",
     "키체인·환경변수·.env 덤프", "시크릿 접근 제거"),
    ("EXEC-PIPE", "원격 코드 실행", 40,
     r"(curl|wget)\s+[^\s|][^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b|(ba|z)?sh\s+-c\s+[\"']?\$\((curl|wget)|base64\s+(-d|--decode)[^\n]*\|\s*(ba|z)?sh",
     "내려받은 코드를 검증 없이 실행", "스크립트를 받아 내용 확인 후 실행"),
    # shortcut: "eval (" with a space is not flagged (prose like "the eval (Step 0)"); revisit if attacks use it
    ("EXEC-EVAL", "원격 코드 실행", 20, r"\beval\(|\bexec\s*\(\s*(base64|compile|requests)|powershell[^\n]*-enc",
     "동적 코드 실행/인코딩된 명령", "정적 코드로 대체"),
    ("PERSIST", "지속성", 30,
     r"crontab\b|launchctl (load|bootstrap)|LaunchAgents|>>\s*~/\.(zshrc|bashrc|profile)|authorized_keys|\.git/hooks|systemctl enable",
     "재부팅·셸 실행 후에도 남는 설치 (백도어 전형)", "자동 실행 등록 제거"),
    ("DESTRUCT", "파괴적 명령", 25,
     r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+(~|/|\$HOME)(\s|/|$)|git push (-f|--force)|chmod\s+-?R?\s*777|mkfs\.|dd\s+if=.*of=/dev/",
     "홈·루트 삭제, 강제 push 등 되돌리기 어려운 명령", "사용자 확인 단계 없이는 사용 금지"),
    ("PERM-BYPASS", "과도한 권한", 30, r"\"defaultMode\"\s*:\s*\"bypassPermissions\"|--permission-mode[= ]bypassPermissions",
     "Claude Code 권한 확인을 모두 끄는 설정 (bypassPermissions)", "기본 권한 모드로 되돌리기"),
    ("ENV-BASEURL", "데이터 유출", 35, r"\"ANTHROPIC_BASE_URL\"\s*:\s*\"",
     "API 요청 주소를 바꾸는 설정 (API 키·대화가 다른 서버로 전송)", "설정 삭제, 이미 열었다면 API 키 폐기"),
    ("HOOK-CMD", "지속성", 20, r"\"hooks\"\s*:\s*\{[\s\S]{0,2000}?\"command\"\s*:",
     "Claude Code 훅: 세션 시작·도구 사용 때 명령이 자동 실행됨", "훅 명령 내용을 확인하고 필요 없으면 삭제"),
    ("PERM-WILD", "과도한 권한", 15, r"allowed-tools:\s*.*(\*|Bash\(\*\))|--dangerously-skip-permissions",
     "모든 도구/권한 승인 우회", "필요한 도구만 명시"),
    ("OBFUSC", "난독화", 20, r"[A-Za-z0-9+/=]{300,}",
     "긴 인코딩 덩어리 (내용 은닉 가능)", "디코딩해 내용 확인"),
]
RULES = [(i, c, w, re.compile(p, re.I | re.S if i == "PI-COMMENT" else re.I), d, f) for i, c, w, p, d, f in R]


def mask(s):
    return SECRET_RE.sub("[REDACTED]", s)[:110]


def scan_mcp(text, rel):
    """Check MCP server definitions (mcpServers in .mcp.json / plugin.json) for risky launch settings."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        return []
    out = []

    def add(name, rid, w, desc, fix, snip):
        i = text.find(json.dumps(name))
        out.append({"id": rid, "cat": "MCP 설정", "w": w, "file": rel, "line": text.count("\n", 0, max(i, 0)) + 1,
                    "count": 1, "desc": desc, "fix": fix, "snippet": mask(snip)})

    for name, s in servers.items():
        if not isinstance(s, dict):
            continue
        cmd = str(s.get("command", ""))
        args = [str(a) for a in s["args"]] if isinstance(s.get("args"), list) else []
        line = " ".join([name + ":", cmd] + args)
        exe = os.path.basename(cmd)
        if exe in ("sh", "bash", "zsh", "cmd", "powershell", "pwsh"):
            add(name, "MCP-SHELL", 30, "MCP 서버를 셸로 실행 (명령 주입·원격 실행에 쓰이기 쉬움)", "직접 실행 파일/패키지를 지정", line)
        if (exe in ("node", "python", "python3", "deno", "bun", "ruby", "perl", "php")
                and any(a in ("-e", "-c", "--eval", "-p") for a in args) and INLINE_RISK.search(" ".join(args))):
            add(name, "MCP-INLINE", 30, "MCP 서버 인자에 인라인 코드 (환경변수·네트워크·실행 코드 포함)", "코드를 파일로 분리해 내용 확인", line)
        if exe in ("curl", "wget", "nc", "ncat", "nslookup", "dig", "host"):
            add(name, "MCP-NETTOOL", 25, "MCP 서버 자리에서 네트워크 도구 실행 (외부 전송·DNS 유출)", "MCP 서버가 아니면 삭제", line)
        if exe in ("npx", "bunx", "pnpx", "uvx", "pipx"):
            pkgs = [a for a in args if not a.startswith("-")]
            if pkgs and not re.search(r"[^@]@\d|==\d", pkgs[0]):
                add(name, "MCP-UNPIN", 15, "버전을 고정하지 않은 패키지를 실행 (업데이트로 악성 코드가 들어올 수 있음)",
                    "패키지@정확한버전으로 고정", line)
        url = str(s.get("url", ""))
        if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1)\b", url):
            add(name, "MCP-HTTP", 20, "암호화되지 않은 원격 MCP 주소", "https 사용", f"{name}: {url}")
        elif url.startswith("https://"):
            add(name, "MCP-REMOTE", 10, "외부 원격 MCP 서버 사용 (도구 설명·응답을 외부가 통제)", "운영 주체와 신뢰 여부 확인", f"{name}: {url}")
        env = s.get("env") if isinstance(s.get("env"), dict) else {}
        for k, v in env.items():
            v = str(v)
            if SECRET_RE.search(v) or (re.search(r"KEY|TOKEN|SECRET|PASSWORD", k, re.I) and v and not v.startswith("$")):
                add(name, "MCP-SECRET", 25, "설정 파일에 키·토큰이 직접 적혀 있음", "환경변수 참조로 바꾸고 이미 노출됐다면 키 폐기", f"{name}.env.{k} = [REDACTED]")
    return out


def fenced_lines(text):
    """Line numbers inside ``` blocks of a markdown file."""
    inside, out = False, set()
    for i, line in enumerate(text.split("\n"), 1):
        if line.lstrip().startswith("```"):
            inside = not inside
        elif inside:
            out.add(i)
    return out


def scan_file(path, rel):
    """Return (findings, sha256 of the text) for one file; ([], None) if unreadable."""
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except (UnicodeDecodeError, OSError):
        return [], None
    sha = hashlib.sha256(text.encode()).hexdigest()
    out = scan_mcp(text, rel) if rel.lower().endswith(".json") and "mcpServers" in text else []
    # in .md only prose is halved: code in ``` blocks is what the agent will run
    fenced = fenced_lines(text) if rel.lower().endswith(".md") else None
    nl = [x.start() for x in re.finditer("\n", text)] if fenced else []
    for rid, cat, w, rx, desc, fix in RULES:
        if rid == "PI-HIDE" and not rel.lower().endswith(".md"):
            continue
        ms = [x for x in rx.finditer(text) if not (cat == "프롬프트 인젝션" and (
            NEG.search(text[max(text.rfind("\n", 0, x.start()) + 1, x.start() - 40):x.start()])
            or (x.start() > 0 and text[x.start() - 1] in "\"'`“‘")))]
        m = next((x for x in ms if fenced and cat in CODE_CATS and bisect.bisect_left(nl, x.start()) + 1 in fenced),
                 ms[0] if ms else None)
        if m:
            ls = text.rfind("\n", 0, m.start()) + 1
            le = text.find("\n", m.start())
            ln = text.count("\n", 0, m.start()) + 1
            out.append({"id": rid, "cat": cat, "w": w // 2 if cat in CODE_CATS and fenced is not None and ln not in fenced else w,
                        "file": rel, "line": ln,
                        "count": len(rx.findall(text)), "desc": desc, "fix": fix,
                        "snippet": mask(text[ls:le if le != -1 else None].strip())})
    return out, sha


def scan(root):
    """Scan text files under root (symlinks not followed). Returns report dict incl. per-file hashes."""
    root = os.path.realpath(root)
    findings, hashes = [], {}
    for d, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for name in files:
            p = os.path.join(d, name)
            if os.path.splitext(name)[1].lower() not in TEXT_EXT or DENY_NAMES.match(name) or os.path.islink(p):
                continue
            rel = os.path.relpath(p, root)
            if os.path.getsize(p) > MAX_BYTES:
                findings.append({"id": "SIZE-SKIP", "cat": "검사 누락", "w": 20, "file": rel, "line": 1, "count": 1,
                                 "desc": f"{MAX_BYTES // (1024 * 1024)}MB 넘는 파일이라 검사하지 않음 (내용 은닉에 쓰일 수 있음)",
                                 "fix": "직접 열어 확인하거나 불필요하면 삭제", "snippet": f"{os.path.getsize(p)} bytes"})
                continue
            fs, sha = scan_file(p, rel)
            findings += fs
            if sha:
                hashes[rel] = sha
    # one weight per category so a noisy category can't drown the others; total capped at 100
    by = {}
    for f in findings:
        by[f["cat"]] = max(by.get(f["cat"], 0), f["w"])
    score = min(sum(by.values()), 100)
    return {"root": root, "files": len(hashes), "score": score, "level": level(score), "hashes": hashes,
            "findings": sorted(findings, key=lambda f: -f["w"])}


def level(s):
    return "위험" if s >= 60 else "주의" if s >= 20 else "양호"


def scan_each(root):
    """Scan every immediate subdirectory (one skill/plugin each); loose files are skipped."""
    root = os.path.realpath(root)
    res = [scan(os.path.join(root, d)) for d in sorted(os.listdir(root))
           if os.path.isdir(os.path.join(root, d)) and d not in SKIP_DIRS and not os.path.islink(os.path.join(root, d))]
    return sorted(res, key=lambda r: -r["score"])


if __name__ == "__main__":
    import sys
    r = scan(sys.argv[1])
    if "--json" in sys.argv:
        print(json.dumps({k: v for k, v in r.items() if k != "hashes"}, ensure_ascii=False, indent=2))
    else:
        print(f"{r['level']} {r['score']}/100  ({r['files']} files)  {r['root']}")
        for f in r["findings"]:
            print(f"  [{f['id']}] {f['file']}:{f['line']} x{f['count']}  {f['desc']}\n      {f['snippet']}")
