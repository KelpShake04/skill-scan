# Skill Scan

AI skill·플러그인(SKILL.md, 스크립트) 공급망 보안 검사기. 설치 전에 정적 분석으로 숨은 프롬프트 인젝션, 데이터 유출, 자격증명 접근, 원격 코드 실행, 지속성 설치를 찾는다. 분석 대상 코드는 실행하지 않는다.

Python 3 표준 라이브러리만 사용.

## 실행

```
python3 app.py            # http://localhost:8000
python3 scanner.py <폴더>  # CLI
```

웹 UI 입력: GitHub 저장소 주소, 홈 폴더 안의 폴더, 설치된 skill 전체(`~/.claude/skills`), 악성 샘플 데모.

## 구성

- `scanner.py` 규칙 엔진 (9개 범주, skill별 0~100점, 파일별 SHA-256, MCP 설정 점검). CLI는 `--json` 지원
- `pins.py` 해시 기준선: 처음 점검 때 저장(`~/.skill-scan/pins.json`), 이후 바뀐·추가·삭제된 파일을 '변경됨'으로 표시
- `llm.py` 로컬 Ollama(`qwen3:8b`, 환경변수 `SKILL_SCAN_MODEL`)로 상위 8건 재판정. 참고용이며 점수에 반영하지 않음(점검 대상 문서가 판정 LLM을 속일 수 있으므로). 데이터는 로컬 밖으로 나가지 않음
- `app.py` 웹 UI·API (127.0.0.1 전용, Host 헤더 검증, 경로·입력 제한, `SKILL_SCAN_PORT`로 포트 변경). UI에서 JSON/HTML 리포트 저장
- `samples/evil-skill` 데모용 악성 패턴 샘플 (텍스트일 뿐, 실행하지 말 것)
- 테스트: `python3 -c "import test_scanner as a, test_features as b; [getattr(m,n)() for m in (a,b) for n in dir(m) if n.startswith('test_')]"`

### MCP 설정 점검 규칙

`.mcp.json` 등의 `mcpServers`에서: 셸로 실행(`MCP-SHELL`), 버전 미고정 `npx`/`uvx` 패키지(`MCP-UNPIN`), 평문 http 주소(`MCP-HTTP`), 외부 원격 서버(`MCP-REMOTE`), 설정에 직접 적힌 키·토큰(`MCP-SECRET`).

## 한계

정규식 기반이라 의미를 이해하지 못한다. '양호'는 안전 보장이 아니며, 근거 위치를 보고 사람이 최종 판단해야 한다.
