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

- `scanner.py` 규칙 엔진 (8개 범주, 14개 규칙, skill별 0~100점)
- `app.py` 웹 UI·API (127.0.0.1 전용, Host 헤더 검증, 경로·입력 제한)
- `samples/evil-skill` 데모용 악성 패턴 샘플 (텍스트일 뿐, 실행하지 말 것)
- `test_scanner.py` 테스트: `python3 -c "import test_scanner as t; [getattr(t,n)() for n in dir(t) if n.startswith('test_')]"`

## 한계

정규식 기반이라 의미를 이해하지 못한다. '양호'는 안전 보장이 아니며, 근거 위치를 보고 사람이 최종 판단해야 한다.
