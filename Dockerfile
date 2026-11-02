FROM python:3.12-slim

# git: GitHub 저장소 점검용 clone
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 app \
    && mkdir -p /home/app/.skill-scan /home/app/.claude/skills /home/app/scan \
    && chown -R app:app /home/app

WORKDIR /opt/skill-scan
COPY app.py scanner.py pins.py llm.py index.html ./
COPY samples ./samples

USER app
ENV SKILL_SCAN_BIND=0.0.0.0 SKILL_SCAN_PORT=8000 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s \
  CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/' % os.environ['SKILL_SCAN_PORT'], timeout=3)"
CMD ["python", "app.py"]
