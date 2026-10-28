FROM python:3.12-slim AS runtime-base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN mkdir -p /app/backend /app/data /app/audit-checkpoint /app/reports/red-runs /tmp \
    && chown -R 10001:10001 /app/data /app/audit-checkpoint /app/reports /tmp

COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir -r requirements.txt

FROM runtime-base AS red-runner

COPY backend/config.py ./backend/config.py
COPY red ./red

USER 10001:10001

CMD ["python", "-m", "red.runner", "run"]

FROM runtime-base AS app

COPY backend ./backend
COPY llm ./llm
COPY blue ./blue
COPY frontend ./frontend
COPY policies ./policies
COPY red ./red

USER 10001:10001

CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
