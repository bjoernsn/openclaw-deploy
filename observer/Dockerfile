FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Run as uid 1000 — matches the openclaw container's "node" user so the
# observer can read session JSONL files from the shared data volume (read-only).
# No raw Docker socket access needed (connects via TCP socket proxy).
RUN useradd --system --no-create-home --uid 1000 observer
USER observer

COPY observer.py .

CMD ["python", "-u", "observer.py"]
