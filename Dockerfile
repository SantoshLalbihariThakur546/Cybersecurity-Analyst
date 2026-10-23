FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/northstar
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn
COPY app ./app
COPY static ./static
COPY run.py .
RUN useradd --create-home --uid 10001 appuser && mkdir -p /srv/northstar/data && chown -R appuser /srv/northstar
USER appuser
ENV HOST=0.0.0.0 PORT=5000
EXPOSE 5000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5000/health')" || exit 1
# one worker with threads: the audit hash-chain lock and login rate limiter are process-local
CMD ["gunicorn", "--workers", "1", "--threads", "8", "--bind", "0.0.0.0:5000", "run:app"]
