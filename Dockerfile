FROM python:3.13-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY hunter/ hunter/
COPY templates/ templates/

# SQLite DB — /app/data works on both Railway and Fly.io
# Override with DB_PATH env var or Fly volume mount as needed
ENV DB_PATH=/app/data/monitor.db

# Railway sets PORT dynamically; default 8080 for Fly.io
ENV PORT=8080

EXPOSE 8080

# Use shell form so $PORT is expanded at runtime (Railway compatibility)
# Do NOT use --preload: it runs create_app() in the master process,
# and the monitor thread does not survive the fork into workers.
CMD gunicorn --bind "0.0.0.0:$PORT" --workers 1 --threads 4 --timeout 120 "hunter.webapp:create_app()"
