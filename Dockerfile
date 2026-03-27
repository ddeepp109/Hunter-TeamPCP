FROM python:3.13-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY config.py db.py flagger.py github_checker.py github_resolver.py \
     monitor.py pipeline.py pypi_analyzer.py pypi_feed.py webapp.py ./
COPY templates/ templates/

# SQLite DB will live on the persistent Fly volume mounted at /data
ENV DB_PATH=/data/monitor.db

# Fly.io sets PORT env var (default 8080)
ENV PORT=8080

EXPOSE 8080

# Use gunicorn with app factory for production
# --preload ensures create_app() runs once (init DB, start monitor thread)
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "4", "--timeout", "120", "--preload", "webapp:create_app()"]
