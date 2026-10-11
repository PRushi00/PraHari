# ==========================================
# PraHari — Multi-Stage Production Dockerfile
# ==========================================

# Stage 1: Build Frontend Assets
FROM node:20-alpine AS frontend-builder
WORKDIR /build/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Stage 2: Production Python Backend + Embedded UI
FROM python:3.12-slim AS runner

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/app ./app
COPY backend/pyproject.toml ./

# Copy compiled frontend from Stage 1 into expected directory
COPY --from=frontend-builder /build/frontend/dist /frontend/dist

# Security: Non-root user
RUN useradd -m -u 1000 prahari && \
    mkdir -p /data && chown -R prahari:prahari /app /data /frontend

USER prahari

# Environment
ENV PYTHONUNBUFFERED=1 \
    PRAHARI_HOST="0.0.0.0" \
    PRAHARI_PORT=8000 \
    PRAHARI_DATABASE_URL="sqlite:////data/prahari.db"

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/api/v1/health || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
