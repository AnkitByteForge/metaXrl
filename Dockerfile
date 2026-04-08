# Build stage for React frontend
FROM node:20-slim AS frontend-builder
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm install --legacy-peer-deps
COPY web/ .
RUN npm run build

# Python backend stage
FROM python:3.11-slim

LABEL maintainer="Ankit Kumar & Jayanth"
LABEL description="SOC Incident Response — OpenEnv environment"

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Copy built frontend from builder stage
COPY --from=frontend-builder /web/dist /app/web/dist

RUN pip install --no-cache-dir -e . --no-deps

ENV PORT=7860
EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -f -X POST http://localhost:7860/reset \
      -H "Content-Type: application/json" \
      -d '{"task_id":"alert_triage"}' || exit 1

CMD ["python", "server.py"]
