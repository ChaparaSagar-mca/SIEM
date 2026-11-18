# Multi-stage build for SIEM-lite project
# Stage 1: Build React frontend
FROM node:18-alpine AS frontend-builder

WORKDIR /app/dashboard
COPY dashboard/package*.json ./
RUN npm install

COPY dashboard/ ./
RUN npm run build

# Stage 2: Python backend
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=server/analyzer.py
ENV FLASK_ENV=production

# Create app directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Copy built React app from frontend-builder stage
COPY --from=frontend-builder /app/dashboard/build ./dashboard/build

# Create necessary directories
RUN mkdir -p /app/data /app/logs

# Create non-root user
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Default command
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
