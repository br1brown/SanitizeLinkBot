# Build stage
FROM python:3.10-slim as builder

WORKDIR /app

# Installa dependencies di build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.10-slim

WORKDIR /app

# Copia dipendenze dal builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Crea user non-root
RUN useradd -m -u 1000 botuser && chown -R botuser:botuser /app

# Copia codice
COPY --chown=botuser:botuser . .

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import os; exit(0 if os.path.exists('.running') else 1)" || exit 1

USER botuser

CMD ["python", "-m", "SanitizeLinkBot"]
