FROM python:3.11-slim

WORKDIR /app

# Install dependencies first — separate layer so Docker caches them
# Only re-runs if requirements.txt changes, not on every code change
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create a non-root user — running as root inside containers is bad practice
RUN useradd -m -u 1000 honeypot && \
    mkdir -p /app/data /app/logs && \
    chown -R honeypot:honeypot /app/data /app/logs

# Copy the rest of the code
COPY . .
RUN chown -R honeypot:honeypot /app

USER honeypot

# Expose all service ports
EXPOSE 2222 8080 2121 2323 5000

# Health check — pings the dashboard API every 30s
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/stats')"

CMD ["python", "main.py"]
