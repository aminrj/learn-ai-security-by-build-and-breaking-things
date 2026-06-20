# Shared image for the honeypot, docs server, and (as a base) the sandbox.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY agent ./agent
COPY config ./config
COPY target ./target

RUN pip install --no-cache-dir -e .

# Default command is overridden per-service in docker-compose.yml.
CMD ["python", "-c", "print('asl base image')"]
