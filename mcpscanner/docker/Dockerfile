FROM python:3.13-alpine

RUN apk add --no-cache gcc musl-dev libffi-dev && \
    pip install --no-cache-dir cisco-ai-mcp-scanner && \
    apk del gcc musl-dev libffi-dev

COPY entrypoint.py /entrypoint.py

ENTRYPOINT ["python", "/entrypoint.py"]
