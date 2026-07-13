# PyPI behavioural scanner image.
#
# ``INSTALL_FROM_SOURCE=1`` builds from the checkout (recommended while
# developing this branch). Otherwise ``SCANNER_PACKAGE_VERSION`` pins the
# PyPI release installed inside the container.

FROM python:3.13-alpine

ARG SCANNER_PACKAGE_VERSION=""
ARG INSTALL_FROM_SOURCE=0

RUN apk add --no-cache gcc musl-dev libffi-dev

WORKDIR /build

COPY pyproject.toml README.md ./
COPY mcpscanner ./mcpscanner

RUN if [ "$INSTALL_FROM_SOURCE" = "1" ]; then \
      pip install --no-cache-dir .; \
    elif [ -n "$SCANNER_PACKAGE_VERSION" ]; then \
      pip install --no-cache-dir "cisco-ai-mcp-scanner==${SCANNER_PACKAGE_VERSION}"; \
    else \
      pip install --no-cache-dir cisco-ai-mcp-scanner; \
    fi \
 && apk del gcc musl-dev libffi-dev

COPY mcpscanner/docker/entrypoint.py /entrypoint.py

RUN adduser -D -u 10001 scanner \
 && mkdir -p /work/download /work/package \
 && chown -R scanner:scanner /work /entrypoint.py
USER scanner
WORKDIR /work

ENTRYPOINT ["python", "/entrypoint.py"]
