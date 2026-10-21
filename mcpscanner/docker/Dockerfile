# PyPI behavioural scanner image.
#
# ``INSTALL_FROM_SOURCE=1`` builds from the checkout (recommended while
# developing this branch). Otherwise ``SCANNER_PACKAGE_VERSION`` pins the
# PyPI release installed inside the container. Either way, dependencies come
# from requirements.lock.txt (the hash-pinned export of uv.lock) and the
# scanner is installed with --no-deps so pip cannot re-resolve them.

ARG PYTHON_BASE_IMAGE=python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0
FROM ${PYTHON_BASE_IMAGE}

ARG SCANNER_PACKAGE_VERSION=""
ARG INSTALL_FROM_SOURCE=0

RUN apk add --no-cache gcc musl-dev libffi-dev

WORKDIR /build

COPY pyproject.toml README.md ./
COPY mcpscanner ./mcpscanner

RUN pip install --no-cache-dir --require-hashes \
      -r mcpscanner/docker/requirements.lock.txt \
 && if [ "$INSTALL_FROM_SOURCE" = "1" ]; then \
      pip install --no-cache-dir --no-deps .; \
    elif [ -n "$SCANNER_PACKAGE_VERSION" ]; then \
      pip install --no-cache-dir --no-deps "cisco-ai-mcp-scanner==${SCANNER_PACKAGE_VERSION}"; \
    else \
      pip install --no-cache-dir --no-deps cisco-ai-mcp-scanner; \
    fi \
 && pip check \
 && apk del gcc musl-dev libffi-dev

COPY mcpscanner/docker/entrypoint.py /entrypoint.py

RUN adduser -D -u 10001 scanner \
 && mkdir -p /work/download /work/package \
 && chown -R scanner:scanner /work /entrypoint.py
USER scanner
WORKDIR /work

ENTRYPOINT ["python", "/entrypoint.py"]
