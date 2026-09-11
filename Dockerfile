# Multi-stage unprivileged build for Vaishnavi Antivirus
FROM python:3.12-alpine AS builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY Vaishnavi_Antivirus_Full_GUI/ Vaishnavi_Antivirus_Full_GUI/

RUN pip install --no-cache-dir --upgrade pip && \
    pip wheel --no-deps -w /dist .

FROM python:3.12-alpine AS runner

WORKDIR /app

# Install package from builder wheel
COPY --from=builder /dist/*.whl /dist/
RUN pip install --no-cache-dir /dist/*.whl psutil && rm -rf /dist

# Non-root unprivileged execution
RUN adduser -D -u 10001 vaishnavi && \
    mkdir -p /app/quarantine_vault && \
    chown -R vaishnavi:vaishnavi /app

ENV VAISHNAVI_QUARANTINE_DIR=/app/quarantine_vault
USER vaishnavi


ENTRYPOINT ["vaishnavi-av"]
CMD ["--help"]
