FROM python:3.11.15-slim-bookworm AS builder

WORKDIR /build

COPY pyproject.toml README.md LICENSE ./
COPY schemas/ schemas/
COPY src/ src/

# Resolve runtime dependencies and build a non-editable wheelhouse. Development
# extras and build tooling never cross into the runtime stage.
RUN python -m pip wheel --disable-pip-version-check --wheel-dir /wheels .


FROM python:3.11.15-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system --gid 10001 cmcp \
    && useradd --system --uid 10001 --gid cmcp --home-dir /var/lib/cmcp cmcp \
    && mkdir -p /etc/cmcp /var/lib/cmcp \
    && chown -R cmcp:cmcp /var/lib/cmcp

COPY --from=builder /wheels /wheels
RUN python -m pip install --disable-pip-version-check --no-index \
        --find-links=/wheels cmcp-runtime \
    && rm -rf /wheels

WORKDIR /var/lib/cmcp
USER 10001:10001

EXPOSE 8443

CMD ["cmcp", "start", "--config", "/etc/cmcp/config.yaml"]
