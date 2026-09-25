# Pinned to the multi-arch index digest of the tag, so a republished tag cannot
# change what the image is built from without a reviewed change here.
FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3 AS builder

WORKDIR /build

COPY pyproject.toml README.md LICENSE ./
COPY schemas/ schemas/
COPY src/ src/

# Build only this package's wheel. Its dependencies are installed in the
# runtime stage from the hash-pinned lock, so every package the image runs is
# pinned. Development extras and build tooling never cross into that stage.
RUN python -m pip wheel --disable-pip-version-check --no-deps --wheel-dir /wheels .


FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system --gid 10001 cmcp \
    && useradd --system --uid 10001 --gid cmcp --home-dir /var/lib/cmcp cmcp \
    && mkdir -p /etc/cmcp /var/lib/cmcp \
    && chown -R cmcp:cmcp /var/lib/cmcp

COPY --from=builder /wheels /wheels
COPY requirements/runtime.txt /tmp/runtime.txt
RUN python -m pip install --disable-pip-version-check --no-cache-dir \
        --require-hashes -r /tmp/runtime.txt \
    && python -m pip install --disable-pip-version-check --no-cache-dir \
        --no-index --no-deps /wheels/cmcp_runtime-*.whl \
    && rm -rf /wheels /tmp/runtime.txt

WORKDIR /var/lib/cmcp
USER 10001:10001

EXPOSE 8443

CMD ["cmcp", "start", "--config", "/etc/cmcp/config.yaml"]
