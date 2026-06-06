FROM python:3.11-slim

WORKDIR /app

# Install package
COPY pyproject.toml .
COPY src/ src/
RUN python -m pip install --upgrade pip setuptools && pip install -e ".[dev]"

# Config, policy, catalog injected via volume mounts
RUN mkdir -p /etc/cmcp

EXPOSE 8443

CMD ["cmcp", "start", "--config", "/etc/cmcp/config.yaml"]
