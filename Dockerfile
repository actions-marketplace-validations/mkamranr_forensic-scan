# Multi-stage: the wheel is built with uv, then installed into a slim runtime.
# Useful for CI images without Python, and for scanning an untrusted repository
# inside a container rather than on your workstation.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS build

WORKDIR /build
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv build --wheel --out-dir /dist

FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="forensic-scan" \
      org.opencontainers.image.description="Forensic AST scanner for hidden logic and obfuscation" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/mkamranr/forensic-scan"

# git is required for --diff mode and nothing else.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Scanning untrusted code should not run as root.
RUN useradd --create-home --uid 1000 scanner

# Bake the tree-sitter grammars into the image.
#
# `tree-sitter-language-pack` fetches grammars on first use. Without this step
# the image cannot parse anything when run with `--network none`, which is
# exactly how you should run a scanner over untrusted code. The cache is written
# as the scanner user so it is readable at runtime.
ENV XDG_CACHE_HOME=/home/scanner/.cache
USER scanner
RUN forensic-scan prefetch

WORKDIR /src

ENTRYPOINT ["forensic-scan"]
CMD ["."]
