# unopened in a container: every optional analyzer installed, no network needed at run time.
#
#   docker build -t unopened .
#   docker run --rm --network none -v "$PWD:/work" unopened triage /work/suspicious.bin
#   docker run --rm --network none -v "$PWD:/work" unopened \
#       triage /work/reported.eml --format all --out /work/reports
#
# --network none is the point: the container cannot reach anything, so even a bug could
# not fetch or send a sample. Reputation lookups (--reputation) need the network and are
# the one exception.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="unopened" \
      org.opencontainers.image.description="Static malware triage for SOC analysts. Never executes the sample." \
      org.opencontainers.image.licenses="MIT"

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends git build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pyproject.toml README.md LICENSE* ./
COPY src ./src
# oscrypto 1.3.0 on PyPI cannot parse OpenSSL 3.0.10+ version strings, so Authenticode
# checks fail without the upstream fix; both report version 1.3.0 (see README, Install).
RUN pip install ".[all]" \
 && pip install --force-reinstall --no-deps \
      "oscrypto @ git+https://github.com/wbond/oscrypto.git@1547f535001ba568b239b8797465536759c742a3" \
 && python -c "import signify.authenticode, capa, floss, yara, oletools" \
 && apt-get purge -y git build-essential && apt-get autoremove -y \
 && rm -rf /src

RUN useradd --create-home --uid 10001 analyst
USER analyst
WORKDIR /work
ENTRYPOINT ["unopened"]
CMD ["--help"]
