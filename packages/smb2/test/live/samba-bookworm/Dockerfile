# Samba from Debian bookworm (4.17) for the encrypted live suite:
# AES-GMAC signing (Samba 4.15+) and per-share `smb encrypt = required`.
# BASE can be any Debian bookworm image (for example a mirror of
# debian:bookworm-slim when Docker Hub rate-limits).
ARG BASE=debian:bookworm-slim
FROM ${BASE}
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends samba >/dev/null \
 && rm -rf /var/lib/apt/lists/*
COPY start.sh /start.sh
ENTRYPOINT ["bash", "/start.sh"]
