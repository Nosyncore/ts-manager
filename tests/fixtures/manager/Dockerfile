# Manager dentro do alvo SSH de teste (linux/arm64), rodando como tsm-manager.
# Contexto de build montado pelo teste: common/ e server/ do repositório + este arquivo.
ARG BASE=tsm-sshd-test:arm64
FROM ${BASE}

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-venv git socat ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && usermod -aG tsm-readers tsm-manager

COPY common /opt/tsm-src/common
COPY server /opt/tsm-src/server
RUN python3 -m venv /opt/tsm-venv \
 && /opt/tsm-venv/bin/pip install --no-cache-dir /opt/tsm-src/common /opt/tsm-src/server \
 && install -d -o root -g tsm-manager -m 0750 /etc/tsm
