# Alvo SSH de teste do TS Manager. Construído para linux/arm64 (mesma
# arquitetura da VM) via emulação QEMU do Docker Desktop.
FROM ubuntu:24.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server openssh-sftp-server procps \
 && rm -rf /var/lib/apt/lists/*

COPY sshd_config /etc/ssh/sshd_config
COPY audit-shell.sh /usr/local/bin/audit-shell
COPY setup.sh /usr/local/sbin/tsm-setup

RUN chmod 0755 /usr/local/bin/audit-shell /usr/local/sbin/tsm-setup \
 && echo /usr/local/bin/audit-shell >> /etc/shells \
 && groupadd tsm-readers \
 && useradd -m -s /usr/local/bin/audit-shell tsm-dev-a \
 && useradd -m -s /usr/local/bin/audit-shell tsm-dev-b \
 && useradd -m -s /usr/sbin/nologin tsm-manager \
 && usermod -p '*' tsm-dev-a && usermod -p '*' tsm-dev-b \
 && usermod -aG tsm-readers tsm-dev-a \
 && usermod -aG tsm-readers tsm-dev-b \
 && usermod -aG tsm-dev-a,tsm-dev-b tsm-manager \
 && mkdir -p /run/sshd /etc/ssh/orig-host-keys \
 && ssh-keygen -A \
 && cp -p /etc/ssh/ssh_host_* /etc/ssh/orig-host-keys/ \
 && install -m 0666 /dev/null /var/log/tsm-audit.log

VOLUME /srv/ts
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
