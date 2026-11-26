#!/bin/sh
# Referência executável das permissões do servidor de teste.
#   tsm-setup reset              recria /srv/ts e semeia o shared a partir de /opt/demo
#   tsm-setup authorize USER     lê a chave pública da entrada padrão (authorized_keys com restrict)
#   tsm-setup restore-host-keys  restaura as chaves de host originais
#   tsm-setup clear-agents       remove agentes Mutagen instalados nas contas de dispositivo
set -eu

ROOT=/srv/ts/projects/demo
DEVS="tsm-dev-a tsm-dev-b"

kill_dev_processes() {
  for u in $DEVS; do pkill -KILL -u "$u" 2>/dev/null || true; done
}

case "${1:-}" in
  reset)
    kill_dev_processes
    rm -rf /srv/ts/projects
    install -d -o root -g root -m 0755 /srv/ts/projects "$ROOT"
    install -d -o root -g root -m 0711 "$ROOT/workspaces"
    install -d -o tsm-dev-a -g tsm-dev-a -m 2750 "$ROOT/workspaces/dev-a" "$ROOT/workspaces/dev-a-h9"
    install -d -o tsm-dev-b -g tsm-dev-b -m 2750 "$ROOT/workspaces/dev-b"
    install -d -o tsm-manager -g tsm-readers -m 2750 "$ROOT/shared"
    install -d -o tsm-manager -g tsm-manager -m 0700 "$ROOT/history"
    if [ -d /opt/demo ]; then
      cp -R /opt/demo/. "$ROOT/shared/"
      chown -R tsm-manager:tsm-readers "$ROOT/shared"
      find "$ROOT/shared" -type d -exec chmod 2750 {} +
      find "$ROOT/shared" -type f -exec chmod 0640 {} +
    fi
    : > /var/log/tsm-audit.log
    ;;
  authorize)
    user="$2"
    home=$(getent passwd "$user" | cut -d: -f6)
    install -d -o "$user" -g "$user" -m 0700 "$home/.ssh"
    key=$(cat)
    printf 'restrict %s\n' "$key" > "$home/.ssh/authorized_keys"
    chown "$user:$user" "$home/.ssh/authorized_keys"
    chmod 0600 "$home/.ssh/authorized_keys"
    ;;
  restore-host-keys)
    cp -p /etc/ssh/orig-host-keys/ssh_host_* /etc/ssh/
    pkill -HUP -x sshd || true
    ;;
  clear-agents)
    kill_dev_processes
    for u in $DEVS; do rm -rf "/home/$u/.mutagen"; done
    ;;
  *)
    echo "uso: tsm-setup reset|authorize USER|restore-host-keys|clear-agents" >&2
    exit 2
    ;;
esac
