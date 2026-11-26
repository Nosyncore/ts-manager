#!/bin/sh
# Remove tudo o que deploy/poc-ssh/provision.sh criou. Executar como root.
#   ssh <alias-admin> 'sudo sh -s' < deploy/poc-ssh/rollback.sh
# Idempotente: pode ser executado mais de uma vez.
set -eu

ROOT=/srv/ts-poc
SSHD_CONFIG=/etc/ssh/sshd_config
ALL_USERS="tsm-poc-dev-a tsm-poc-dev-b tsm-poc-manager"

[ "$(id -u)" -eq 0 ] || { echo "execute como root (sudo)" >&2; exit 1; }
command -v sshd >/dev/null 2>&1 || PATH="$PATH:/usr/sbin"

for u in $ALL_USERS; do
  if id "$u" >/dev/null 2>&1; then
    pkill -KILL -u "$u" 2>/dev/null || true
  fi
done
sleep 1
for u in $ALL_USERS; do
  if id "$u" >/dev/null 2>&1; then
    userdel -r "$u" 2>/dev/null || true
    if id "$u" >/dev/null 2>&1; then userdel "$u"; fi
  fi
done
for g in tsm-poc-readers tsm-poc-dev-a tsm-poc-dev-b tsm-poc-manager; do
  getent group "$g" >/dev/null 2>&1 && groupdel "$g"
done
rm -rf "$ROOT"

if grep -q '^# >>> tsm-poc ' "$SSHD_CONFIG"; then
  cp -p "$SSHD_CONFIG" "$SSHD_CONFIG.tsm-poc-rollback.bak"
  sed -i '/^# >>> tsm-poc /,/^# <<< tsm-poc /d' "$SSHD_CONFIG"
  # remove a linha em branco que o provision acrescentou antes do bloco
  sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$SSHD_CONFIG"
  if ! sshd -t; then
    cp -p "$SSHD_CONFIG.tsm-poc-rollback.bak" "$SSHD_CONFIG"
    echo "tsm-poc: sshd -t falhou após remover o bloco; arquivo restaurado" >&2
    exit 1
  fi
  rm -f "$SSHD_CONFIG.tsm-poc-rollback.bak"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
  else
    pkill -HUP -x sshd 2>/dev/null || true
  fi
fi
echo "tsm-poc: removido (contas, grupos, $ROOT e bloco do sshd_config)"
