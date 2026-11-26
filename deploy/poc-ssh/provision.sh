#!/bin/sh
# Provisiona as contas de teste da PoC do TS Manager. Executar como root.
#
# Não use diretamente: gere o script final com
#   python scripts/poc_remote_prepare.py
# que define PUBKEY_A, PUBKEY_B e DEMO_TGZ_B64 no topo e grava .poc/remote-provision.sh.
# Revise o arquivo gerado e execute:
#   ssh <alias-admin> 'sudo sh -s' < .poc/remote-provision.sh
#
# O que faz (tudo com prefixo tsm-poc e em /srv/ts-poc):
#   - cria grupos/contas tsm-poc-dev-a, tsm-poc-dev-b (login só por chave) e tsm-poc-manager
#     (sem login), e o grupo tsm-poc-readers;
#   - cria /srv/ts-poc/projects/demo/{workspaces/dev-a,dev-b,shared,history} com as
#     permissões por grupo e semeia o shared com o projeto fictício;
#   - instala as chaves públicas com "restrict";
#   - acrescenta ao fim do sshd_config um bloco "Match User" delimitado por marcadores,
#     valida com "sshd -t" e recarrega o serviço ssh já existente (porta e firewall intactos).
# Desfazer: deploy/poc-ssh/rollback.sh
set -eu

: "${PUBKEY_A:?defina PUBKEY_A}" "${PUBKEY_B:?defina PUBKEY_B}" "${DEMO_TGZ_B64:?defina DEMO_TGZ_B64}"

ROOT=/srv/ts-poc
PROJECT="$ROOT/projects/demo"
SSHD_CONFIG=/etc/ssh/sshd_config
BEGIN_MARK='# >>> tsm-poc (TS Manager) >>>'
END_MARK='# <<< tsm-poc (TS Manager) <<<'
DEVS="tsm-poc-dev-a tsm-poc-dev-b"
ALL_USERS="$DEVS tsm-poc-manager"

die() { echo "tsm-poc: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "execute como root (sudo)"
command -v sshd >/dev/null 2>&1 || PATH="$PATH:/usr/sbin"

# ---------------------------------------------------------------- pré-checagens
grep -qF "$BEGIN_MARK" "$SSHD_CONFIG" && die "bloco tsm-poc já existe; rode o rollback antes"
[ -e "$ROOT" ] && die "$ROOT já existe; rode o rollback antes"
for u in $ALL_USERS; do
  id "$u" >/dev/null 2>&1 && die "usuário $u já existe; rode o rollback antes"
done
getent group tsm-poc-readers >/dev/null 2>&1 && die "grupo tsm-poc-readers já existe"
if sshd -T -C user=tsm-poc-dev-a,host=localhost,addr=127.0.0.1 2>/dev/null \
    | grep -qiE '^(allowusers|allowgroups) '; then
  die "AllowUsers/AllowGroups ativos no sshd: inclua as contas tsm-poc manualmente e repita"
fi
sshd -t || die "a configuração atual do sshd já é inválida; nada foi alterado"

# ---------------------------------------------------------------- contas
groupadd tsm-poc-readers
for u in $DEVS; do
  useradd -m -s /bin/sh "$u"
  usermod -p '*' "$u"           # sem senha, mas não bloqueada (login só por chave)
  usermod -aG tsm-poc-readers "$u"
done
useradd -M -d /nonexistent -s /usr/sbin/nologin tsm-poc-manager
usermod -aG tsm-poc-dev-a,tsm-poc-dev-b tsm-poc-manager

# ---------------------------------------------------------------- diretórios
install -d -o root -g root -m 0755 "$ROOT" "$ROOT/projects" "$PROJECT"
install -d -o root -g root -m 0711 "$PROJECT/workspaces"
install -d -o tsm-poc-dev-a -g tsm-poc-dev-a -m 2750 "$PROJECT/workspaces/dev-a"
install -d -o tsm-poc-dev-b -g tsm-poc-dev-b -m 2750 "$PROJECT/workspaces/dev-b"
install -d -o tsm-poc-manager -g tsm-poc-readers -m 2750 "$PROJECT/shared"
install -d -o tsm-poc-manager -g tsm-poc-manager -m 0700 "$PROJECT/history"
printf '%s' "$DEMO_TGZ_B64" | base64 -d | tar -xzf - -C "$PROJECT/shared" --no-same-owner
chown -R tsm-poc-manager:tsm-poc-readers "$PROJECT/shared"
find "$PROJECT/shared" -type d -exec chmod 2750 {} +
find "$PROJECT/shared" -type f -exec chmod 0640 {} +

# ---------------------------------------------------------------- chaves
install_key() {
  user="$1"; key="$2"
  home=$(getent passwd "$user" | cut -d: -f6)
  install -d -o "$user" -g "$user" -m 0700 "$home/.ssh"
  printf 'restrict %s\n' "$key" > "$home/.ssh/authorized_keys"
  chown "$user:$user" "$home/.ssh/authorized_keys"
  chmod 0600 "$home/.ssh/authorized_keys"
}
install_key tsm-poc-dev-a "$PUBKEY_A"
install_key tsm-poc-dev-b "$PUBKEY_B"

# ---------------------------------------------------------------- sshd
cp -p "$SSHD_CONFIG" "$SSHD_CONFIG.tsm-poc.bak"
cat >> "$SSHD_CONFIG" <<EOF

$BEGIN_MARK
Match User tsm-poc-dev-a,tsm-poc-dev-b
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    AllowAgentForwarding no
    PermitTunnel no
    PermitTTY no
$END_MARK
EOF
if ! sshd -t; then
  cp -p "$SSHD_CONFIG.tsm-poc.bak" "$SSHD_CONFIG"
  die "sshd -t falhou com o bloco tsm-poc; sshd_config restaurado (contas e diretórios mantidos: rode o rollback)"
fi
rm -f "$SSHD_CONFIG.tsm-poc.bak"

reload_sshd() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload ssh 2>/dev/null && return 0
    systemctl reload sshd 2>/dev/null && return 0
    # Ubuntu com ativação por socket: cada conexão lê a config de novo
    systemctl is-active --quiet ssh.socket && return 0
  fi
  pkill -HUP -x sshd 2>/dev/null && return 0
  echo "tsm-poc: aviso: recarregue o sshd manualmente" >&2
}
reload_sshd

echo "tsm-poc: provisionado em $ROOT (contas: $ALL_USERS)"
