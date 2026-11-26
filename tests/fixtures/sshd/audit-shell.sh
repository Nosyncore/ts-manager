#!/bin/sh
# Shell de login de teste: registra cada comando executado via SSH (base para restringir
# os comandos permitidos) e executa normalmente. NÃO é controle de segurança.
if [ "$1" = "-c" ]; then
  printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(id -un)" "$2" >> /var/log/tsm-audit.log
  exec /bin/sh -c "$2"
fi
printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(id -un)" "<sessão interativa recusada>" >> /var/log/tsm-audit.log
exit 1
