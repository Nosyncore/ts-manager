# Validação do transporte na VM ARM64 (contas de teste)

Procedimento **manual**, executado pelo operador da VM e **somente com autorização
explícita**. Cria contas e diretórios de teste isolados (prefixo `tsm-poc`, raiz
`/srv/ts-poc`), roda os testes de validação e desfaz tudo ao final.

O procedimento foi ensaiado num contêiner `ubuntu:24.04` `linux/arm64` com sshd padrão
(`tests/integration_ssh/test_vm_procedure.py`): provisionamento, testes de validação e rollback. O
ensaio não substitui a execução na VM.

## O que muda na VM

| Item | Detalhe |
|---|---|
| Contas | `tsm-poc-dev-a`, `tsm-poc-dev-b` (login só por chave, shell `/bin/sh`, sem sudo); `tsm-poc-manager` (sem login) |
| Grupos | `tsm-poc-readers` (devs); `tsm-poc-manager` entra nos grupos `tsm-poc-dev-a` e `tsm-poc-dev-b` |
| Diretórios | `/srv/ts-poc/projects/demo/{workspaces/dev-a,workspaces/dev-b,shared,history}` |
| Chaves | `authorized_keys` com `restrict`, só as chaves públicas geradas localmente |
| sshd | bloco `Match User tsm-poc-dev-a,tsm-poc-dev-b` no **fim** do `/etc/ssh/sshd_config`, entre marcadores `# >>> tsm-poc` / `# <<< tsm-poc`; validado com `sshd -t` antes do reload |
| Não muda | porta do sshd, firewall, outras contas, pacotes, serviços |

Permissões:

| Caminho | Dono:grupo | Modo |
|---|---|---|
| `/srv/ts-poc/projects/demo/workspaces/` | `root:root` | `0711` |
| `…/workspaces/dev-a/` | `tsm-poc-dev-a:tsm-poc-dev-a` | `2750` |
| `…/workspaces/dev-b/` | `tsm-poc-dev-b:tsm-poc-dev-b` | `2750` |
| `…/shared/` | `tsm-poc-manager:tsm-poc-readers` | `2750` (arquivos `0640`) |
| `…/history/` | `tsm-poc-manager:tsm-poc-manager` | `0700` |

Os agentes do Mutagen são instalados pelo próprio Mutagen em `~/.mutagen` de cada conta
de teste (scp/SFTP + `chmod +x` + `install`).

## Pré-requisitos

- Acesso administrativo do operador pelo alias pessoal (ex.: `ts-dev`), com a chave de
  host já no `known_hosts` pessoal. Em caso de dúvida, confira o fingerprint pelo console
  do provedor.
- No PC: Mutagen fixado (`python scripts/fetch_mutagen.py`) e OpenSSH do Git for Windows.
- Os comandos com `<` abaixo rodam no **Git Bash** (o PowerShell 5.1 não aceita `<`, e
  pipes do PowerShell podem converter fim de linha para CRLF, o que quebra o `sh`).

## 1. Gerar chaves de teste e o script

```bash
.venv/Scripts/python scripts/poc_remote_prepare.py
# -> .poc/remote-keys/id_ed25519_tsm_poc_dev_a(.pub), ..._dev_b(.pub)
# -> .poc/remote-provision.sh  (deploy/poc-ssh/provision.sh + chaves públicas + projeto fictício)
```

Revise `.poc/remote-provision.sh`. Ele contém apenas chaves **públicas**. `.poc/` é
ignorado pelo Git.

## 2. Provisionar (com autorização)

```bash
ssh ts-dev 'sudo sh -s' < .poc/remote-provision.sh
```

O script aborta sem alterar nada se: já houver algo `tsm-poc`; `/srv/ts-poc` existir; o
sshd tiver `AllowUsers`/`AllowGroups` (nesse caso, inclua as contas manualmente e
repita); ou `sshd -t` já falhar antes da mudança. Se `sshd -t` falhar depois do bloco, o
`sshd_config` é restaurado.

## 3. Rodar os testes de validação

```powershell
$env:TSM_REMOTE_ALIAS='ts-dev'; $env:TSM_REMOTE_ROOT='/srv/ts-poc'; $env:TSM_REMOTE_KEYS='.poc\remote-keys'
.venv\Scripts\python -m pytest -m remote tests\remote -rs -s
```

Os testes usam `ssh -G ts-dev` só para **ler** HostName/Port, e `ssh-keygen -F` para
copiar a chave de host já confiada para um `known_hosts` gerenciado. Eles conectam com as
contas `tsm-poc-dev-*` e chaves próprias, nunca com o alias ou a chave do operador. Nada é
gravado no `~/.ssh` pessoal.

| Teste | Verifica |
|---|---|
| `test_two_devices_four_sessions_real_arm64` | 2 dispositivos, 4 sessões, agente linux/arm64 real; edição, exclusão, ignores, 20× flush |
| `test_server_permissions_are_the_boundary` | sessão Mutagen "crua" da conta dev-a não altera o shared nem o workspace de dev-b; dev-a não lista `workspaces/`; modos `0750`/`0640` e Manager nos grupos dos devs |
| `test_reconnect_after_own_agents_are_killed` | a conta de teste mata os próprios agentes; reconexão automática; edição feita no intervalo propaga |
| `test_agent_resource_usage` | CPU e RSS dos `mutagen-agent` em repouso e com carga (300 arquivos), 4 sessões |

Queda da rede local é teste manual opcional: desconectar o Wi-Fi/cabo com as sessões
ativas, editar um arquivo, reconectar e conferir `tsm status` e o workspace.

## 4. Rollback

```bash
ssh ts-dev 'sudo sh -s' < deploy/poc-ssh/rollback.sh
```

Encerra os processos das contas `tsm-poc-*`, remove contas, grupos, `/srv/ts-poc` e o
bloco do `sshd_config` (com `sshd -t` antes do reload). É idempotente. Depois, apague
`.poc/remote-keys/` no PC, se quiser.

Se algo permanecer na VM de propósito, documente o que ficou e por quê.
