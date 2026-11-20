# TS Manager

Protótipo de publicação manual de um arquivo Lua por vez. O cliente roda no PC do desenvolvedor e usa Mutagen e SSH. O publicador roda sob demanda em Linux e usa SQLite, SHA-256 e snapshots em disco. Uma revisão-base desatualizada bloqueia a publicação e deixa o arquivo do desenvolvedor disponível para integração manual.

O piloto usa um diretório descartável como destino.

## Requisitos

- **PC** — Python 3.11+, Mutagen 0.18.1, `ssh` e `scp`. Configure `MUTAGEN_SSH_PATH` para o diretório do cliente SSH que autentica no alias escolhido. O piloto com `ts-dev` funcionou com o OpenSSH nativo do Windows. [Mutagen 0.18.1](https://github.com/mutagen-io/mutagen/releases/tag/v0.18.1) · [SSH no Mutagen](https://mutagen.io/documentation/transports/ssh/#windows)
- **Publicador Linux** — Python 3.11+ com `fcntl` e `sqlite3`, OpenSSH e `luac` compatível com o Lua que estiver sendo publicado. O piloto usa Lua 5.4. O código roda diretamente de `src` e também oferece o comando `ts` com `python -m pip install .`.

Para executar a partir do código-fonte, use `python -m ts_manager` com `PYTHONPATH` apontando para `src`. No PowerShell e no shell Linux, respectivamente.

```powershell
$env:PYTHONPATH = (Resolve-Path src).Path
$env:MUTAGEN_SSH_PATH = "$env:WINDIR\System32\OpenSSH"
python -m ts_manager --help
```

```sh
export PYTHONPATH="$PWD/src"
python3 -m ts_manager --help
```

## Preparar o piloto na VM

Copie o código para a VM e execute a partir da raiz que contém `src`. O exemplo usa `luac5.4` no `PATH` e imprime o caminho privado criado por `mktemp`.

```sh
set -eu
export PYTHONPATH="$PWD/src"
validator=$(command -v luac5.4)
umask 077
pilot=$(mktemp -d /tmp/ts-manager-pilot.XXXXXXXX)
mkdir "$pilot/target" "$pilot/state" "$pilot/staging" "$pilot/dev-a" "$pilot/dev-b"
printf 'return 10\n' > "$pilot/target/pilot.lua"
cp "$pilot/target/pilot.lua" "$pilot/dev-a/pilot.lua"
cp "$pilot/target/pilot.lua" "$pilot/dev-b/pilot.lua"
cat > "$pilot/publisher.toml" <<EOF
target = "target"
state = "state"
staging = "staging"
validator = "$validator"
allowed = ["pilot.lua"]

[workspaces]
dev-a = "dev-a"
dev-b = "dev-b"
EOF
python3 -m ts_manager server --config "$pilot/publisher.toml" init pilot.lua
printf '%s\n' "$pilot"
```

Os caminhos relativos do TOML têm como base o diretório da configuração. Estado, staging, destino e workspaces devem usar raízes independentes. O staging deve ficar no mesmo sistema de arquivos do destino. A conta de publicação precisa ler os workspaces e ser proprietária do arquivo no destino. A troca mantém as permissões Unix e o grupo do arquivo anterior. Arquivos Lua têm limite de 1 MiB e o armazenamento de snapshots tem limite de 32 MiB. Ao chegar ao limite, o publicador recusa a operação e mantém os snapshots existentes para recuperação.

## Configurar SSH e publicar

No piloto individual, use `ts-dev` para sincronização com o diretório temporário. Substitua `<PILOTO>` pelo caminho criado na VM e use um workspace local dedicado com o mesmo `pilot.lua` inicial. O comando também funciona para B, com a sua própria raiz e a sessão `ts-dev-b`.

```text
mutagen sync create --name=ts-dev-a --sync-mode=two-way-safe --symlink-mode=ignore --ignore-vcs --default-file-mode-beta=0640 --default-directory-mode-beta=0750 ./workspace-a ts-dev:<PILOTO>/dev-a
mutagen sync flush ts-dev-a
mutagen sync list --long ts-dev-a
```

Com contas separadas, use um grupo diferente por workspace e dê à conta publicadora acesso de leitura pelos dois grupos. Os modos da ponta remota no comando acima permitem que o publicador leia os arquivos e que cada desenvolvedor escreva no próprio workspace. Use esses mesmos modos ao copiar a revisão inicial, com o proprietário e o grupo de cada workspace.

Para a publicação, use uma chave de cada desenvolvedor com comando forçado na conta dedicada. O exemplo de entrada de `authorized_keys` fixa `dev-a` na VM. A configuração de SSH, os scripts do publicador, o estado e a lista de caminhos devem ficar sob controle da administração. As contas de sincronização escrevem no workspace correspondente e executam o agente do Mutagen em seu próprio ambiente. [Comando forçado no OpenSSH](https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT)

```text
restrict,command="/usr/bin/env PYTHONPATH=/opt/ts-manager/src /usr/bin/python3 -m ts_manager server --config /etc/ts-manager/publisher.toml serve --actor dev-a" ssh-ed25519 <CHAVE_PUBLICA_DE_PUBLICACAO>
```

Para ensaiar com a mesma conta que criou o diretório descartável, use um arquivo **local** de configuração SSH alternativo. Substitua `<PILOTO>` e `<CAMINHO_DO_REPOSITORIO_NA_VM>` por caminhos absolutos na VM. A entrada `Include` herda a configuração existente do alias `ts-dev`. Para simular B, use uma cópia do arquivo com `--actor dev-b`.

```sshconfig
Host ts-dev
    RemoteCommand /usr/bin/env PYTHONPATH=<CAMINHO_DO_REPOSITORIO_NA_VM>/src /usr/bin/python3 -m ts_manager server --config <PILOTO>/publisher.toml serve --actor dev-a

Host *
    Include ~/.ssh/config
```

Salve `pilot.lua` no VS Code e execute o fluxo abaixo. Se estiver executando a partir do código-fonte, use `python -m ts_manager` no lugar de `ts`. Na configuração com chave de publicação dedicada, use o alias dessa conta e omita `--ssh-config`.

```text
ts status pilot.lua --host ts-dev --ssh-config ssh-pilot.conf
ts publish pilot.lua --host ts-dev --ssh-config ssh-pilot.conf --session ts-dev-a --workspace ./workspace-a
```

`status` mostra a revisão publicada, a base do desenvolvedor e os hashes do workspace remoto e do destino. `publish` calcula o hash local e exige um ciclo Mutagen íntegro antes de solicitar a publicação. A VM só aplica os bytes que correspondem ao hash escolhido. A saída inclui o número da revisão aplicada. Uma segunda publicação do mesmo conteúdo e da mesma base retorna a revisão vigente com `changed: false`.

## Conflito e restauração

Se A publicar primeiro, B recebe um conflito de base e mantém a própria edição. No piloto, preserve uma cópia do Lua de B, integre a versão publicada no PC dele e peça ao administrador para confirmar a nova revisão-base. A adoção atualiza o metadado do desenvolvedor e deixa o conteúdo do workspace sob o controle dele.

```sh
python3 -m ts_manager server --config "$pilot/publisher.toml" adopt pilot.lua 2 --developer dev-b
```

Para restaurar o conteúdo anterior, informe a revisão que está publicada. O comando cria outra revisão e preserva as alterações nos dois workspaces. Retome a publicação após adotar a base resultante.

```sh
python3 -m ts_manager server --config "$pilot/publisher.toml" rollback pilot.lua 2
```

Depois de uma interrupção, a próxima operação confere o destino com os dois hashes registrados. Ela confirma a revisão nova se a troca ocorreu e encerra a tentativa se o destino ainda contém a versão anterior. Se encontrar um terceiro conteúdo, interrompe a publicação para investigação.

## Testes

No Linux com Lua instalado, rode a suíte a partir da raiz. `TS_TEST_LUAC` pode apontar para outro executável de teste. Os testes do cliente também rodam no Windows.

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

O primeiro piloto em `ts-dev` validou sincronização, publicação, conflito e restauração a partir do Windows. Um segundo ensaio na VM confirmou as permissões com duas contas Linux distintas e uma conta publicadora com chaves restritas. A implantação ainda precisa ser validada com as chaves dos dois PCs.
