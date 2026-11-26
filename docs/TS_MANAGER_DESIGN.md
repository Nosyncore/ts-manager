# TS Manager — Design do projeto

> **Status:** proposta inicial. Define intenção, limites e critérios de aceitação — não é uma especificação final de implementação.

## 1. Objetivo

Um sistema de colaboração para desenvolvedores de OTServ (Canary/TFS), no estilo "Dropbox para código": cada um trabalha em arquivos locais, as alterações sincronizam quase em tempo real e uma versão integrada é publicada em um único ambiente de testes compartilhado — sem commit ou push manual para um Git remoto.

- O TS Manager é independente do OTServ. A primeira versão será testada com um projeto fictício de arquivos Lua/texto.
- A integração com o jogo (hot reload, validação Lua, build C++) fica fora do MVP.

**Premissas:** dois desenvolvedores no início; PCs Windows (Linux como alvo secundário); uma VM Ubuntu ARM64 na Oracle Cloud (2 núcleos, 11 GB de RAM); no futuro, um único TS compartilhado, sem processos de jogo individuais.

## 2. Arquitetura e stack

| Componente | Função | Stack sugerida |
|---|---|---|
| **TS Client** | App desktop único para usuários e admins: identidade, dependências, pasta local, sessões de sync, publicação e importação de mudanças. | Python + PySide6; CLI reutilizável para desenvolvimento e automação (Typer, se útil). |
| **TS Manager Server** | API de autenticação, autorização, cadastro de dispositivos, configuração de projetos, integração de alterações e auditoria. | Python/FastAPI, SQLite, SQLAlchemy, Alembic; Git interno para revisões e merges. |
| **Transporte** | O Mutagen roda em cada PC, instala seu agente remoto via SSH e faz a sincronização diferencial. A API é o plano de controle, não o transporte dos arquivos. | Mutagen + OpenSSH. |
| **Deploy** | Serviço no servidor e binário desktop distribuível. | systemd, HTTPS via Caddy ou Nginx, SSH com usuários sem privilégios; PyInstaller em etapa posterior. |

Não criar painel web, microserviços, Redis nem infraestrutura paga adicional. A stack é uma sugestão e pode ser substituída quando houver justificativa.

Monorepo com componentes independentes e interfaces testáveis:

```text
ts-manager/
  client/        # núcleo, CLI e UI desktop
  server/        # API, identidade, workspaces, publicação, provisionamento
  common/        # contratos e modelos compartilhados, se necessário
  tests/         # unitários e integração
  examples/      # projeto fictício
  docs/          # design
  deploy/        # configuração Ubuntu/systemd/SSH
```

## 3. Modelo de sincronização

```text
PC Dev A --upload--> workspace A --+
                                   +--> TS Manager --> shared (Git interno)
PC Dev B --upload--> workspace B --+                        |
       cache A <--download---------------------------------+
       cache B <--download---------------------------------+
```

Cada PC tem sua pasta de trabalho e um cache local, gerenciado, da versão compartilhada. Cada vínculo usa duas sessões Mutagen:

1. **Upload:** pasta local autorizada → workspace remoto individual.
2. **Download:** shared remoto → cache local separado (nunca direto sobre a pasta em edição).

Regras:

- Usar `one-way-replica` só em destinos dedicados e descartáveis/reconstruíveis, pois ele pode apagar dados no destino.
- A sincronização acontece ao salvar; não há publicação automática.
- Só o Manager escreve no shared. Trazer mudanças do shared para a pasta de trabalho é uma ação explícita e segura do Client.
- Workspaces são diretórios, não servidores de jogo. Há um workspace por dispositivo/projeto, associado ao usuário, para que dois PCs nunca escrevam no mesmo espelho. No MVP basta um dispositivo ativo por usuário/projeto, mas o modelo deve suportar vários dispositivos sem escritores concorrentes na mesma pasta (local ou remota).

```text
/srv/ts/projects/<project_id>/
  workspaces/<device_id>/  # escrita apenas pelo respectivo dispositivo
  shared/                  # escrita exclusiva do Manager; leitura pelos devs
  history/                 # Git interno e snapshots; acesso restrito
```

**Não sincronizar:** `.git`, builds, logs, caches, segredos e configurações privadas. As regras (diretórios permitidos e exclusões) são centralizadas por projeto; quando possível, limitar as sessões aos diretórios permitidos.

**Segurança:** ignores não são fronteira de segurança. O servidor valida caminhos, tipos de arquivo, limites e permissões independentemente do cliente — bloqueando path traversal, symlinks/reparse points perigosos e escrita fora da raiz. O Manager nunca executa código recebido.

## 4. Experiência do usuário

### Primeiro acesso

1. O usuário abre o Client e informa o endereço HTTPS do Manager, seu nome e um convite temporário de uso único (que pode já vir na configuração de instalação).
2. O Client gera uma chave Ed25519 exclusiva do dispositivo, verifica/instala as dependências oficiais e envia a solicitação com a chave pública e prova de posse. Sem senha, e-mail ou comandos SSH manuais.
3. O admin aprova no próprio Client. O status é consultado automaticamente; solicitações pendentes não têm acesso aos arquivos.
4. Após a aprovação, o Client recebe uma configuração confiável (host/porta SSH, usuário técnico, identidade do servidor, projeto e regras), e o usuário seleciona e vincula a pasta local.
5. O Client valida o vínculo, mostra um resumo da sincronização inicial e conecta. Nas próximas aberturas, autentica e reconecta automaticamente (se habilitado).

### Vínculo da pasta

- Arquivo versionado `ts-project.json` na raiz (`project_id`, `version`). Ele identifica o projeto, mas não concede acesso.
- Verificar identificador, estrutura, caminho canônico, sobreposição com outros vínculos e autorização.
- A configuração por dispositivo fica fora do repositório.
- **Pasta com arquivos:** identificar a revisão base compatível e mostrar as diferenças. Nunca sobrescrever nem assumir que ela é igual ao shared. No primeiro teste, usar uma pasta nova inicializada a partir de uma revisão conhecida.
- **Pasta ausente, movida ou inesperadamente vazia:** bloquear e pedir revisão antes de publicar ou sincronizar de novo.
- **Troca de pasta:** encerrar/reconfigurar as sessões antigas e validar o novo vínculo.
- Exclusões em massa exigem confirmação; o shared nunca recebe exclusões automaticamente.

### Telas

- **Comum:** estado da conexão/sync, pasta vinculada, abrir no VS Code, alterações próprias e recebidas, diff, publicar arquivos selecionados ou todos, importar alterações, histórico, erros e desconectar.
  - Fechar o Client pode manter o Mutagen ativo, desde que isso fique claro para o usuário; desconectar pausa de fato as sessões gerenciadas.
  - É possível trabalhar offline; reconectar não publica nada automaticamente.
- **Admin:** tudo da tela comum, mais: criar convites, consultar/aprovar/rejeitar solicitações, listar usuários/dispositivos, bloquear usuário, revogar dispositivo, configurar projeto/regras e consultar a auditoria. Sem painel web separado.

## 5. Identidade e segurança

### Usuários e dispositivos

- **Usuário:** UUID, nome de exibição, role (`developer`/`admin`) e status.
- **Dispositivo:** UUID, `user_id`, chave pública única, fingerprint, status, nome e último acesso.
- Nomes não são credenciais nem identificadores de segurança. Um novo dispositivo de um usuário existente precisa de convite vinculado à conta e de aprovação — nunca vincular apenas pelo nome.

### Autenticação

- Sem senha. Challenge-response Ed25519 (biblioteca madura ou `ssh-keygen -Y` do OpenSSH, com namespace próprio):
  - o servidor emite um nonce aleatório, de uso único, com expiração curta e contexto de identidade/servidor/operação;
  - o Client assina localmente; o servidor verifica e emite uma sessão temporária.
- Prova de posse também no cadastro.
- A chave privada nunca é enviada, registrada em log ou sincronizada. Proteger o arquivo/chave com ACL ou armazenamento seguro do SO e documentar o risco de roubo do dispositivo.
- Validar TLS e fixar/verificar a chave de host SSH a partir de configuração confiável; nunca desabilitar a verificação.

### Autorização na API

- Toda operação sensível verifica role e status do usuário e do dispositivo; nunca confiar no que a UI informa.
- Convites de alta entropia, expiráveis, de uso único e com rate limiting.
- Tokens de sessão curtos e revogáveis. O status de uma solicitação pendente só é acessível com credencial/prova do próprio solicitante.

### Primeiro admin

- Criado por uma CLI administrativa local no servidor, com bootstrap único e convite especial, ou com aprovação/promoção explícita de um ID/fingerprint verificado pelo operador. Não editar o SQLite manualmente.
- No início, promoção de admins e recuperação ficam restritas à CLI da VM.
- Auditar as ações e impedir o bloqueio acidental do último admin.

### Contas SSH

- Contas sem sudo, de preferência uma por dispositivo, com permissões mínimas no filesystem: escrita só no workspace autorizado, leitura no shared.
- Bloquear forwarding/PTY quando compatível.
- O Mutagen precisa copiar e executar seu agente via SSH, então não aplicar `ForceCommand internal-sftp` indiscriminadamente.
- Sem isolamento adicional, o SSH permite executar comandos com a conta: não prometer acesso exclusivo a arquivos sem implementá-lo e testá-lo. Para produção, definir e testar o isolamento e os riscos das contas SSH; não expor credenciais da API ou de outros serviços.

### Provisionamento e revogação

- A API não roda como root. O provisionamento é feito por um helper restrito, com comandos/argumentos fixos e validados, sem shell arbitrário.
- Aprovação e revogação são idempotentes e auditadas; só marcar como aprovado após o provisionamento efetivo.
- Revogar um dispositivo remove a chave, as sessões/tokens da API e as conexões/processos SSH dele (incluindo agentes persistentes); testar que ele não reconecta. A revogação não apaga cópias locais já recebidas.

### Dependências

- **Mutagen:** versão fixa, fonte oficial e integridade verificada contra uma referência confiável; nunca executar download arbitrário.
- **OpenSSH:** usar o existente ou instruir a instalação/elevação explícita quando necessário.
- Configuração SSH dedicada e gerenciada pelo Client, sem sobrescrever aliases/chaves pessoais. Verificar a compatibilidade real Windows → Linux ARM64.

### Modelo de dados e rotas

**Entidades mínimas:** `users`, `devices`, `invites`, `auth_challenges`, `sessions`, `projects`, `project_memberships`, `workspace_bindings`, `revisions`/`publications`, `audit_logs`. O esquema evolui com as fases — não implementar tudo de uma vez.

**Rotas sugeridas** (os contratos finais são definidos na implementação):

- `POST /auth/register`, `/auth/challenge`, `/auth/verify`
- `GET /me`, `/connection/config`
- `/admin/invites`, `/admin/requests`, `/admin/devices/{id}/approve|revoke`, `/admin/users/{id}/block`
- `/projects/{id}/changes|revisions|publish`

Cadastro e administração passam por HTTPS antes de qualquer acesso SSH.

## 6. Publicação, merge e importação

Cada vínculo tem uma revisão base conhecida e preservada (ou uma base por arquivo, se houver publicação/importação parcial). Comparar apenas o workspace com o shared atual pode apagar mudanças de outro dev. O Git interno é a fonte das revisões; o `.git` dos devs nunca é sincronizado, e o Git local e seu índice são preservados.

### Publicação (manual)

1. Selecionar os arquivos e mostrar o diff contra a base (inclusive criações e exclusões).
2. Fazer flush da sessão Mutagen, verificar os hashes esperados e copiar os arquivos selecionados para um staging imutável. Validar o conjunto e falhar se houver alterações concorrentes durante a coleta — um flush sozinho não é snapshot de vários arquivos.
3. Com lock de publicação por projeto, comparar base, snapshot do dev e revisão mais recente do shared. Usar Git para merge de três vias em texto; conflito de conteúdo, binário divergente, delete/modify etc. bloqueiam a publicação inteira. No MVP, renomeações podem ser tratadas como add/delete; não tentar inferi-las sem testes.
4. Sem conflitos, registrar a revisão no Git interno e disponibilizar o conteúdo integrado de forma indivisível do ponto de vista do Manager (staging, troca controlada ou diário de recuperação). Uma revisão nunca aponta para arquivos parcialmente publicados. Expor revisão/hash para que caches em trânsito possam ser detectados como incompletos.
5. Registrar autor, dispositivo, base, resultado, caminhos e horário. Requisições repetidas são idempotentes; se não houver mudança, não cria revisão nova.

### Importação (`pull`)

- Ler uma revisão compartilhada imutável e verificada e integrá-la à pasta local por merge de três vias, preservando alterações ainda não publicadas.
- Mostrar prévia e bloquear conflitos sem perder dados.
- Atualizar a base somente após a aplicação bem-sucedida (inclusive arquivos/caminhos removidos). Publicar não significa que a pasta local recebeu a versão integrada, então a base não avança cegamente.
- No MVP: base única por vínculo e importação da revisão inteira; a base só avança após um pull concluído. A publicação seletiva parte dessa base e distingue mudanças já publicadas das pendentes.
- Recuperar operações interrompidas e evitar corrida entre edição local, importação e sync.
- Não implementar CRDT nem edição simultânea com cursores.

### Histórico e rollback

- Rollback gera uma nova revisão de restauração, sem reescrever o histórico; no MVP, exige autorização de admin.
- Nunca reverter automaticamente as alterações locais dos devs.
- Merge textual limpo não garante correção semântica; as validações do OTServ serão adicionadas depois.

## 7. Roadmap

Cada fase é entregue com testes e demonstração antes da próxima. Não criar componentes futuros só para preencher a estrutura.

Toda funcionalidade do Client é entregue e testada primeiro pelo terminal (CLI `tsm`), inclusive as operações de admin. As interfaces gráficas são a última fase e consomem o mesmo serviço já validado.

| Fase | Entrega | Critério de conclusão |
|---|---|---|
| 1 — Transporte/PoC | Núcleo mínimo do Client (CLI), adaptador Mutagen, fixture de arquivos, diretórios A/B/shared/cache; provisionamento SSH manual em ambiente de teste. | Dois diretórios locais simulam os devs; upload, download, pause/resume, reconexão, exclusões e ignores testados. Mutagen real rodando localmente e validação Windows → Ubuntu ARM64 via SSH quando o ambiente estiver disponível. A cópia manual/controlada para o shared serve só como demonstração. Nenhum OTServ. |
| 2 — Colaboração | Manager, Git interno, base/revisões, publicação seletiva, pull, conflitos e histórico. API local/ambiente isolado com identidade de teste. | Dois devs alteram arquivos distintos e o mesmo arquivo; merge sem conflito funciona, conflito é bloqueado, rollback funciona e falhas de sync/publicação não perdem dados. Testar offline e concorrência. |
| 3 — Identidade/acessos | SQLite/migrations, convites, challenge-response, sessões, roles, bootstrap do admin, aprovação/revogação, provisionamento e configuração SSH. | Usuário pendente não acessa; admin aprova pelo `tsm` e o novo dispositivo conecta; revogação interrompe e impede o acesso; replay, acesso cruzado e operação sem role são rejeitados. |
| 4 — Deploy/hardening | Instalação do Client de terminal no Windows, systemd, TLS, isolamento SSH, backup/recuperação, documentação e teste ponta a ponta na VM. | Dois PCs reais + VM, operados pelo `tsm`; instalação reproduzível, permissões e revogação verificadas, recuperação de backup testada, logs e erros úteis. Só expor o serviço depois de validar os controles de segurança. |
| 5 — Client desktop (interfaces) | PySide6 sobre o núcleo e o serviço já validados pelo terminal: onboarding, gerenciamento de dependências, seleção/validação da pasta, conexão, publish/pull e seção admin; pacote Windows final com a interface. | Um novo dev instala/abre, informa nome e convite, é aprovado pelo Client do admin, escolhe a pasta e colabora sem comandos nem senha. |
| Futuro — OTServ | Adaptador separado para aplicar revisões aprovadas, validar Lua, hot reload e, se necessário, build/restart controlado. | Fora do MVP; planejar separadamente quando a colaboração estiver estável. |

**Projeto fictício:** `examples/demo-project/` com `ts-project.json`, `data/scripts/spells.lua`, `data/scripts/creatures.lua`, README e arquivos ignorados de teste. Usar duas alterações em linhas não adjacentes para o caso de merge limpo e a mesma linha para o caso de conflito. Não são necessários banco MariaDB, cliente Tibia nem executável Canary.

## 8. Regras de desenvolvimento

- Priorizar simplicidade, testes com pytest e contratos claros.
- Separar os adaptadores (subprocesso, filesystem, Git, provisionamento) da lógica de domínio.
- Usar mocks nos testes unitários e Mutagen/Git/SSH reais nos testes de integração relevantes. Não confundir teste simulado com teste remoto real.
- Não executar comandos destrutivos nem alterar a VM real sem autorização.
- Registrar riscos, decisões de design e pendências.
- Sem publicação automática no MVP. Notificações em tempo real, WebSocket, extensão do VS Code, múltiplos projetos ativos e integração com o jogo ficam para incrementos posteriores.
- Não exigir Git remoto no uso cotidiano.

## 9. Referências para validar antes de implementar

- Mutagen — sincronização: https://mutagen.io/documentation/synchronization/
- Mutagen — SSH: https://mutagen.io/documentation/transports/ssh/
- Mutagen — sessões/flush: https://mutagen.io/documentation/introduction/getting-started/
- Mutagen — controle de versão: https://mutagen.io/documentation/synchronization/version-control-systems/
- OpenSSH — assinatura de mensagens: https://man.openbsd.net/ssh-keygen.1
- Git merge-file: https://git-scm.com/docs/git-merge-file
