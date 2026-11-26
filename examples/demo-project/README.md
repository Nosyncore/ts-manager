# Projeto fictício (demo)

Projeto Lua/texto usado nos testes e na demo do TS Manager. Não depende de OTServ,
banco de dados nem cliente do jogo.

- `ts-project.json`: identifica o projeto (`project_id`, `version`). Não concede acesso.
- `data/scripts/spells.lua` e `data/scripts/creatures.lua`: arquivos editados nos testes.

Os arquivos que devem ser ignorados pela sincronização (`.env`, `logs/`, `build/`,
`*.tmp`, `__pycache__/`, `.git/`) não são versionados aqui: os testes de integração e o
`scripts/poc_local_setup.py` os geram.
