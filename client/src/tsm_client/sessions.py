"""Vínculo de pasta → duas sessões Mutagen (upload e download) e suas invariantes.

- upload:   alpha = pasta local  → beta = workspace remoto individual
- download: alpha = shared       → beta = cache local
- ambas em ``one-way-replica`` (modo fixo por papel, não configurável).

Invariante geral (cobre todos os casos do design): o beta de uma sessão não pode ser
igual, ancestral ou descendente de nenhum endpoint de outra sessão, nem do alpha da
própria sessão. Daí decorre que a pasta local e o shared nunca são beta, que o cache
não se aninha com a pasta local e que dois vínculos nunca escrevem no mesmo destino.

Limitação: a sobreposição remota é avaliada por alias SSH. Dois aliases apontando para
o mesmo servidor não são identificados como iguais; a fronteira real é a permissão
UNIX no servidor (coberta pelos testes SSH).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from tsm_client.paths import Endpoint, endpoints_overlap
from tsm_client.rules import ProjectRules, sync_flags

MODE = "one-way-replica"

LABEL_MANAGED = "tsm-managed"
LABEL_BINDING = "tsm-binding"
LABEL_ROLE = "tsm-role"
LABEL_SPEC = "tsm-spec"
MANAGED_SELECTOR = f"{LABEL_MANAGED}=true"

# Permissões no beta POSIX remoto: o Manager precisa ler (pelo grupo do conteúdo).
REMOTE_BETA_MODES = ("--default-file-mode-beta=0640", "--default-directory-mode-beta=0750")
# O shared remoto é somente leitura para o dispositivo. Em filesystem que o Mutagen não
# reconhece, ele testa o comportamento criando um arquivo na raiz, o que falha. Com
# "assume", usa o comportamento padrão da plataforma (POSIX), correto para o Linux.
REMOTE_ALPHA_PROBE = ("--probe-mode-alpha=assume",)

_BINDING_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")


class SessionRuleError(ValueError):
    """Vínculo ou conjunto de sessões viola uma invariante."""


class Role(StrEnum):
    UPLOAD = "upload"
    DOWNLOAD = "download"


@dataclass(frozen=True)
class Binding:
    id: str
    project_id: str
    local: Endpoint
    cache: Endpoint
    workspace: Endpoint
    shared: Endpoint
    rules: ProjectRules
    # Grupo do conteúdo do workspace no servidor (``--default-group-beta``); só nos
    # vínculos vindos da /connection/config com workspace remoto.
    workspace_group: str | None = None

    def __post_init__(self) -> None:
        if not _BINDING_ID_RE.match(self.id):
            raise SessionRuleError(
                f"id de vínculo inválido {self.id!r}: use [a-z0-9-], até 48 caracteres"
            )
        if self.local.is_remote:
            raise SessionRuleError("a pasta local precisa ser um caminho local")
        if self.cache.is_remote:
            raise SessionRuleError("o cache precisa ser um caminho local")


@dataclass(frozen=True)
class SyncSpec:
    name: str
    binding_id: str
    role: Role
    alpha: Endpoint
    beta: Endpoint
    flags: tuple[str, ...]

    @property
    def mode(self) -> str:
        return MODE

    @property
    def spec_hash(self) -> str:
        payload = json.dumps(
            [self.role.value, MODE, self.alpha.url, self.beta.url, list(self.flags)],
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:12]

    @property
    def labels(self) -> dict[str, str]:
        return {
            LABEL_MANAGED: "true",
            LABEL_BINDING: self.binding_id,
            LABEL_ROLE: self.role.value,
            LABEL_SPEC: self.spec_hash,
        }


@dataclass(frozen=True)
class ExistingSession:
    """Sessão já presente no daemon (gerenciada ou alheia), para checagem de colisão."""

    name: str
    alpha: Endpoint
    beta: Endpoint


def session_name(binding_id: str, role: Role) -> str:
    return f"tsm-{binding_id}-{'up' if role is Role.UPLOAD else 'down'}"


def build_specs(binding: Binding) -> tuple[SyncSpec, SyncSpec]:
    up_flags = tuple(sync_flags(binding.rules, role=Role.UPLOAD.value)) + (
        REMOTE_BETA_MODES if binding.workspace.is_remote else ()
    )
    if binding.workspace.is_remote and binding.workspace_group:
        # o agente aplica o grupo a tudo que cria; o portão do workspace isola os
        # dispositivos entre si
        up_flags += (f"--default-group-beta={binding.workspace_group}",)
    down_flags = tuple(sync_flags(binding.rules, role=Role.DOWNLOAD.value)) + (
        REMOTE_ALPHA_PROBE if binding.shared.is_remote else ()
    )
    up = SyncSpec(
        name=session_name(binding.id, Role.UPLOAD),
        binding_id=binding.id,
        role=Role.UPLOAD,
        alpha=binding.local,
        beta=binding.workspace,
        flags=up_flags,
    )
    down = SyncSpec(
        name=session_name(binding.id, Role.DOWNLOAD),
        binding_id=binding.id,
        role=Role.DOWNLOAD,
        alpha=binding.shared,
        beta=binding.cache,
        flags=down_flags,
    )
    return up, down


def _describe(name: str, side: str, ep: Endpoint) -> str:
    return f"{name}.{side} ({ep.url})"


def validate_specs(
    specs: Sequence[SyncSpec], existing: Iterable[ExistingSession] = ()
) -> None:
    """Falha se algum beta colidir com outro endpoint (novas sessões e as existentes).

    ``existing`` deve conter apenas sessões que **não** correspondem às specs: o chamador
    exclui as sessões gerenciadas que serão reutilizadas (identificadas por labels, não
    pelo nome, que pode se repetir em sessões alheias).
    """
    names = [s.name for s in specs]
    dup = {n for n in names if names.count(n) > 1}
    if dup:
        raise SessionRuleError(f"nomes de sessão duplicados: {sorted(dup)}")

    sessions: list[ExistingSession] = [ExistingSession(s.name, s.alpha, s.beta) for s in specs]
    others = list(existing)

    for s in specs:
        if endpoints_overlap(s.alpha, s.beta):
            raise SessionRuleError(
                f"{s.name}: alpha e beta se sobrepõem ({s.alpha.url} × {s.beta.url})"
            )

    def check(a: ExistingSession, b: ExistingSession) -> None:
        # o beta de cada sessão não pode tocar nenhum endpoint da outra
        for writer, other in ((a, b), (b, a)):
            for side, ep in (("alpha", other.alpha), ("beta", other.beta)):
                if endpoints_overlap(writer.beta, ep):
                    hint = ""
                    if writer.beta == ep and side == "beta":
                        hint = " (destinos iguais: workspaces/caches não são compartilháveis)"
                    raise SessionRuleError(
                        f"sobreposição: {_describe(writer.name, 'beta', writer.beta)} × "
                        f"{_describe(other.name, side, ep)}{hint}"
                    )

    for i, a in enumerate(sessions):
        for b in sessions[i + 1 :]:
            check(a, b)
        for e in others:
            check(a, e)
