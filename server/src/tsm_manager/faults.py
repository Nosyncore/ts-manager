"""Falhas injetadas para os testes de recuperação.

Só têm efeito com ``test_faults: true`` na config do Manager. No processo de teste,
``Faults`` é passado diretamente; num Manager iniciado pelos testes, vem da variável
``TSM_MANAGER_FAULTS`` (JSON), por exemplo ``{"crash": "before_update_ref"}`` ou
``{"delay_per_file": 0.5}``.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

POINTS = ("before_update_ref", "during_materialize", "before_record", "after_stage")


class SimulatedCrash(RuntimeError):
    """Interrupção simulada (no processo de teste)."""


@dataclass
class Faults:
    crash: str | None = None
    delay_per_file: float = 0.0
    hard_exit: bool = False  # True: os._exit (processo do Manager); False: exceção
    hits: dict[str, int] = field(default_factory=dict)

    def hit(self, point: str) -> None:
        self.hits[point] = self.hits.get(point, 0) + 1
        if self.crash == point:
            if self.hard_exit:
                os._exit(70)
            raise SimulatedCrash(point)

    def per_file(self) -> None:
        if self.delay_per_file:
            time.sleep(self.delay_per_file)

    @classmethod
    def from_env(cls, enabled: bool) -> Faults:
        raw = os.environ.get("TSM_MANAGER_FAULTS")
        if not enabled or not raw:
            return cls()
        data = json.loads(raw)
        return cls(crash=data.get("crash"), delay_per_file=float(data.get("delay_per_file", 0)),
                   hard_exit=True)
