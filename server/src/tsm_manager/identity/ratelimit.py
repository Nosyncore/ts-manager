"""Rate limit em memória (token bucket) por IP.

Dois limites por IP: requisições por classe de rota (padrão ``auth``: 20 por minuto) e
falhas de cadastro ou verificação (5 por minuto). Com o bucket de falhas vazio, todas as
classes do IP são recusadas até ele voltar a ter uma ficha. Uma recusa não gasta fichas.

O estado é do processo: zera ao reiniciar e não vale entre processos (o Manager roda num
processo só). O número de IPs guardados é limitado; ao passar do limite, saem primeiro os buckets
cheios (inativos) e depois os mais antigos. A auditoria das recusas é de quem chama.
"""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass

FAILURES = "failures"
_EPSILON = 1e-9  # tolerância de ponto flutuante no reabastecimento


@dataclass(frozen=True)
class Rate:
    capacity: int
    per_seconds: float

    def __post_init__(self) -> None:
        if self.capacity <= 0 or self.per_seconds <= 0:
            raise ValueError("limite deve ser positivo")

    @property
    def refill_per_second(self) -> float:
        return self.capacity / self.per_seconds


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    retry_after: int = 0  # segundos inteiros, para o cabeçalho Retry-After


DEFAULT_CLASSES: Mapping[str, Rate] = {"auth": Rate(20, 60)}
DEFAULT_FAILURES = Rate(5, 60)


class _Bucket:
    __slots__ = ("tokens", "updated")

    def __init__(self, tokens: float, now: float) -> None:
        self.tokens = tokens
        self.updated = now

    def refill(self, rate: Rate, now: float) -> None:
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(rate.capacity, self.tokens + elapsed * rate.refill_per_second)
        self.updated = now

    def wait(self, rate: Rate) -> int:
        return max(1, math.ceil((1 - self.tokens) / rate.refill_per_second - _EPSILON))


class RateLimiter:
    def __init__(self, *, classes: Mapping[str, Rate] = DEFAULT_CLASSES,
                 failures: Rate = DEFAULT_FAILURES,
                 clock: Callable[[], float] = time.monotonic, max_keys: int = 10_000) -> None:
        if FAILURES in classes:
            raise ValueError(f"classe reservada: {FAILURES}")
        self._rates = {**classes, FAILURES: failures}
        self._clock = clock
        self._max_keys = max_keys
        self._ips: OrderedDict[str, dict[str, _Bucket]] = OrderedDict()
        self._lock = threading.Lock()

    def _bucket(self, ip: str, kind: str, now: float) -> _Bucket:
        entry = self._ips.get(ip)
        if entry is None:
            entry = self._ips[ip] = {}
            self._evict(now, keep=ip)
        else:
            self._ips.move_to_end(ip)
        rate = self._rates[kind]
        bucket = entry.get(kind)
        if bucket is None:
            bucket = entry[kind] = _Bucket(rate.capacity, now)
        else:
            bucket.refill(rate, now)
        return bucket

    def _idle(self, entry: dict[str, _Bucket], now: float) -> bool:
        for kind, bucket in entry.items():
            bucket.refill(self._rates[kind], now)
            if bucket.tokens < self._rates[kind].capacity:
                return False
        return True

    def _evict(self, now: float, keep: str) -> None:
        if len(self._ips) <= self._max_keys:
            return
        for ip in [ip for ip, entry in self._ips.items()
                   if ip != keep and self._idle(entry, now)]:
            del self._ips[ip]
            if len(self._ips) <= self._max_keys:
                return
        while len(self._ips) > self._max_keys:
            self._ips.popitem(last=False)

    def check(self, ip: str, route_class: str) -> Verdict:
        """Consome uma ficha da classe, se o IP não estiver bloqueado por falhas."""
        if route_class not in self._rates or route_class == FAILURES:
            raise ValueError(f"classe de rota desconhecida: {route_class!r}")
        with self._lock:
            now = self._clock()
            failures = self._bucket(ip, FAILURES, now)
            if failures.tokens < 1 - _EPSILON:
                return Verdict(False, failures.wait(self._rates[FAILURES]))
            bucket = self._bucket(ip, route_class, now)
            if bucket.tokens < 1 - _EPSILON:
                return Verdict(False, bucket.wait(self._rates[route_class]))
            bucket.tokens = max(0.0, bucket.tokens - 1)
            return Verdict(True)

    def record_failure(self, ip: str) -> None:
        with self._lock:
            bucket = self._bucket(ip, FAILURES, self._clock())
            bucket.tokens = max(0.0, bucket.tokens - 1)

    def size(self) -> int:
        """Número de IPs guardados."""
        with self._lock:
            return len(self._ips)
