"""Rate limit em memória por IP e classe de rota, com relógio monotônico falso."""

from __future__ import annotations

import threading

import pytest

from tsm_manager.identity.ratelimit import Rate, RateLimiter, Verdict


class Monotonic:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock():
    return Monotonic()


@pytest.fixture
def limiter(clock):
    return RateLimiter(clock=clock)


def test_twenty_requests_per_minute_per_ip(limiter, clock):
    assert all(limiter.check("1.1.1.1", "auth").allowed for _ in range(20))
    verdict = limiter.check("1.1.1.1", "auth")
    assert verdict == Verdict(False, 3)          # 1 ficha a cada 3 s
    assert limiter.check("2.2.2.2", "auth").allowed  # outro IP não é afetado
    clock.t += 2.9
    assert limiter.check("1.1.1.1", "auth") == Verdict(False, 1)
    clock.t += 0.1
    assert limiter.check("1.1.1.1", "auth").allowed
    assert not limiter.check("1.1.1.1", "auth").allowed


def test_refill_caps_at_capacity(limiter, clock):
    for _ in range(20):
        limiter.check("1.1.1.1", "auth")
    clock.t += 3600
    assert sum(limiter.check("1.1.1.1", "auth").allowed for _ in range(30)) == 20


def test_five_failures_per_minute_block_the_ip(limiter, clock):
    for _ in range(5):
        assert limiter.check("1.1.1.1", "auth").allowed
        limiter.record_failure("1.1.1.1")
    verdict = limiter.check("1.1.1.1", "auth")
    assert verdict == Verdict(False, 12)          # 1 falha liberada a cada 12 s
    assert limiter.check("2.2.2.2", "auth").allowed
    clock.t += 12
    assert limiter.check("1.1.1.1", "auth").allowed


def test_refused_checks_do_not_consume(limiter, clock):
    for _ in range(5):
        limiter.record_failure("1.1.1.1")
    for _ in range(50):
        assert not limiter.check("1.1.1.1", "auth").allowed
    clock.t += 12
    assert limiter.check("1.1.1.1", "auth").allowed  # pedidos não foram gastos


def test_custom_classes_and_unknown_class(clock):
    limiter = RateLimiter(classes={"auth": Rate(2, 10), "admin": Rate(1, 60)},
                          failures=Rate(1, 60), clock=clock)
    assert limiter.check("ip", "admin").allowed
    assert limiter.check("ip", "admin") == Verdict(False, 60)
    assert limiter.check("ip", "auth").allowed   # classes independentes
    with pytest.raises(ValueError):
        limiter.check("ip", "outra")


def test_invalid_rates_refused():
    for bad in [(0, 60), (5, 0), (-1, 60)]:
        with pytest.raises(ValueError):
            Rate(*bad)


def test_memory_is_bounded_dropping_idle_buckets_first(clock):
    limiter = RateLimiter(clock=clock, max_keys=3)
    limiter.check("busy", "auth")              # gasta 1 ficha: não está cheio
    clock.t += 1
    limiter.check("idle-1", "auth")
    clock.t += 1
    limiter.check("idle-2", "auth")
    clock.t += 60                               # idle-1 e idle-2 voltam a encher; busy também
    limiter.check("novo", "auth")
    assert limiter.size() <= 3


def test_memory_is_bounded_dropping_the_oldest(clock):
    limiter = RateLimiter(clock=clock, max_keys=3)
    for ip in ("a", "b", "c", "d"):
        for _ in range(20):                    # todos esgotados: nenhum cheio
            limiter.check(ip, "auth")
    assert limiter.size() == 3
    assert limiter.check("a", "auth").allowed  # "a" foi descartado (o mais antigo)
    assert not limiter.check("d", "auth").allowed


def test_thread_safety(clock):
    limiter = RateLimiter(clock=clock)
    allowed = []

    def worker():
        allowed.extend(limiter.check("ip", "auth").allowed for _ in range(10))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(allowed) == 20
