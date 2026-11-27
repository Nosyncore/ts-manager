"""``git merge-file`` e ``git diff --no-index`` para o Client, com config isolada.

O merge de três vias do pull opera sobre bytes, sem conversão de fim de linha. A
config global e a do sistema do usuário são ignoradas, para que ``core.autocrlf`` ou
opções de diff pessoais não mudem o resultado.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

_GIT_FOR_WINDOWS = Path("C:/Program Files/Git/cmd/git.exe")


class GitUnavailable(RuntimeError):
    """Git não encontrado ou falha inesperada."""


@dataclass(frozen=True)
class MergeOutcome:
    conflicts: int
    content: bytes

    @property
    def clean(self) -> bool:
        return self.conflicts == 0


def find_git(configured: str | None = None) -> str:
    if configured:
        return configured
    found = shutil.which("git")
    if found:
        return found
    if _GIT_FOR_WINDOWS.is_file():
        return str(_GIT_FOR_WINDOWS)
    raise GitUnavailable("git não encontrado; instale o Git ou defina 'git' na config")


class ClientGit:
    def __init__(self, executable: str, global_config: Path) -> None:
        self.executable = executable
        self.global_config = global_config

    def _env(self) -> dict[str, str]:
        if not self.global_config.exists():
            self.global_config.parent.mkdir(parents=True, exist_ok=True)
            self.global_config.write_bytes(b"")
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(self.global_config),
                    "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
        return env

    def merge(self, ours: bytes, base: bytes, theirs: bytes, *,
              labels: tuple[str, str, str] = ("local", "base", "revisão")) -> MergeOutcome:
        with tempfile.TemporaryDirectory(prefix="tsm-merge-") as tmp:
            paths = []
            for name, data in (("ours", ours), ("base", base), ("theirs", theirs)):
                p = Path(tmp) / name
                p.write_bytes(data)
                paths.append(str(p))
            proc = subprocess.run(
                [self.executable, "-c", "core.autocrlf=false", "merge-file", "--stdout",
                 "-L", labels[0], "-L", labels[1], "-L", labels[2], *paths],
                capture_output=True, env=self._env(), check=False)
        if proc.returncode < 0 or proc.returncode > 127:
            raise GitUnavailable(f"git merge-file falhou: {proc.stderr.decode('utf-8', 'replace')}")
        return MergeOutcome(proc.returncode, proc.stdout)

    def diff(self, old: Path | None, new: Path | None, label: str) -> str:
        null = os.devnull
        args = [self.executable, "-c", "core.autocrlf=false", "-c", "core.quotepath=false",
                "diff", "--no-index", "--no-color", "--no-ext-diff",
                "--src-prefix=base/", "--dst-prefix=local/",
                str(old) if old else null, str(new) if new else null]
        proc = subprocess.run(args, capture_output=True, env=self._env(), check=False)
        if proc.returncode not in (0, 1):
            raise GitUnavailable(f"git diff falhou: {proc.stderr.decode('utf-8', 'replace')}")
        text = proc.stdout.decode("utf-8", "replace")
        if not text:
            return ""
        # troca os caminhos temporários pelo caminho do projeto, só no cabeçalho (antes do
        # primeiro "@@"): no corpo, "--- " pode ser uma linha de conteúdo removida
        lines = text.splitlines(keepends=True)
        out = [f"diff --tsm {label}\n"]
        in_header = True
        for line in lines[1:]:
            if line.startswith("@@"):
                in_header = False
            if in_header and line.startswith("--- "):
                line = "--- /dev/null\n" if old is None else f"--- base/{label}\n"
            elif in_header and line.startswith("+++ "):
                line = "+++ /dev/null\n" if new is None else f"+++ local/{label}\n"
            out.append(line)
        return "".join(out)
