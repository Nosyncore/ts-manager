import hashlib
import re


MAX_FILE_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 4096


class ManagerError(Exception):
    """Erro de operação que pode ser exibido pela CLI."""


def lua_path(value):
    if (
        not isinstance(value, str)
        or len(value) > 512
        or not value.endswith(".lua")
        or not all(re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*", part) for part in value.split("/"))
    ):
        raise ManagerError("Informe um caminho Lua relativo, com barras '/' e sem segmentos '.' ou '..'.")
    return value


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_limited(source):
    data = source.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ManagerError("O Lua excede o limite de 1 MiB do protótipo.")
    return data
