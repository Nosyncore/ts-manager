"""ProxyCommand contador do teste de tráfego: repassa a conexão SSH e conta os bytes.

Uso (só na config SSH gerenciada do teste):
    ProxyCommand <python> count_proxy.py %h %p <arquivo.json>

Grava ``{"sent": N, "received": M}`` (bytes do cliente para o servidor e de volta) a cada
0,2 s e ao terminar. Só stdlib.
"""

import json
import os
import socket
import sys
import threading
import time

host, port, out_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
sock = socket.create_connection((host, port))
counts = {"sent": 0, "received": 0}
done = threading.Event()


def dump() -> None:
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(counts, fh)
    os.replace(tmp, out_path)


def upstream() -> None:
    src = sys.stdin.buffer.raw
    try:
        while chunk := src.read(65536):
            sock.sendall(chunk)
            counts["sent"] += len(chunk)
    except OSError:
        pass
    finally:
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def downstream() -> None:
    dst = sys.stdout.buffer.raw
    try:
        while chunk := sock.recv(65536):
            view = memoryview(chunk)
            while view:
                n = dst.write(view)
                view = view[n:]
            counts["received"] += len(chunk)
    except OSError:
        pass
    finally:
        done.set()


def writer() -> None:
    while not done.wait(0.2):
        dump()


threading.Thread(target=upstream, daemon=True).start()
threading.Thread(target=writer, daemon=True).start()
downstream()
dump()
time.sleep(0.1)
