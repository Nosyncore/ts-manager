"""Driver do domínio de identidade dentro do contêiner, com o verificador SSHSIG real.

Executado pela venv da imagem do Manager, como ``tsm-manager``::

    python sshsig_driver.py <banco>   (pedido JSON na entrada padrão, resposta na saída)

Cada execução é um processo novo; o estado fica no banco. As assinaturas são feitas fora
do contêiner, pelo teste; aqui só se emite desafio, verifica e registra.
"""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

from tsm_common.authmsg import NAMESPACE
from tsm_manager.adapters.sshsig import SshKeygenVerifier, default_executable, work_dir_for
from tsm_manager.db import Database, Repository, server_id, upgrade
from tsm_manager.identity import accounts, challenges, invites, sessions
from tsm_manager.identity.base import Actor, IdentityContext, IdentityError


def main() -> None:
    database = Path(sys.argv[1])
    request = json.load(sys.stdin)
    db = Database(database)
    try:
        if request["op"] == "setup":
            upgrade(db)
        verifier = SshKeygenVerifier(default_executable(), work_dir_for(database))
        ctx = IdentityContext(repo=Repository(db), server_id=server_id(db), verifier=verifier,
                              projects=frozenset({"demo"}))
        try:
            reply = handle(ctx, verifier, request)
        except IdentityError as exc:
            reply = {"error": exc.code}
    finally:
        db.close()
    json.dump(reply, sys.stdout)


def handle(ctx: IdentityContext, verifier: SshKeygenVerifier, req: dict) -> dict:
    op = req["op"]
    if op == "setup":
        invite = invites.create_bootstrap(ctx, Actor.operator(), project_id="demo")
        return {"invite": invite.code, "server_id": ctx.server_id}
    if op == "register_challenge":
        return challenges.issue_register(ctx, req["public_key"]).to_response()
    if op == "register":
        reg = accounts.register(ctx, invite_code=req["invite"], display_name="Admin",
                                device_name="pc-admin", challenge_id=req["challenge_id"],
                                signature=req["signature"])
        return {"device_id": reg.device_id, "fingerprint": reg.fingerprint,
                "status": reg.status}
    if op == "approve":
        ticket = accounts.begin_approval(ctx, Actor.operator(), req["device_id"],
                                         fingerprint=req["fingerprint"])
        accounts.complete_approval(ctx, req["device_id"], ticket.op_id)
        return {"ok": True}
    if op == "login_challenge":
        return challenges.issue_login(ctx, req["fingerprint"]).to_response()
    if op == "login":
        issued = sessions.login(ctx, req["challenge_id"], req["signature"])
        principal = sessions.authenticate(ctx, issued.token)
        return {"scope": issued.scope, "is_admin": principal.is_admin,
                "device_id": principal.device_id}
    if op == "verify":
        return {"results": [verifier.verify(c["public_key"], NAMESPACE,
                                            c["message_text"].encode("ascii"),
                                            c["signature"]) for c in req["cases"]]}
    if op == "self_check":
        verifier.self_check()
        return {"ok": True}
    if op == "work_dir":
        work = verifier.work_dir
        return {"entries": sorted(p.name for p in work.iterdir()),
                "mode": oct(stat.S_IMODE(work.stat().st_mode))}
    raise ValueError(f"operação desconhecida: {op}")


if __name__ == "__main__":
    main()
