"""PS.5: tira o endereço público do banco (PubliclyAccessible=false, aplicado na hora).

O banco continua acessível de dentro da VPC. Quem acessava pela internet passa a precisar
de VPN, bastion pelo Session Manager (ep. 7) ou de estar na VPC. A mudança leva alguns
minutos para aparecer: se o VERIFIED não vier, rode o scan de novo daqui a pouco.
"""


def run(clients, res, params, ctx, dry_run):
    if dry_run:
        return {"ok": True, "message": f"DRY_RUN: tiraria o acesso público de {res['name']}", "changes": []}
    clients["rds"].modify_db_instance(DBInstanceIdentifier=res["locator"], PubliclyAccessible=False, ApplyImmediately=True)
    return {"ok": True, "message": f"APPLIED: {res['name']} sem acesso público",
            "changes": [{"publiclyAccessible": {"before": True, "after": False}}]}
