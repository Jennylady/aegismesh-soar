"""Bounded, explicitly operator-initiated *real* EDR quarantine for WIN-LAB-01.

This is a separate lab exercise. It never claims an AI-driven incident,
never enables automatic production EDR isolation, and never targets the DC.
The existing Velociraptor Quarantine event monitor does the endpoint work.
"""
import datetime as dt
import json
import secrets

from ops import edr_velociraptor as edr

LAB_AGENT = '001'
LAB_CLIENT = 'C.3c9cde1e0b930676'
LAB_HOST = 'win-lab-01'
LAB_TTL_SECONDS = 180



def monitor_assigned_to_quarantine():
    """Require a *specific* monitoring assignment, not a text substring.

    Velociraptor stores label-scoped queries in `label_events` and general
    queries in `artifacts`. A monitor in an unrelated label group is inert.
    """
    rows = edr.api_query(edr.READ_MONITORING)
    if len(rows) != 1:
        return False
    config = rows[0].get('monitoring')
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except ValueError:
            return False
    if not isinstance(config, dict):
        return False

    name = 'Windows.Remediation.QuarantineMonitor'
    def assigned(group):
        if not isinstance(group, dict):
            return False
        specs = group.get('specs', [])
        return any(isinstance(spec, dict) and spec.get('artifact') == name
                   for spec in specs if isinstance(spec, dict))

    if assigned(config.get('artifacts')):
        return True
    labels = config.get('label_events', [])
    return isinstance(labels, list) and any(
        isinstance(item, dict) and
        str(item.get('label', '')).casefold() == 'quarantine' and
        assigned(item.get('artifacts'))
        for item in labels
    )


def _validate_target(agent):
    if agent != LAB_AGENT:
        raise PermissionError('Mode laboratoire limité à WIN-LAB-01 (agent 001), jamais au contrôleur AD 006')
    if not edr.CONF.is_file():
        raise RuntimeError('API Velociraptor mTLS non configurée')
    if not edr.timer_active():
        raise PermissionError('Timer automatique de retrait EDR inactif')
    cid = edr.linked(agent)
    if cid != LAB_CLIENT:
        raise PermissionError('Identifiant client EDR inattendu : intervention refusée')
    client = edr.valid_client(cid)
    if str(client.get('hostname', '')).lower().split('.')[0] != LAB_HOST:
        raise PermissionError('Identité Windows LAB différente de la cible autorisée')
    if 'windows' not in edr.client_os(client):
        raise PermissionError('La cible EDR n est pas Windows')
    wazuh = next((x for x in edr.wazuh_agents() if str(x.get('id', '')) == agent), None)
    if not wazuh or wazuh.get('status') != 'active':
        raise PermissionError('Agent Wazuh Windows LAB non actif')
    if not edr.identity_corresponds(agent, client, wazuh):
        raise PermissionError('Mapping Wazuh / Velociraptor non attesté')
    monitor = edr.quarantine_monitoring_status(agent)
    if not monitor['artifact_referenced_by_server_monitoring']:
        raise PermissionError('Windows.Remediation.QuarantineMonitor non présent dans le monitoring')
    if not monitor_assigned_to_quarantine():
        raise PermissionError('Le moniteur n est pas attribué au label Quarantine ni au groupe global')
    return cid


def start(agent, *, confirm=False, console_access=False):
    edr.require_root()
    if not (confirm and console_access):
        raise PermissionError('--confirm et --console-access requis (console de secours indépendante du réseau)')
    cid = _validate_target(agent)
    # Do not turn on global production isolation or forge an incident/score.
    with edr.lease_lock():
        leases = edr.read_json(edr.LEASES, {})
        if leases:
            raise PermissionError('Une quarantaine SOAR existe déjà : essai laboratoire refusé')
        if 'Quarantine' in edr.labels_for(cid):
            raise PermissionError('Label Quarantine préexistant : refus de gérer une isolation étrangère')
        now = dt.datetime.now(dt.timezone.utc)
        until = (now + dt.timedelta(seconds=LAB_TTL_SECONDS)).isoformat()
        lab_id = 'lab-' + secrets.token_hex(12)
        leases[agent] = {
            'client_id': cid, 'decision_id': lab_id, 'expires_at': until,
            'source': 'operator_lab_real', 'created_at': now.isoformat(),
        }
        edr.atomic_json(edr.LEASES, leases)
        try:
            edr.modify_label(cid, 'set')
        except Exception:
            try:
                edr.modify_label(cid, 'remove')
                leases.pop(agent, None)
                edr.atomic_json(edr.LEASES, leases)
            except Exception:
                # Preserve cleanup lease with an immediate expiry if label state is uncertain.
                leases[agent]['expires_at'] = dt.datetime.now(dt.timezone.utc).isoformat()
                edr.atomic_json(edr.LEASES, leases)
            raise
    return {
        'status': 'QUARANTINE_LABEL_SET_NETWORK_NOT_YET_VERIFIED',
        'source': 'operator_lab_real_not_ai',
        'lab_id': lab_id, 'agent_id': agent, 'client_id': cid,
        'label_verified': True, 'expires_at': until,
        'auto_release_timer_active': True,
        'production_isolation_configuration_changed': False,
        'endpoint_network_isolation_verified': False,
        'next': 'Tester LDAP 10.77.77.34:389 et la politique IPsec sur WIN-LAB-01',
    }


def status(agent):
    edr.require_root()
    if agent != LAB_AGENT:
        raise PermissionError('Lecture du test labo limitée à 001')
    record = edr.quarantine_monitoring_status(agent)
    record['endpoint_network_isolation_verified'] = False
    record['note'] = 'Seul un test de connectivité sur Windows prouve l isolement réseau'
    return record


def stop(agent, *, confirm=False):
    edr.require_root()
    if not confirm:
        raise PermissionError('--confirm requis')
    if agent != LAB_AGENT:
        raise PermissionError('Seul 001 peut être libéré via le mode laboratoire')
    lease = edr.read_json(edr.LEASES, {}).get(agent)
    if not lease or lease.get('source') != 'operator_lab_real':
        raise PermissionError('Aucun bail de laboratoire SOAR à retirer')
    result = edr.release(agent, expected_cid=LAB_CLIENT)
    result['network_restoration_verified'] = False
    result['next'] = 'Confirmer que LDAP 10.77.77.34:389 est redevenu accessible sur WIN-LAB-01'
    return result


def monitoring_logs(agent):
    edr.require_root()
    if agent != LAB_AGENT:
        raise PermissionError('Logs laboratoire limités à 001')
    cid = edr.linked(agent)
    if cid != LAB_CLIENT:
        raise PermissionError('Liaison EDR modifiée')
    # Read-only, client-specific, bounded log; no arbitrary network-supplied VQL.
    rows = edr.api_query(edr.READ_QUARANTINE_LOGS, {'ClientId': cid})
    return {'agent_id': agent, 'client_id': cid, 'monitoring_log': rows[-20:],
            'endpoint_network_isolation_verified': False}


def main(argv=None):
    import argparse
    p=argparse.ArgumentParser(description='AEGISMESH LAB / isolation réelle limitée à WIN-LAB-01')
    s=p.add_subparsers(dest='action',required=True)
    start_parser=s.add_parser('start');start_parser.add_argument('--agent-id',required=True)
    start_parser.add_argument('--confirm',action='store_true')
    start_parser.add_argument('--console-access',action='store_true')
    for cmd in ('status', 'logs'):
        sub=s.add_parser(cmd);sub.add_argument('--agent-id',required=True)
    release_parser=s.add_parser('release');release_parser.add_argument('--agent-id',required=True)
    release_parser.add_argument('--confirm',action='store_true')
    a=p.parse_args(argv)
    try:
        if a.action=='start': result=start(a.agent_id,confirm=a.confirm,console_access=a.console_access)
        elif a.action=='status': result=status(a.agent_id)
        elif a.action=='release': result=stop(a.agent_id,confirm=a.confirm)
        else: result=monitoring_logs(a.agent_id)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 0
    except (ValueError,RuntimeError,PermissionError,OSError) as exc:
        print('AEGISMESH LAB EDR : '+str(exc)[:250],file=__import__('sys').stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
