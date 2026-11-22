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



def _read_monitoring_assignments():
    """Exact-match configured CLIENT_EVENT artifact assignments, no substring guesses.

    The API returns an Artifacts proto with `specs`; releases may also expose
    its `artifacts` list. Never interpret an artifact under an unrelated label
    as a Quarantine monitor.
    """
    rows = edr.api_query(edr.READ_MONITORING)
    if len(rows) != 1:
        raise RuntimeError('Etat client monitoring absent ou ambigu')
    config = rows[0].get('monitoring')
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except ValueError:
            raise RuntimeError('Réponse monitoring non JSON') from None
    if not isinstance(config, dict):
        raise RuntimeError('Réponse monitoring invalide')
    name = 'Windows.Remediation.QuarantineMonitor'

    def assigned(group):
        if not isinstance(group, dict):
            return False
        specs = group.get('specs') or []
        if not isinstance(specs, list):
            raise RuntimeError('Format specs du monitoring inconnu')
        if any(isinstance(x, dict) and x.get('artifact') == name for x in specs):
            return True
        artifacts = group.get('artifacts') or []
        if not isinstance(artifacts, list):
            raise RuntimeError('Format artifacts du monitoring inconnu')
        return name in artifacts

    global_assigned = assigned(config.get('artifacts'))
    label_events = config.get('label_events') or []
    if not isinstance(label_events, list):
        raise RuntimeError('Format label_events du monitoring inconnu')
    labels = sorted({str(item.get('label', '')) for item in label_events
                     if isinstance(item, dict) and assigned(item.get('artifacts'))})
    return {'global': global_assigned, 'labels': labels,
            'quarantine': global_assigned or any(x.casefold() == 'quarantine' for x in labels)}


def monitor_assigned_to_quarantine():
    return _read_monitoring_assignments()['quarantine']


def monitor_status(agent):
    edr.require_root()
    cid = _validate_target(agent, require_monitor=False)
    assignments = _read_monitoring_assignments()
    return {'agent_id': agent, 'client_id': cid,
            'monitor': 'Windows.Remediation.QuarantineMonitor',
            'assignment': assignments,
            'ready_for_lab_quarantine': assignments['quarantine'],
            'label_present': 'Quarantine' in edr.labels_for(cid),
            'network_effect_verified': False,
            'note': 'Affectation du moniteur ne prouve pas l application IPsec'}


def ensure_monitor(agent, *, confirm=False):
    """Narrow, idempotent monitoring setup via Velociraptor's mTLS server API.

    Only the `Quarantine` group is modified, and only if it is not already
    properly monitored. No client is quarantined by this operation.
    """
    edr.require_root()
    if not confirm:
        raise PermissionError('--confirm requis pour modifier le monitoring EDR')
    cid = _validate_target(agent, require_monitor=False)
    before = _read_monitoring_assignments()
    if before['quarantine']:
        return {'status':'already_configured', 'changed':False, 'assignment':before,
                'agent_id': agent,'client_id':cid, 'network_effect_verified':False}
    if edr.read_json(edr.LEASES, {}):
        raise PermissionError('Baux de quarantaine déjà actifs : configuration refusée')
    clients = edr.api_clients()
    if any('Quarantine' in (client.get('labels') or []) for client in clients):
        raise PermissionError('Un client est déjà en quarantaine : pas de modification du monitoring pendant un isolement')
    if 'Quarantine' in edr.labels_for(cid):
        raise PermissionError('Quarantaine existante sur WIN-LAB-01')
    # This call requires COLLECT_CLIENT. Never change API credentials or roles.
    edr.api_query(edr.ADD_QUARANTINE_MONITOR)
    after = _read_monitoring_assignments()
    if not after['quarantine']:
        raise RuntimeError('Modification API non confirmée dans le monitoring : aucune isolation demandée')
    return {'status':'monitor_configured', 'changed':True,
            'agent_id':agent, 'client_id':cid, 'assignment':after,
            'label_present': False, 'network_effect_verified':False,
            'next': 'edr lab-quarantine start --agent-id 001 --confirm --console-access'}


def _validate_target(agent, *, require_monitor=True):
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
    if require_monitor:
        monitor = edr.quarantine_monitoring_status(agent)
        if not monitor['artifact_referenced_by_server_monitoring']:
            raise PermissionError('Windows.Remediation.QuarantineMonitor absent du monitoring Velociraptor')
        if not monitor_assigned_to_quarantine():
            raise PermissionError('Moniteur non attribué au groupe Quarantine : lancer lab-quarantine monitor-ensure --agent-id 001 --confirm')
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


def monitor_results(agent):
    """Read actual Windows.Quarantine output, NOT the log("Setting...") messages.

    The result stream is produced by the remote Windows event artifact, and
    reports each netsh command plus the Velociraptor frontend reachability
    check.  It is still *not* a measured network-isolation proof.
    """
    edr.require_root()
    if agent != LAB_AGENT:
        raise PermissionError('Résultats laboratoire limités à WIN-LAB-01 (001)')
    cid = edr.linked(agent)
    if cid != LAB_CLIENT:
        raise PermissionError('Correspondance Wazuh/Velociraptor modifiée')
    rows = edr.api_query(edr.READ_QUARANTINE_RESULTS, {'ClientId': cid})
    if not isinstance(rows, list):
        raise RuntimeError('Résultats EDR inattendus')
    # Preserve original result rows for forensic traceability.  Detect common
    # error patterns only as *hints*, never as endpoint packet-filtering proof.
    messages = [str(row.get('Result','')) for row in rows if isinstance(row, dict)]
    lowered = '\n'.join(messages).casefold()
    failed_test = 'failed connection test' in lowered
    applied = 'ipsec policy applied' in lowered
    removed = 'ipsec policy removed' in lowered
    # Netsh stderr can be localized: expose raw bounded rows, no false positive.
    if failed_test:
        note = 'Le client a échoué au test Velociraptor frontend et retire la politique : examiner URL/port et certificats EDR, sans désactiver les protections.'
    elif not rows:
        note = 'Aucun résultat de l artefact reçu : vérifier l acheminement monitoring et ses journaux ; ne pas conclure à une isolation.'
    elif applied and removed:
        note = 'La politique a été appliquée puis retirée dans la fenêtre consultée ; corréler les horodatages et les essais LDAP.'
    elif applied:
        note = 'Velociraptor rapporte avoir appliqué la politique ; confirmer l effet réel depuis WIN-LAB-01 et vérifier les éventuelles exceptions.'
    else:
        note = 'Résultats disponibles sans preuve d application : lire les messages netsh et la configuration IPsec/GPO.'
    return {
        'agent_id': agent, 'client_id': cid,
        'artifact': 'Windows.Remediation.QuarantineMonitor',
        'window_seconds': 3600,
        'results': rows[-80:],
        'artifact_reports_policy_applied': applied,
        'artifact_reports_policy_removed': removed,
        'artifact_reports_failed_frontend_test': failed_test,
        'endpoint_network_isolation_verified': False,
        'note': note,
    }


def main(argv=None):
    import argparse
    p=argparse.ArgumentParser(description='AEGISMESH LAB / isolation réelle limitée à WIN-LAB-01')
    s=p.add_subparsers(dest='action',required=True)
    start_parser=s.add_parser('start');start_parser.add_argument('--agent-id',required=True)
    start_parser.add_argument('--confirm',action='store_true')
    start_parser.add_argument('--console-access',action='store_true')
    for cmd in ('status', 'logs', 'results', 'monitor-status'):
        sub=s.add_parser(cmd);sub.add_argument('--agent-id',required=True)
    monitor_parser=s.add_parser('monitor-ensure');monitor_parser.add_argument('--agent-id',required=True)
    monitor_parser.add_argument('--confirm',action='store_true')
    release_parser=s.add_parser('release');release_parser.add_argument('--agent-id',required=True)
    release_parser.add_argument('--confirm',action='store_true')
    a=p.parse_args(argv)
    try:
        if a.action=='start': result=start(a.agent_id,confirm=a.confirm,console_access=a.console_access)
        elif a.action=='status': result=status(a.agent_id)
        elif a.action=='monitor-status': result=monitor_status(a.agent_id)
        elif a.action=='monitor-ensure': result=ensure_monitor(a.agent_id,confirm=a.confirm)
        elif a.action=='release': result=stop(a.agent_id,confirm=a.confirm)
        elif a.action=='results': result=monitor_results(a.agent_id)
        else: result=monitoring_logs(a.agent_id)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 0
    except (ValueError,RuntimeError,PermissionError,OSError) as exc:
        print('AEGISMESH LAB EDR : '+str(exc)[:250],file=__import__('sys').stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
