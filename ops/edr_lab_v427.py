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


def _quarantine_spec(table_override=None):
    """Read the exact label-scoped monitor, supporting both proto encodings.

    Velociraptor's ArtifactCollectorArgs may expose artifact names in
    `.artifacts` while its `.specs` list contains *only artifacts with custom
    parameters*. A default artifact therefore legitimately has no spec.
    Never call it missing solely because the spec list is empty. Refuse
    duplicates, mismatched representations and unexpected structures.
    """
    if table_override is None:
        rows = edr.api_query(edr.READ_MONITORING)
        if len(rows) != 1:
            raise RuntimeError('Table de monitoring absente ou ambiguë')
        table = rows[0].get('monitoring')
    else:
        table = table_override
    if isinstance(table, str):
        try:
            table = json.loads(table)
        except ValueError:
            raise RuntimeError('Table de monitoring non JSON') from None
    if not isinstance(table, dict):
        raise RuntimeError('Monitoring invalide')
    groups = [group for group in (table.get('label_events') or [])
              if isinstance(group, dict) and str(group.get('label', '')).casefold() == 'quarantine']
    if len(groups) != 1:
        raise PermissionError('Groupe Quarantine absent ou ambigu')
    data = groups[0].get('artifacts')
    if not isinstance(data, dict):
        raise PermissionError('Format des artefacts du groupe Quarantine inconnu')

    names = data.get('artifacts') or []
    specs = data.get('specs') or []
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise PermissionError('Liste de noms du monitoring invalide')
    if not isinstance(specs, list) or not all(isinstance(spec, dict) for spec in specs):
        raise PermissionError('Liste des spécifications du monitoring invalide')
    monitor = 'Windows.Remediation.QuarantineMonitor'
    name_count = names.count(monitor)
    matched_specs = [spec for spec in specs if spec.get('artifact') == monitor]
    if name_count > 1 or len(matched_specs) > 1:
        raise PermissionError('Moniteur Quarantine dupliqué')
    if not (name_count or matched_specs):
        raise PermissionError('Moniteur Quarantine absent')
    # ArtifactCollectorArgs.specs is not required for an artifact using its
    # default parameters. Return an empty spec in that case; `_rule_table`
    # interprets it as not yet configured, not as an absent monitor.
    if matched_specs:
        return matched_specs[0]
    return {'artifact': monitor}


def _monitoring_patch_target():
    """Find the unique, existing Quarantine group for a minimal JSON patch.

    Do not rewrite all monitoring settings or remove the artifact: the rest
    of Velociraptor's monitoring table may be managed by other operators.
    """
    rows = edr.api_query(edr.READ_MONITORING)
    if len(rows) != 1:
        raise RuntimeError('Table de monitoring absente ou ambiguë')
    table = rows[0].get('monitoring')
    if isinstance(table, str):
        try:
            table = json.loads(table)
        except ValueError:
            raise RuntimeError('Monitoring non JSON') from None
    if not isinstance(table, dict):
        raise RuntimeError('Format de monitoring inconnu')
    groups = table.get('label_events') or []
    if not isinstance(groups, list) or len(groups) > 16:
        raise RuntimeError('Groupes du monitoring absents ou trop nombreux')
    indices = [i for i, g in enumerate(groups)
               if isinstance(g, dict) and str(g.get('label', '')).casefold() == 'quarantine']
    if len(indices) != 1:
        raise PermissionError('Groupe Quarantine absent ou ambigu')
    idx = indices[0]
    group = groups[idx]
    data = group.get('artifacts')
    if not isinstance(data, dict):
        raise RuntimeError('Structure d artefacts Quarantine inconnue')
    names = data.get('artifacts') or []
    specs = data.get('specs')
    name = 'Windows.Remediation.QuarantineMonitor'
    if not isinstance(names, list) or names.count(name) != 1:
        raise PermissionError('Le moniteur doit figurer exactement une fois dans la liste Quarantine')
    if specs is not None and (not isinstance(specs, list) or not all(isinstance(x, dict) for x in specs)):
        raise PermissionError('Liste de paramètres monitoring invalide')
    if any(x.get('artifact') == name for x in (specs or [])):
        raise PermissionError('Paramètres du moniteur déjà présents : remplacement refusé')
    return idx, bool(specs), table


def _quarantine_proto_extras_v4216(args):
    """Classify unknown protobuf fields without exposing their values.

    Proto JSON may explicitly serialize default-valued resource/collector
    fields. These must not be confused with real custom configuration. Only
    empty/default scalar or container values qualify for a scoped rm/add;
    all nondefault extras refuse replacement to protect other settings.
    """
    if not isinstance(args, dict):
        raise RuntimeError('Quarantine: structure artifacts invalide')
    known = {'artifacts', 'specs'}
    extras = {key: val for key, val in args.items() if key not in known}
    if any(not isinstance(key, str) for key in extras):
        raise PermissionError('Noms de champs du monitoring inattendus')
    if len(extras) > 32:
        raise PermissionError('Trop de champs supplémentaires du monitoring')
    def is_default(value):
        # Strictly refuse nonempty collections and all truthy scalar values;
        # never discard a customized batch/timeout/resource setting.
        if value is None or value is False:
            return True
        if type(value) in (int, float):
            return value == 0
        if isinstance(value, str):
            return value == ''
        if isinstance(value, (dict, list)):
            return len(value) == 0
        return False
    nondefault = sorted(key for key, val in extras.items() if not is_default(val))
    return {'extra_keys': sorted(extras),
            'nondefault_extra_keys': nondefault,
            'extra_types': {key: type(extras[key]).__name__ for key in sorted(extras)},
            'safe_default_only': not nondefault}


def transport_inspect(agent):
    """Read-only shape diagnostic; no raw VQL configuration or secrets exposed."""
    edr.require_root()
    cid = _validate_target(agent, require_monitor=False)
    rows = edr.api_query(edr.READ_MONITORING)
    if len(rows) != 1:
        raise RuntimeError('Table de monitoring absente ou ambiguë')
    table = rows[0].get('monitoring')
    if isinstance(table, str):
        try:
            table = json.loads(table)
        except ValueError:
            raise RuntimeError('Réponse monitoring non JSON') from None
    if not isinstance(table, dict):
        raise RuntimeError('Format monitoring inconnu')
    groups = table.get('label_events') or []
    if not isinstance(groups, list):
        raise RuntimeError('Format groupes monitoring invalide')
    matches = [g for g in groups if isinstance(g, dict)
               and str(g.get('label', '')).casefold() == 'quarantine']
    info = []
    for group in matches:
        data = group.get('artifacts') or {}
        names = data.get('artifacts') if isinstance(data, dict) else None
        specs = data.get('specs') if isinstance(data, dict) else None
        info.append({
            'artifacts_names_type': type(names).__name__,
            'artifact_names_count': len(names) if isinstance(names, list) else None,
            'name_matches_count': names.count('Windows.Remediation.QuarantineMonitor') if isinstance(names, list) else None,
            'specs_type': type(specs).__name__,
            'specs_count': len(specs) if isinstance(specs, list) else None,
            'spec_matches_count': sum(1 for sp in specs if isinstance(sp, dict) and sp.get('artifact') == 'Windows.Remediation.QuarantineMonitor') if isinstance(specs, list) else None,
            'proto_metadata': _quarantine_proto_extras_v4216(data) if isinstance(data, dict) else None,
            'repair_safe_default_metadata': (_quarantine_proto_extras_v4216(data)['safe_default_only'] if isinstance(data, dict) else False),
        })
    return {'agent_id': agent, 'client_id': cid,
            'quarantine_group_count': len(matches), 'groups': info,
            'read_only': True, 'network_effect_verified': False,
            'note': 'Ne montre ni paramètres ni données sensibles des autres artefacts'}


def _rule_table(spec):
    """Velociraptor artifact parameter encoding: spec.parameters.env[]"""
    params = spec.get('parameters') or {}
    if not isinstance(params, dict):
        raise RuntimeError('Paramètres du moniteur inconnus')
    env = params.get('env') or []
    if not isinstance(env, list):
        raise RuntimeError('Format env du moniteur inconnu')
    values = [str(row.get('value', '')) for row in env if isinstance(row, dict)
              and row.get('key') == 'RuleLookupTable']
    if len(values) > 1:
        raise RuntimeError('Plusieurs paramètres RuleLookupTable : refus')
    return values[0].replace('\r\n', '\n').strip() if values else None


def transport_status(agent):
    edr.require_root()
    cid = _validate_target(agent)
    current = _rule_table(_quarantine_spec())
    return {'agent_id':agent, 'client_id':cid,
            'wireguard_peer':f'{edr.WG_LAB_TRANSPORT_IP}:{edr.WG_LAB_TRANSPORT_PORT}/udp',
            'wg_exception_configured':current == edr.WG_LAB_RULE_TABLE.strip(),
            'current_rule_table_is_default':current is None,
            'network_effect_verified':False,
            'tls_frontend_check_verified':False,
            'note':'Le maintien de WireGuard ne suffit pas à prouver la réponse TLS de /server.pem'}


def _preview_shape(proposed, index):
    """Only expose data *types*, never raw artifact settings or secrets."""
    if isinstance(proposed, str):
        try: proposed=json.loads(proposed)
        except (ValueError, TypeError):
            return {'table_type': 'invalid_json_string'}
    if not isinstance(proposed, dict):
        return {'table_type':type(proposed).__name__}
    groups=proposed.get('label_events')
    if not isinstance(groups, list) or index >= len(groups):
        return {'table_type':'dict', 'groups_type':type(groups).__name__}
    data=groups[index].get('artifacts') if isinstance(groups[index],dict) else None
    specs=data.get('specs') if isinstance(data,dict) else None
    return {'table_type':'dict','specs_type':type(specs).__name__,
            'specs_length':len(specs) if isinstance(specs,list) else None,
            'spec_item_types':[type(x).__name__ for x in specs[:3]] if isinstance(specs,list) else []}


def _transport_preview_choice(index, append):
    """Prefer an exact pre-validated existing patch, try JSON-typed RFC6902
    only if Velociraptor cannot represent the legacy VQL literal correctly.
    Neither candidate writes anything, and both must pass strict validation.
    """
    failures=[]
    attempts=(('legacy_vql', edr.WG_MONITOR_PREVIEW_QUERIES[(index,append)],
               edr.WG_MONITOR_PATCH_QUERIES[(index,append)]),
              ('json_rfc6902',edr.WG_MONITOR_JSON_PREVIEW_QUERIES[(index,append)],
               edr.WG_MONITOR_JSON_PATCH_QUERIES[(index,append)]))
    for name, preview_query, write_query in attempts:
        try:
            rows=edr.api_query(preview_query)
            if len(rows)!=1 or not isinstance(rows[0],dict):
                failures.append({'variant':name,'problem':'no_structured_response'})
                continue
            proposed=rows[0].get('monitoring')
            if proposed is None:
                failures.append({'variant':name,'problem':'null_preview'})
                continue
            try:
                spec=_quarantine_spec(proposed)
                if _rule_table(spec)==edr.WG_LAB_RULE_TABLE.strip():
                    return proposed, name, write_query, failures
                failures.append({'variant':name,'problem':'rule_table_mismatch',
                                 'shape':_preview_shape(proposed,index)})
            except (RuntimeError, ValueError, PermissionError) as exc:
                failures.append({'variant':name,'problem':str(exc),
                                 'shape':_preview_shape(proposed,index)})
        except (RuntimeError, ValueError, PermissionError) as exc:
            failures.append({'variant':name,'problem':type(exc).__name__})
    raise RuntimeError('Prévisualisation VQL invalide pour les deux variantes : '
                       +json.dumps(failures,ensure_ascii=False))


def _transport_preview(index, append):
    """Backwards-compatible read-only wrapper for tests and local consumers."""
    return _transport_preview_choice(index, append)[0]


def transport_diagnose(agent):
    """Read-only check that a full monitoring patch is correctly representable."""
    edr.require_root()
    cid = _validate_target(agent)
    status = transport_status(agent)
    details = {'agent_id': agent, 'client_id': cid,
               'wg_exception_configured': status['wg_exception_configured'],
               'read_only': True, 'server_write_attempted': False,
               'endpoint_network_isolation_verified': False}
    if status['wg_exception_configured']:
        details['diagnosis'] = 'already_configured'
        return details
    try:
        index, append, _ = _monitoring_patch_target()
        details['quarantine_group_index'] = index
        details['existing_other_specs'] = append
        proposed, variant, _, failures = _transport_preview_choice(index, append)
        details['patch_preview_valid'] = True
        details['patch_variant'] = variant
        details['legacy_preview_failures'] = failures
        details['preview_artifact_custom_parameter_verified'] = (_rule_table(_quarantine_spec(proposed)) == edr.WG_LAB_RULE_TABLE.strip())
        details['diagnosis'] = 'preview_valid; server write persistence must be evaluated separately'
    except (RuntimeError, ValueError, PermissionError) as exc:
        # Controlled errors only: never dump the monitoring table or VQL content.
        details['patch_preview_valid'] = False
        details['diagnosis'] = str(exc)
    return details


def transport_ensure(agent, *, confirm=False):
    """Change only the Quarantine monitor parameters, never isolate a client.

    Uses the documented add_client_monitoring(parameters=dict(...)) function.
    Verify exact resulting configuration and refuse any complex existing table.
    """
    edr.require_root()
    if not confirm:
        raise PermissionError('--confirm requis pour modifier les paramètres du moniteur')
    cid = _validate_target(agent)
    with edr.lease_lock():
        if edr.read_json(edr.LEASES, {}):
            raise PermissionError('Baux EDR actifs : modification refusée')
        if any('Quarantine' in (client.get('labels') or []) for client in edr.api_clients()):
            raise PermissionError('Un client est en quarantaine : modification refusée')
        if 'Quarantine' in edr.labels_for(cid):
            raise PermissionError('Cible actuellement en quarantaine : modification refusée')
        # A globally assigned QuarantineMonitor would affect other clients.
        if _read_monitoring_assignments()['global']:
            raise PermissionError('Moniteur global : modification refusée')
        existing_spec = _quarantine_spec()
        previous = _rule_table(existing_spec)
        env = (existing_spec.get('parameters') or {}).get('env') or []
        # Other custom parameters must not be discarded by a narrow transport
        # update even when RuleLookupTable itself still has the default value.
        if previous is None and env:
            raise PermissionError('Autres paramètres personnalisés du moniteur : remplacement automatique refusé')
        if previous == edr.WG_LAB_RULE_TABLE.strip():
            return {'status':'already_configured', **transport_status(agent)}
        if previous is not None:
            raise PermissionError('Paramètres existants personnalisés : pas de remplacement automatique')
        index, append, before_table = _monitoring_patch_target()
        # V4.2.13: check what the server's OWN VQL patch function will
        # produce. Prior mock tests incorrectly assumed patch always worked.
        proposed, variant, query, failures = _transport_preview_choice(index, append)
        # The preview may not mutate any other group or global setting.
        check_table = json.loads(proposed) if isinstance(proposed, str) else proposed
        if not isinstance(check_table, dict):
            raise RuntimeError('Prévisualisation invalide : table non structurée')
        before_global={k:v for k,v in before_table.items() if k!='label_events'}
        preview_global={k:v for k,v in check_table.items() if k!='label_events'}
        before_groups=before_table.get('label_events') or []
        preview_groups=check_table.get('label_events') or []
        if (before_global!=preview_global or not isinstance(preview_groups,list) or
            len(before_groups)!=len(preview_groups) or
            any(a!=b for j,(a,b) in enumerate(zip(before_groups,preview_groups)) if j!=index)):
            raise RuntimeError('Prévisualisation affecte des groupes non ciblés : écriture interdite')
        response = edr.api_query(query)
        if len(response) != 1 or not isinstance(response[0], dict):
            raise RuntimeError('API set_client_monitoring sans réponse structurée : ne pas isoler')
        value = response[0].get('result')
        if value is None or value is False:
            raise RuntimeError('set_client_monitoring a renvoyé NULL/false (permission, erreur VQL ou sérialisation) : aucune isolation')
        new_spec = _quarantine_spec()
        if _rule_table(new_spec) != edr.WG_LAB_RULE_TABLE.strip():
            raise RuntimeError('Patch valide en prévisualisation, mais valeur NON persistée par set_client_monitoring; examiner rôle API et journaux VQL')
        # Detect unexpected changes outside this dedicated group; do not
        # automatically restore a potentially concurrent user's configuration.
        after_rows = edr.api_query(edr.READ_MONITORING)
        if len(after_rows) != 1:
            raise RuntimeError('Monitoring impossible à vérifier après écriture')
        after_table = after_rows[0].get('monitoring')
        if isinstance(after_table, str):
            after_table = json.loads(after_table)
        if not isinstance(after_table, dict):
            raise RuntimeError('Monitoring inattendu après écriture')
        before_other = dict(before_table)
        after_other = dict(after_table)
        before_other.pop('label_events', None)
        after_other.pop('label_events', None)
        if before_other != after_other:
            raise RuntimeError('Changement de monitoring global détecté : contrôle requis avant isolement')
        b_groups, a_groups = before_table.get('label_events', []), after_table.get('label_events', [])
        if len(b_groups) != len(a_groups) or any(bg != ag for i,(bg,ag) in enumerate(zip(b_groups,a_groups)) if i != index):
            raise RuntimeError('Modification inattendue des autres labels : contrôle requis avant isolement')
    return {'status':'configured_no_quarantine_started', 'patch_variant':variant, **transport_status(agent),
            'scope':'Quarantine monitoring label; seule la cible LAB 001 est autorisée à déclencher cette quarantaine'}



def _read_monitor_table_v4215():
    """Read the entire monitoring state; do not print its potentially sensitive content."""
    rows = edr.api_query(edr.READ_MONITORING)
    if len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeError('Lecture monitoring Velociraptor absente ou ambiguë')
    table = rows[0].get('monitoring')
    if isinstance(table, str):
        table = json.loads(table)
    if not isinstance(table, dict):
        raise RuntimeError('Structure du monitoring invalide ou inaccessible')
    # Velociraptor protobuf JSON can omit empty repeated fields entirely.
    # A successful removal of the last label-group may legitimately omit
    # `label_events`; normalize it, rather than blocking rollback.
    if table.get('label_events') is None:
        table['label_events'] = []
    if not isinstance(table['label_events'], list):
        raise RuntimeError('Format label_events du monitoring invalide')
    return table


def _quarantine_group_v4215(table):
    groups = [x for x in table.get('label_events', [])
              if isinstance(x, dict) and str(x.get('label', '')).casefold() == 'quarantine']
    if len(groups) > 1:
        raise PermissionError('Groupes Quarantine dupliqués; opération refusée')
    return groups[0] if groups else None


def _monitor_exists_v4215(table):
    group = _quarantine_group_v4215(table)
    if not group:
        return False
    config = group.get('artifacts') or {}
    if not isinstance(config, dict):
        raise RuntimeError('Quarantine: structure artifacts inconnue')
    names = config.get('artifacts') or []
    if not isinstance(names, list):
        raise RuntimeError('Quarantine: noms des artefacts invalides')
    if names.count('Windows.Remediation.QuarantineMonitor') > 1:
        raise PermissionError('Moniteur Quarantine dupliqué')
    return 'Windows.Remediation.QuarantineMonitor' in names


def _other_monitoring_unchanged_v4215(before, after):
    """Never silently alter other label groups or the global monitoring state."""
    bg = {k: v for k, v in before.items() if k != 'label_events'}
    ag = {k: v for k, v in after.items() if k != 'label_events'}
    if bg != ag:
        return False
    def others(table):
        return [x for x in table.get('label_events', [])
                if not (isinstance(x,dict) and str(x.get('label','')).casefold() == 'quarantine')]
    return others(before) == others(after)


def transport_repair(agent, *, confirm=False):
    """Safely replace a default Quarantine-only entry with a parameterized one.

    V4.2.14: `set_client_monitoring(value=patch(...))` returns NULL on this
    server although the patch previews correctly. Use the documented scoped
    rm/add API pair, verifying each real readback and restoring the original
    default monitor if anything fails. No label, isolation, or firewall action.
    """
    edr.require_root()
    if not confirm:
        raise PermissionError('Confirmation --confirm requise pour réparer le moniteur')
    cid = _validate_target(agent)
    with edr.lease_lock():
        if edr.read_json(edr.LEASES, {}):
            raise PermissionError('Bail EDR actif : réparation refusée')
        if any('Quarantine' in (client.get('labels') or []) for client in edr.api_clients()):
            raise PermissionError('Un client possède déjà le label Quarantine : réparation refusée')
        if 'Quarantine' in edr.labels_for(cid):
            raise PermissionError('Windows LAB déjà en quarantaine : réparation refusée')
        assignments = _read_monitoring_assignments()
        if assignments['global'] or any(x.casefold() != 'quarantine' for x in assignments['labels']):
            raise PermissionError('Moniteur utilisé dans un autre groupe : réparation refusée')
        before = _read_monitor_table_v4215()
        group = _quarantine_group_v4215(before)
        if group is None:
            raise RuntimeError('Groupe Quarantine absent; lancer monitor-ensure')
        if set(group) != {'label','artifacts'} or str(group.get('label')) != 'Quarantine':
            raise PermissionError('Groupe Quarantine non standard : remplacement refusé')
        args = group.get('artifacts')
        if not isinstance(args, dict):
            raise PermissionError('Artefacts Quarantine non structurés : remplacement refusé')
        extra = _quarantine_proto_extras_v4216(args)
        if not extra['safe_default_only']:
            raise PermissionError('Artefacts Quarantine : paramètres supplémentaires non vides; '
                                  'remplacement refusé. Champs: ' + ','.join(extra['nondefault_extra_keys']))
        if args.get('artifacts') != ['Windows.Remediation.QuarantineMonitor']:
            raise PermissionError('Autres artefacts Quarantine présents : remplacement refusé')
        if args.get('specs') not in (None, []):
            if _rule_table(_quarantine_spec(before)) == edr.WG_LAB_RULE_TABLE.strip():
                return {'status':'already_configured', **transport_status(agent)}
            raise PermissionError('Paramètres personnalisés existants : remplacement refusé')
        # Back up only after all guards pass. This file is private (0600) and
        # stays on the host; the public Git checkout contains no credentials.
        backup = edr.LEASES.parent / 'edr-quarantine-monitor-backup-v4215.json'
        edr.atomic_json(backup, before)
        removal_attempted = False
        try:
            removal_attempted = True
            edr.api_query(edr.RM_QUARANTINE_MONITOR)
            without = _read_monitor_table_v4215()
            if _monitor_exists_v4215(without):
                raise RuntimeError('Retrait ciblé non confirmé par Velociraptor')
            if not _other_monitoring_unchanged_v4215(before, without):
                raise RuntimeError('Modification inattendue d un autre groupe lors du retrait')
            edr.api_query(edr.ADD_QUARANTINE_WG_MONITOR)
            after = _read_monitor_table_v4215()
            if not _other_monitoring_unchanged_v4215(before, after):
                raise RuntimeError('Modification inattendue d un autre groupe lors de l ajout')
            if _rule_table(_quarantine_spec(after)) != edr.WG_LAB_RULE_TABLE.strip():
                raise RuntimeError('Exception WireGuard non persistée après ajout avec paramètres')
            return {'status':'configured_no_quarantine_started',
                    'repair_method':'scoped_remove_add_verified', 'agent_id':agent,
                    'client_id':cid, 'wireguard_peer':f'{edr.WG_LAB_TRANSPORT_IP}:{edr.WG_LAB_TRANSPORT_PORT}/udp',
                    'wg_exception_configured':True, 'endpoint_network_isolation_verified':False,
                    'next':'Confirmer le maintien TLS Velociraptor puis tester une seule isolation lab'}
        except Exception as primary:
            # A query may raise *after* the remote function ran: inspect the
            # current state instead of trusting the local return code.
            recovery_error = None
            try:
                current = _read_monitor_table_v4215()
                if removal_attempted and _other_monitoring_unchanged_v4215(before, current):
                    if _monitor_exists_v4215(current):
                        present_spec = _quarantine_spec(current)
                        present_rule = _rule_table(present_spec)
                        if present_rule == edr.WG_LAB_RULE_TABLE.strip():
                            # Writing happened despite API response error.
                            return {'status':'configured_no_quarantine_started',
                                    'repair_method':'scoped_remove_add_verified_after_api_error',
                                    'agent_id':agent, 'client_id':cid,
                                    'wg_exception_configured':True,
                                    'endpoint_network_isolation_verified':False}
                        if present_rule is not None:
                            # Partial custom modification: remove this group only.
                            edr.api_query(edr.RM_QUARANTINE_MONITOR)
                            edr.api_query(edr.ADD_QUARANTINE_MONITOR)
                        # Otherwise original default monitor remains: no extra mutation.
                    else:
                        edr.api_query(edr.ADD_QUARANTINE_MONITOR)
                    restored = _read_monitor_table_v4215()
                    if (not _other_monitoring_unchanged_v4215(before, restored)
                        or not _monitor_exists_v4215(restored)
                        or _rule_table(_quarantine_spec(restored)) is not None):
                        raise RuntimeError('Restauration du moniteur par défaut NON confirmée')
                else:
                    raise RuntimeError('Changement concurrent/état ambigu : restauration automatique refusée')
            except Exception as ex:
                recovery_error = type(ex).__name__ + ': ' + str(ex)[:120]
            if recovery_error:
                raise RuntimeError('Réparation EDR interrompue ET restauration non vérifiée; '
                                   'sauvegarde privée sur GCP conservée; cause=' +
                                   type(primary).__name__ + '; reprise=' + recovery_error) from None
            raise RuntimeError('Réparation EDR non persistée, moniteur d origine restauré et vérifié; '
                               'cause=' + type(primary).__name__ + ': ' + str(primary)[:110]) from None


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
    # A newly created quarantine label is not enough: avoid another ineffective
    # quarantine if the exact WireGuard underlay exception is not installed.
    if _rule_table(_quarantine_spec()) != edr.WG_LAB_RULE_TABLE.strip():
        raise PermissionError('Exception WireGuard non confirmée : exécuter transport-status puis transport-ensure avant un nouveau test')
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
    for cmd in ('status', 'logs', 'results', 'monitor-status', 'transport-status', 'transport-inspect', 'transport-diagnose'):
        sub=s.add_parser(cmd);sub.add_argument('--agent-id',required=True)
    monitor_parser=s.add_parser('monitor-ensure');monitor_parser.add_argument('--agent-id',required=True)
    monitor_parser.add_argument('--confirm',action='store_true')
    transport_parser=s.add_parser('transport-ensure');transport_parser.add_argument('--agent-id',required=True)
    transport_parser.add_argument('--confirm',action='store_true')
    repair_parser=s.add_parser('transport-repair');repair_parser.add_argument('--agent-id',required=True)
    repair_parser.add_argument('--confirm',action='store_true')
    for name in ('direct-doctor','direct-status'):
        sub=s.add_parser(name);sub.add_argument('--agent-id',required=True)
    direct_start=s.add_parser('direct-start');direct_start.add_argument('--agent-id',required=True)
    direct_start.add_argument('--confirm',action='store_true')
    direct_start.add_argument('--console-access',action='store_true')
    direct_start.add_argument('--recovery-task-armed',action='store_true')
    direct_release=s.add_parser('direct-release');direct_release.add_argument('--agent-id',required=True)
    direct_release.add_argument('--confirm',action='store_true')
    direct_clear=s.add_parser('direct-clear');direct_clear.add_argument('--agent-id',required=True)
    direct_clear.add_argument('--confirm',action='store_true')
    release_parser=s.add_parser('release');release_parser.add_argument('--agent-id',required=True)
    release_parser.add_argument('--confirm',action='store_true')
    a=p.parse_args(argv)
    try:
        if a.action=='start': result=start(a.agent_id,confirm=a.confirm,console_access=a.console_access)
        elif a.action=='status': result=status(a.agent_id)
        elif a.action=='monitor-status': result=monitor_status(a.agent_id)
        elif a.action.startswith('direct-'):
            from ops import edr_direct_v4217 as direct
            if a.action=='direct-doctor':result=direct.doctor(a.agent_id)
            elif a.action=='direct-status':result=direct.status(a.agent_id)
            elif a.action=='direct-start':result=direct.start(a.agent_id, confirm=a.confirm,
                console_access=a.console_access,recovery_task_armed=a.recovery_task_armed)
            elif a.action=='direct-release':result=direct.release(a.agent_id,confirm=a.confirm)
            elif a.action=='direct-clear':result=direct.clear(a.agent_id,confirm=a.confirm)
            else:raise RuntimeError('Commande LAB inconnue')
        elif a.action=='monitor-ensure': result=ensure_monitor(a.agent_id,confirm=a.confirm)
        elif a.action=='transport-status': result=transport_status(a.agent_id)
        elif a.action=='transport-inspect': result=transport_inspect(a.agent_id)
        elif a.action=='transport-diagnose': result=transport_diagnose(a.agent_id)
        elif a.action=='transport-ensure': result=transport_ensure(a.agent_id,confirm=a.confirm)
        elif a.action=='transport-repair': result=transport_repair(a.agent_id,confirm=a.confirm)
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
