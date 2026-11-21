#!/usr/bin/env python3
"""AEGISMESH-SOAR / operational chain: inspection and opt-in validation.

Invoked as `aegismesh-soar chain ...`; standard library only. Does NOT
modify existing Wazuh, Fail2ban, Shuffle or AEGISMESH services implicitly.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
CONF = Path('/etc/aegismesh-soar/soar.env')


def settings():
    values = {}
    if CONF.is_file():
        for line in CONF.read_text().splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                k,v = line.split('=',1)
                values[k.strip()] = v.strip().strip('"')
    return values


def info(label, state, explanation=''):
    print(f'  {label:<26} {state:<14} {explanation}')


def cmd(argv, timeout=12):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def service_state(name):
    result=cmd(['systemctl','is-active',name])
    return result.stdout.strip() if result is not None else 'unknown'


def check_http_health(config):
    host=config.get('SOAR_BIND_HOST','127.0.0.1')
    port=config.get('SOAR_PORT','19081')
    try:
        request=urllib.request.Request(f'http://{host}:{port}/health')
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=3) as response:
            body=json.load(response)
            return response.status == 200 and body.get('status') == 'up'
    except (ValueError, OSError, urllib.error.URLError):
        return False


def report():
    cfg=settings()
    print('AEGISMESH SOAR · chaîne décision → Shuffle → Wazuh / Fail2ban')
    info('Bridge', 'OK' if check_http_health(cfg) else 'ÉCHEC', f"{cfg.get('SOAR_BIND_HOST','127.0.0.1')}:{cfg.get('SOAR_PORT','19081')}")
    info('Shuffle webhook', 'CONFIGURÉ' if cfg.get('SHUFFLE_WEBHOOK_URL') else 'MANQUANT')
    info('Auth webhook', 'CONFIGURÉ' if cfg.get('SHUFFLE_WEBHOOK_HEADER_NAME') and cfg.get('SHUFFLE_WEBHOOK_HEADER_VALUE') else 'MANQUANT')
    info('Retour HTTP Shuffle', 'À TESTER', 'Le worker doit atteindre /v1/execute')
    info('Wazuh manager', service_state('wazuh-manager.service'))
    info('Identifiants Wazuh', 'CONFIGURÉ' if cfg.get('WAZUH_USER') and cfg.get('WAZUH_PASSWORD') else 'MANQUANT')
    info('Wazuh CA TLS', 'CONFIGURÉ' if cfg.get('WAZUH_CA_FILE') else 'À VÉRIFIER')
    info('Fail2ban',service_state('fail2ban.service'))
    p=cmd(['fail2ban-client','status','aegismesh-soar-gcp'])
    info('Jail SOAR', 'OK' if p is not None and p.returncode == 0 else 'ÉCHEC')
    info('Tests actifs', cfg.get('ENABLE_TEST_ACTIONS','false'))
    info('Actions production', cfg.get('ENABLE_PROD_ACTIONS','false'))
    bind=cfg.get('SOAR_BIND_HOST','127.0.0.1')
    if bind.startswith('127.'):
        print('\n  ATTENTION : le port est lié au loopback de l’hôte. Un worker Shuffle Docker')
        print('  ne peut pas joindre 127.0.0.1 de l’hôte via son propre localhost.')
        print('  Choisir une adresse de passerelle Docker locale après `aegismesh-soar network`.')
    print('  Aucune action de sécurité déclenchée par ce diagnostic.')


def api_wazuh_check():
    cfg = settings()
    if not cfg.get('WAZUH_USER') or not cfg.get('WAZUH_PASSWORD'):
        raise RuntimeError('Configurer les identifiants : aegismesh-soar configure wazuh')
    sys.path.insert(0, str(ROOT/'soar'))
    import bridge
    bridge.ENV.clear()
    bridge.ENV.update(cfg)
    try:
        token = bridge.wazuh_auth_token()
        agents = bridge.wazuh_api_request('GET', '/agents?limit=1', None,
                                          {'Authorization':'Bearer '+token})
        if agents.get('error'):
            raise RuntimeError('API Wazuh a signalé une erreur de lecture des agents')
    except Exception as exc:
        raise RuntimeError(f'API Wazuh : {type(exc).__name__}: {str(exc)[:180]}') from None
    print('OK : API Wazuh authentifiée sur HTTPS, lecture agents autorisée; ')
    print('     certificat vérifié localement ou CA explicite. Aucune action déclenchée.')


def agent_configuration_status():
    cfg = settings()
    print('Production actions :',cfg.get('ENABLE_PROD_ACTIONS', 'false'))
    print('Wazuh agent IDs approuvés :',cfg.get('WAZUH_PROD_AGENT_IDS') or 'aucun')
    print('Réseaux protégés :', cfg.get('PROTECTED_CIDRS') or 'NON DÉFINIS')
    print('API Wazuh :',cfg.get('WAZUH_API_URL','https://127.0.0.1:55000'))
    print('Certificat CA explicite :','oui' if cfg.get('WAZUH_CA_FILE') else 'non (certificat local Wazuh utilisé en loopback)')


def operational_submit(tag, args):
    if not args.confirm:
        raise RuntimeError('Action réelle : ajouter --confirm après validation de l’incident et de la cible')
    if len(args.evidence) < 2:
        raise RuntimeError('Deux références de preuve distinctes sont obligatoires')
    if len(set(args.evidence)) < 2:
        raise RuntimeError('Deux preuves distinctes sont obligatoires')
    if not 0.90 <= args.confidence <= 1:
        raise RuntimeError('--confidence doit être compris entre 0.90 et 1')
    cfg = settings()
    if cfg.get('ENABLE_PROD_ACTIONS') != 'true':
        raise RuntimeError('Actions désactivées : exécuter aegismesh-soar configure production')
    if not cfg.get('PROTECTED_CIDRS'):
        raise RuntimeError('Réseaux de gestion non protégés : configure production')
    cmdline = [sys.executable, str(ROOT/'soar/soarctl.py'), 'submit',
               '--tag',tag,'--incident-id',args.incident,
               '--ip',args.ip,'--confidence',str(args.confidence), '--approved','--wait','40']
    if tag == 'WAZUH_BLOCK_AGENT':
        cmdline.extend(['--agent-id',args.agent_id])
    for e in args.evidence:
        cmdline.extend(['--evidence',e])
    return subprocess.run(cmdline).returncode


def local_proof(ident):
    if not re.fullmatch('[A-Za-z0-9_-]{8,64}',ident):
        raise ValueError('identifiant de décision non valide')
    path=Path('/var/ossec/logs/aegismesh-soar-proof.jsonl')
    if not path.is_file():
        print('Pas de fichier de preuve Wazuh local; une commande API acceptée ne suffit pas.')
        return 3
    with path.open('rb') as f:
        f.seek(0,os.SEEK_END)
        f.seek(max(0,f.tell()-100000))
        for line in f:
            try: obj=json.loads(line)
            except (ValueError, UnicodeDecodeError): continue
            if obj.get('proof_id')==ident and obj.get('event')=='wazuh-active-response-executed' and obj.get('command')=='add':
                print('OK : preuve écrite par l’exécuteur Wazuh local pour la décision',ident)
                return 0
    print('Preuve Wazuh non retrouvée dans les dernières entrées du journal local.')
    return 3


def submit(tag,agent_id=''):
    args=[sys.executable,str(ROOT/'soar/soarctl.py'),'submit','--tag',tag,
          '--incident-id','SOAR-CONTROLLED-CHECK','--wait','35']
    if tag == 'F2B_TEST_BAN':
        args += ['--ip','198.51.100.42','--approved','--confidence','0.99',
                 '--evidence','controlled-test-001','--evidence','controlled-test-002']
    elif tag == 'WAZUH_AR_PROOF':
        args += ['--agent-id',agent_id,'--approved','--confidence','0.99',
                 '--evidence','controlled-test-001','--evidence','controlled-test-002']
    return subprocess.run(args).returncode


def guide():
    cfg=settings()
    print('''AEGISMESH SOAR · connexion initiale (aucun webhook exécuté dans cette commande)

1) Shuffle UI → Workflows → créer `AEGISMESH - Decision Dispatcher`.
   Ajouter Webhook en déclencheur (POST) puis une action HTTP POST.
   Démarrer le webhook et copier son URL réelle.

2) Le bridge doit être joignable depuis le *worker* HTTP Shuffle, pas seulement
   depuis shuffle-backend. Inspecter `aegismesh-soar network` ; choisir une IP
   de passerelle Docker attribuée à l’hôte. Ne pas exposer 19081 à Internet.
   Définir dans l’action HTTP :
     URL     : http://IP_DOCKER_HOTE:19081/v1/execute
     Headers : Content-Type: application/json
               X-Aegismesh-Token: [SECRET SHUFFLE_ACTION_TOKEN, dans auth de l'app]
     Body    : {"decision_id":"$exec.decision_id","execution_id":"$exec.decision_id"}
   Le second champ est une CLÉ DE CORRÉLATION stable, pas l’ID d’exécution natif
   Shuffle. L’ID natif est à relever dans Shuffle > Executions.
   Utiliser la fonction d’autocomplétion de Shuffle pour sélectionner $exec.decision_id.

3) Sur GCP : `aegismesh-soar configure webhook URL_REELLE`
   Si auth Webhook requise dans le déclencheur Shuffle :
     `aegismesh-soar configure shuffle-auth` (saisie secrète, hors Git).
   Vérifier : `aegismesh-soar chain status`.

4) Tester une seule décision : `aegismesh-soar chain observe`
   Preuve attendue : action_status=executed (pas seulement accepted_by_shuffle)
   et exécution visible dans l’historique Shuffle.

5) Wazuh : installer une preuve contrôlée sur le manager, configurer l’API
   avec CA TLS valide, puis lancer WAZUH_AR_PROOF sur un agent autorisé.

6) Fail2ban : activer explicitement les tests avant de lancer F2B_TEST_BAN ;
   le test ajoute puis retire 198.51.100.42 uniquement dans aegismesh-soar-gcp.
   Aucune action de production autorisée par défaut.
''')
    print('État actuel : webhook', 'CONFIGURÉ' if cfg.get('SHUFFLE_WEBHOOK_URL') else 'MANQUANT')


def main(argv=None):
    parser=argparse.ArgumentParser(description='Vérification de la chaîne SOAR effective')
    sub=parser.add_subparsers(dest='action',required=True)
    for action in ('status','guide','observe','wazuh-check','wazuh-connect','wazuh-install','production-status'):
        sub.add_parser(action)
    pb=sub.add_parser('wazuh-proof');pb.add_argument('--agent-id',default='000')
    ps=sub.add_parser('proof-check');ps.add_argument('decision_id')
    f=sub.add_parser('f2b-test');f.add_argument('--confirm',action='store_true')
    f2b=sub.add_parser('ban-ip',help='Blocage réel sur le serveur principal par Fail2ban via Shuffle')
    ar=sub.add_parser('block-agent',help='Action réelle sur agent Linux équipé du script nft temporisé')
    for x in (f2b, ar):
        x.add_argument('--ip',required=True,help='IPv4 publique externe suspecte')
        x.add_argument('--incident',required=True,help='Identifiant incident réel')
        x.add_argument('--evidence',action='append',default=[],help='Preuve distincte; fournir au moins 2 fois')
        x.add_argument('--confidence',type=float,required=True,help='Confiance réelle fournie par le moteur de décision')
        x.add_argument('--confirm',action='store_true',help='Autoriser une vraie remédiation')
    ar.add_argument('--agent-id',required=True,help='ID Wazuh Linux sur liste autorisée')
    args=parser.parse_args(argv)
    if args.action in ('observe','f2b-test','wazuh-proof','wazuh-install','wazuh-check','wazuh-connect','ban-ip','block-agent') and os.geteuid() != 0:
        parser.error('root/sudo requis')
    try:
        if args.action=='status': report()
        elif args.action=='guide': guide()
        elif args.action in ('wazuh-check','wazuh-connect'): api_wazuh_check()
        elif args.action=='production-status': agent_configuration_status()
        elif args.action=='ban-ip': return operational_submit('F2B_BAN_SERVER', args)
        elif args.action=='block-agent': return operational_submit('WAZUH_BLOCK_AGENT', args)
        elif args.action=='wazuh-install':
            print('Installation du script de preuve sur le MANAGER uniquement ; aucune commande Wazuh déclenchée.')
            result=subprocess.run(['bash',str(ROOT/'ops/wazuh/install_ar_proof.sh')])
            return result.returncode
        elif args.action=='proof-check': return local_proof(args.decision_id)
        elif args.action=='observe': return submit('OBSERVE')
        elif args.action=='f2b-test':
            if not args.confirm:
                parser.error('Test avec action réelle Fail2ban : réexécuter avec --confirm après vérification de l’impact')
            if settings().get('ENABLE_TEST_ACTIONS')!='true':
                parser.error('Tests désactivés. Activer explicitement : aegismesh-soar configure enable-tests')
            return submit('F2B_TEST_BAN')
        elif args.action=='wazuh-proof':
            if settings().get('ENABLE_TEST_ACTIONS')!='true':
                parser.error('Tests désactivés. Activer explicitement : aegismesh-soar configure enable-tests')
            if not re.fullmatch(r'\d{3}',args.agent_id): parser.error('Agent Wazuh : trois chiffres')
            return submit('WAZUH_AR_PROOF',args.agent_id)
    except (RuntimeError, ValueError) as exc:
        print('ÉCHEC :',exc,file=sys.stderr)
        return 2
    return 0


if __name__=='__main__':
    sys.exit(main())
