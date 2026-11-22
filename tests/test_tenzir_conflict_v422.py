#!/usr/bin/env python3
"""Tests isolated to a temporary directory; never call Docker or Wazuh."""
from pathlib import Path
import sys, tempfile, copy
from unittest import mock
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from ops import tenzir_conflict_v422 as t
from ops import audit_v42 as audit

YAML_LIST='''services:
  backend:
    image: shuffle/backend
  orborus:
    image: shuffle/orborus
    environment:
      - BASE_URL=http://backend:5001
      - SHUFFLE_LOGS_DISABLED=true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  frontend:
    image: shuffle/frontend
'''
YAML_MAP='''services:
  orborus:
    environment:
      BASE_URL: http://backend:5001
  frontend:
    image: shuffle/frontend
'''
for text in (YAML_LIST,YAML_MAP):
    new=t.add_flags(text)
    assert new!=text
    assert 'SHUFFLE_SKIP_PIPELINES' in new and 'SHUFFLE_PIPELINE_ENABLED' in new
    assert 'frontend:' in new and 'SHUFFLE_LOGS_DISABLED=true' in new if text==YAML_LIST else 'frontend:' in new
    try:t.add_flags(new);raise AssertionError('Previously set flag accepted')
    except audit.AuditError:pass
try:t.add_flags('services:\n  other:\n    image: nope\n');raise AssertionError('Unknown service accepted')
except audit.AuditError:pass
before={'services': {'orborus': {'environment':{'BASE_URL':'http://backend:5001'},'image':'x'},'frontend':{'image':'y'}}}
after=copy.deepcopy(before)
after['services']['orborus']['environment'].update(t.FLAG_VALUES)
t.service_config_check(before,after)
wrong=copy.deepcopy(after);wrong['services']['frontend']['image']='new'
try:t.service_config_check(before,wrong);raise AssertionError('Unrelated service change accepted')
except audit.AuditError:pass
wrong=copy.deepcopy(after);wrong['services']['orborus']['environment']['BASE_URL']='http://other'
try:t.service_config_check(before,wrong);raise AssertionError('Other env change accepted')
except audit.AuditError:pass

with tempfile.TemporaryDirectory() as temp:
    folder=Path(temp)
    compose=folder/'compose.yaml'
    compose.write_text(YAML_LIST,encoding='utf-8')
    backup_dir=folder/'backups'
    config_before={'services': {'orborus': {'environment':{'BASE_URL':'http://backend:5001','SHUFFLE_LOGS_DISABLED':'true'},'image':'x'},'frontend':{'image':'y'},'backend':{'image':'z'}}}
    config_after=copy.deepcopy(config_before)
    config_after['services']['orborus']['environment'].update(t.FLAG_VALUES)
    def compose_config(p=None):return config_after if p is not None and p!=compose else config_before
    fake_obj={'Config':{'Env':[k+'='+v for k,v in t.FLAG_VALUES.items()]},'State':{'Status':'running'}}
    common=[mock.patch.object(t,'COMPOSE',compose),mock.patch.object(t,'BACKUPS',backup_dir),
            mock.patch.object(t,'_container_composition_ok',return_value=True),
            mock.patch.object(t,'_wazuh_owns_tcp_1514',return_value=True),
            mock.patch.object(t,'_running_container',return_value=True),
            mock.patch.object(audit,'tenzir_status',return_value={'state':'broken_missing_network'}),
            mock.patch.object(t,'compose_config',side_effect=compose_config),
            mock.patch.object(audit,'docker_object',return_value=fake_obj),
            mock.patch.object(audit,'command',return_value=mock.Mock(returncode=0,stdout='',stderr='')),
            mock.patch.object(t.time,'sleep',return_value=None),
            mock.patch.object(t.os,'geteuid',return_value=0)]
    for p in common:p.start()
    try:
        try:t.disable_pipelines(confirm=False);raise AssertionError('Missing confirmation accepted')
        except audit.AuditError:pass
        with mock.patch.object(audit,'checked',return_value='') as checked:
            result=t.disable_pipelines(confirm=True,wait_seconds=0)
            assert result['status']=='pipelines_disabled'
            assert checked.call_count==1
            assert checked.call_args.args[0][-3:]==['--no-deps','--no-build','orborus']
            assert 'SHUFFLE_SKIP_PIPELINES' in compose.read_text()
            backups=list(backup_dir.glob('*.yaml'))
            assert len(backups)==1 and backups[0].read_text()==YAML_LIST
        compose.write_text(YAML_LIST,encoding='utf-8')
        with mock.patch.object(audit,'checked',side_effect=audit.AuditError('simulated failed update')):
            try:t.disable_pipelines(confirm=True,wait_seconds=0);raise AssertionError('Broken restart accepted')
            except audit.AuditError as e:assert 'rollback' in str(e)
            assert compose.read_text()==YAML_LIST
    finally:
        for p in reversed(common):p.stop()
print('PASS: V4.2.2 Compose changes limited to Orborus; Wazuh 1514 precondition; backup and rollback tests')

# V4.2.3: reproduce the exact `ss` output seen on GCP and ensure fail-closed
# behavior with other listeners and ambiguous process ownership.
def _fake_ss(output, rc=0):
    return mock.Mock(returncode=rc,stdout=output,stderr='')

GCP_SS='''State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      128               0.0.0.0:1514       0.0.0.0:*    users:(("wazuh-remoted",pid=3238690,fd=4))
'''
with mock.patch.object(audit,'command',return_value=_fake_ss(GCP_SS)) as cmd:
    assert t._wazuh_owns_tcp_1514() is True
    cmd.assert_called_once_with(['ss','-lntp'],timeout=6)
with mock.patch.object(audit,'command',return_value=_fake_ss('''LISTEN 0 128 [::]:1514 [::]:* users:(("wazuh-remoted",pid=12,fd=2))
''')):
    assert t._wazuh_owns_tcp_1514() is True
BAD = [
    GCP_SS.replace('wazuh-remoted','nginx'),
    GCP_SS.replace('wazuh-remoted','fake-wazuh-remoted'),
    GCP_SS.replace('0.0.0.0:1514','0.0.0.0:15140'),
    GCP_SS.replace('users:(("wazuh-remoted",pid=3238690,fd=4))','-'),
    GCP_SS.replace('users:(("wazuh-remoted",pid=3238690,fd=4))','users:(("wazuh-remoted",fd=4))'),
    GCP_SS.replace('0.0.0.0:1514','0.0.0.0:1515').replace('0.0.0.0:*','0.0.0.0:1514'),
    GCP_SS+'LISTEN 0 128 [::]:1514 [::]:* users:(("nginx",pid=13,fd=2))\n',
]
for case in BAD:
    with mock.patch.object(audit,'command',return_value=_fake_ss(case)):
        assert t._wazuh_owns_tcp_1514() is False,case
with mock.patch.object(audit,'command',return_value=_fake_ss(GCP_SS,rc=1)):
    assert t._wazuh_owns_tcp_1514() is False

# Executed as a file, ops.audit_v42 is a different Python module from
# __main__. The guardrail must yield a clean CLI error, not a traceback.
import io,runpy
from contextlib import redirect_stderr,redirect_stdout
old_argv=sys.argv[:]
try:
    sys.argv=[str(ROOT/'ops/audit_v42.py'),'tenzir','--disable-pipelines','--confirm']
    with mock.patch.object(t,'disable_pipelines',side_effect=audit.AuditError('Protection Wazuh 1514')):
        out,err=io.StringIO(),io.StringIO()
        with redirect_stdout(out),redirect_stderr(err):
            try:
                runpy.run_path(str(ROOT/'ops/audit_v42.py'),run_name='__main__')
                raise AssertionError('Unexpected successful CLI exit')
            except SystemExit as exc:assert exc.code==2,exc.code
        assert 'AEGISMESH AUDIT:' in err.getvalue(),err.getvalue()
        assert 'Traceback' not in err.getvalue(),err.getvalue()
finally:
    sys.argv=old_argv
print('PASS: V4.2.3 exact Wazuh TCP 1514 ownership and clean fail-closed CLI errors')
