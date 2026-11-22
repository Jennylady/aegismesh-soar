#!/usr/bin/env python3
"""Tests isolated to a temporary directory; never call Docker or Wazuh."""
from pathlib import Path
import sys, tempfile, copy
from unittest import mock
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from ops import tenzir_conflict_v422 as t
from ops import audit_v42 as audit

# A normalized Compose diff must only change Orborus pipeline variables.
before={'name':'aegismesh-shuffle','services': {'orborus': {'environment':{'BASE_URL':'http://backend:5001'},'image':'x'},'frontend':{'image':'y'}}}
after=copy.deepcopy(before)
after['services']['orborus']['environment'].update(t.FLAG_VALUES)
t.service_config_check(before,after)
wrong=copy.deepcopy(after);wrong['services']['frontend']['image']='new'
try:t.service_config_check(before,wrong);raise AssertionError('Unrelated service change accepted')
except audit.AuditError:pass
wrong=copy.deepcopy(after);wrong['services']['orborus']['environment']['BASE_URL']='http://other'
try:t.service_config_check(before,wrong);raise AssertionError('Other env change accepted')
except audit.AuditError:pass
wrong=copy.deepcopy(after);wrong['name']='other-project'
try:t.service_config_check(before,wrong);raise AssertionError('Project name change accepted')
except audit.AuditError:pass

# V4.2.4: production path no longer parses or rewrites the base YAML. The
# complete Compose config is validated before any Docker action, and an
# override supplies only Orborus environment flags.
with tempfile.TemporaryDirectory() as temp:
    folder=Path(temp)
    compose=folder/'compose.yaml'
    # Valid service YAML whose original indentation is NOT accepted by the old
    # two-space regular expression; the new override method doesn't care.
    unusual_yaml='''services:
    backend:
        image: shuffle/backend
    orborus:
        image: shuffle/orborus
        environment: [BASE_URL=http://backend:5001]
    frontend:
        image: shuffle/frontend
'''
    compose.write_text(unusual_yaml,encoding='utf-8')
    override=folder/'compose.aegismesh-soar.override.yaml'
    backup_dir=folder/'backups'
    config_before={'name':'aegismesh-shuffle','services': {'orborus': {'environment':{'BASE_URL':'http://backend:5001'},'image':'x'},'frontend':{'image':'y'},'backend':{'image':'z'}}}
    config_after=copy.deepcopy(config_before)
    config_after['services']['orborus']['environment'].update(t.FLAG_VALUES)
    def config_probe(p=None):return config_after if p is not None else config_before
    def fake_obj(*_):return {'Config':{'Env':([k+'='+v for k,v in t.FLAG_VALUES.items()] if override.exists() else [])},'State':{'Status':'running'}}
    common=[mock.patch.object(t,'COMPOSE',compose),mock.patch.object(t,'OVERRIDE',override),
            mock.patch.object(t,'BACKUPS',backup_dir),
            mock.patch.object(t,'_container_composition_ok',return_value=True),
            mock.patch.object(t,'_wazuh_owns_tcp_1514',return_value=True),
            mock.patch.object(t,'_running_container',return_value=True),
            mock.patch.object(audit,'tenzir_status',return_value={'state':'broken_missing_network'}),
            mock.patch.object(t,'compose_config',side_effect=config_probe),
            mock.patch.object(audit,'docker_object',side_effect=fake_obj),
            mock.patch.object(audit,'command',return_value=mock.Mock(returncode=0,stdout='',stderr='')),
            mock.patch.object(t.time,'sleep',return_value=None),
            mock.patch.object(t.os,'geteuid',return_value=0)]
    for patch in common:patch.start()
    try:
        try:t.disable_pipelines(confirm=False);raise AssertionError('Missing confirmation accepted')
        except audit.AuditError:pass
        with mock.patch.object(audit,'checked',return_value='') as checked:
            result=t.disable_pipelines(confirm=True,wait_seconds=0)
            assert result['status']=='pipelines_disabled'
            assert checked.call_count==1
            cmd=checked.call_args.args[0]
            assert cmd[-3:]==['--no-deps','--no-build','orborus']
            assert cmd[:6]==['docker','compose','-f',str(compose),'-f',str(override)]
            assert 'SHUFFLE_SKIP_PIPELINES' in override.read_text()
            assert compose.read_text()==unusual_yaml  # not one byte of base changed
            backups=list(backup_dir.glob('*.yaml'))
            assert len(backups)==1 and backups[0].read_text()==unusual_yaml
        # A repeat should not overwrite an existing operator-owned override.
        override.write_text('services: {}',encoding='utf-8')
        try:t.disable_pipelines(confirm=True,wait_seconds=0);raise AssertionError('Custom override accepted')
        except audit.AuditError:pass
        assert override.read_text()=='services: {}'
        override.unlink()
        with mock.patch.object(audit,'checked',side_effect=audit.AuditError('simulated failed update')):
            try:t.disable_pipelines(confirm=True,wait_seconds=0);raise AssertionError('Broken restart accepted')
            except audit.AuditError as exc:assert 'retour' in str(exc)
            assert compose.read_text()==unusual_yaml
            assert not override.exists()  # automatic rollback
        # Reject a merged Compose config that changes anything unrelated.
        changed=copy.deepcopy(config_after)
        changed['services']['backend']['image']='different'
        with mock.patch.object(t,'compose_config',side_effect=lambda p=None: changed if p is not None else config_before):
            with mock.patch.object(audit,'checked') as checked:
                try:t.disable_pipelines(confirm=True,wait_seconds=0);raise AssertionError('Changed backend accepted')
                except audit.AuditError:pass
                checked.assert_not_called()
                assert not override.exists()
    finally:
        for patch in reversed(common):patch.stop()
print('PASS: V4.2.4 override-only mode, arbitrary base indentation, guarded merge and rollback')

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

# V4.2.4 Compose label identity: accept the known base and an optional exact
# managed override only, never a neighboring Compose project or extra file.
fake_labels={
    'com.docker.compose.project':t.PROJECT,
    'com.docker.compose.service':t.SERVICE,
    'com.docker.compose.project.config_files':str(t.COMPOSE),
}
with mock.patch.object(audit,'docker_object',return_value={'Config':{'Labels':fake_labels}}):
    assert t._container_composition_ok(expect_override=False)
    assert not t._container_composition_ok(expect_override=True)
fake_labels['com.docker.compose.project.config_files']=str(t.COMPOSE)+','+str(t.OVERRIDE)
with mock.patch.object(audit,'docker_object',return_value={'Config':{'Labels':fake_labels}}):
    assert t._container_composition_ok(expect_override=True)
fake_labels['com.docker.compose.project.config_files']+=',/tmp/unrelated.yaml'
with mock.patch.object(audit,'docker_object',return_value={'Config':{'Labels':fake_labels}}):
    assert not t._container_composition_ok()
print('PASS: V4.2.4 exact Compose ownership and override labels')
