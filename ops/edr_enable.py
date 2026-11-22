"""One-time, root-only EDR isolation allowlist, persisted outside Git checkout."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ENV = Path('/etc/aegismesh-soar/soar.env')
UNIT = 'aegismesh-soar-bridge.service'


def enable_isolation_agent(agent):
    if os.geteuid()!=0: raise PermissionError('root requis')
    if not re.fullmatch(r'\d{3}',agent) or agent in ('000','006'):
        raise PermissionError('Quarantaine du manager ou du DC refusée')
    if not ENV.is_file(): raise FileNotFoundError('SOAR env inexistant')
    before=ENV.read_text(encoding='utf-8')
    rows=before.splitlines()
    values={}
    for row in rows:
        if '=' in row and not row.lstrip().startswith('#'):
            key,val=row.split('=',1);values[key.strip()]=val.strip()
    authorized=set(filter(None,values.get('EDR_ISOLATION_AGENT_IDS','').split(',')))
    authorized.add(agent)
    updates={'EDR_ISOLATION_AGENT_IDS':','.join(sorted(authorized)),'ENABLE_EDR_ISOLATION':'true'}
    result=[]
    for row in rows:
        name=row.split('=',1)[0].strip()
        if name in updates and not row.lstrip().startswith('#'):
            result.append(name+'='+updates.pop(name))
        else:result.append(row)
    result.extend(k+'='+v for k,v in updates.items())
    fd,name=tempfile.mkstemp(prefix='.soar-edr-',dir=ENV.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as out:
            os.fchmod(out.fileno(),0o600)
            out.write('\n'.join(result)+'\n');out.flush();os.fsync(out.fileno())
        os.replace(name,ENV)
        p=subprocess.run(['systemctl','restart',UNIT],capture_output=True,text=True,timeout=20)
        if p.returncode:raise RuntimeError('Redémarrage du bridge a échoué')
        p=subprocess.run(['systemctl','is-active',UNIT],capture_output=True,text=True,timeout=5)
        if p.returncode or p.stdout.strip()!='active':raise RuntimeError('Bridge inactif')
    except Exception:
        # restore config, restart bridge, fail closed
        ENV.write_text(before,encoding='utf-8');os.chmod(ENV,0o600)
        subprocess.run(['systemctl','restart',UNIT],capture_output=True,timeout=15)
        raise
    finally:
        if os.path.exists(name):os.unlink(name)
