#!/usr/bin/env python3
"""Tests locaux de la politique; aucun UFW, Docker ou réseau réel modifié."""
import importlib.util,pathlib,subprocess,sys
p=pathlib.Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('repair',p/'ops/network_repair.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
network={'Name':'aegismesh-shuffle_shuffle','Driver':'bridge','Id':'c25f8eb733b12a03a7f5942b0a80b36181570396f8db88037d3a88f537a90077','IPAM':{'Config':[{'Subnet':'192.168.96.0/20','Gateway':'192.168.96.1'}]}}
interfaces=[{'ifname':'br-c25f8eb733b1','addr_info':[{'family':'inet','local':'192.168.96.1'}]}]
assert m.policy(network,'192.168.96.1',19081,interfaces)==('br-c25f8eb733b1','192.168.96.0/20','192.168.96.1')
rule=m.rule_args(*m.policy(network,'192.168.96.1',19081,interfaces))
assert '0.0.0.0' not in rule and 'br-c25f8eb733b1' in rule and '19081' in rule and 'AEGISMESH-SOAR-SHUFFLE' in rule[-1]
for bind,port in [('0.0.0.0',19081),('10.128.0.4',19081),('192.168.96.1',22)]:
    try: m.policy(network,bind,port,interfaces)
    except m.RepairError: pass
    else: raise AssertionError('policy accepted unsafe bind')
cli=p/'bin/aegismesh-soar'
res=subprocess.run([sys.executable,str(cli),'network','--help'],capture_output=True,text=True,timeout=10)
assert res.returncode==0 and '--repair-shuffle' in res.stdout and '--undo-shuffle' in res.stdout
print('PASS: règle UFW limitée à interface/subnet/gateway/port; refus bind public; CLI exposé')
