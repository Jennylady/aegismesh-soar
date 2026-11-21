#!/usr/bin/env python3
"""Le CLI publié doit rester exécutable à travers Git update."""
import pathlib, stat, subprocess, sys, os
root=pathlib.Path(__file__).resolve().parent.parent
cli=root/'bin/aegismesh-soar'
assert cli.stat().st_mode & stat.S_IXUSR, 'bin/aegismesh-soar a perdu le mode executable (Git 100644)'
p=subprocess.run([sys.executable,str(cli),'network','--help'],capture_output=True,text=True,timeout=10)
assert p.returncode==0 and '--check' in p.stdout, p.stderr
probe=root/'ops/network_probe.py'
assert probe.is_file()
p=subprocess.run([sys.executable,'-m','py_compile',str(probe)],capture_output=True,text=True,timeout=10)
assert p.returncode==0,p.stderr
print('PASS: CLI mode exécutable, network --check, syntaxe de la sonde')
