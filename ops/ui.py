#!/usr/bin/env python3
"""Small, dependency-free TTY UI; quiet noninteractive and NO_COLOR-aware."""
import os
import sys
import threading
import time

COLORS={'green':'\033[92m','red':'\033[91m','yellow':'\033[93m','cyan':'\033[96m','bold':'\033[1m','dim':'\033[2m'}
RESET='\033[0m'

def tty():
    return sys.stdout.isatty() and not os.getenv('NO_COLOR') and os.getenv('TERM','') not in ('dumb','')

def color(value, shade):
    return COLORS.get(shade,'')+str(value)+RESET if tty() else str(value)

def banner():
    if not sys.stdout.isatty(): return
    print(color('╭──────────────────────────────────────────────────╮','cyan'))
    print(color('│  ⛨  AEGISMESH  /  SOAR CONTROL CENTER       V4  │','cyan'))
    print(color('╰──────────────────────────────────────────────────╯','cyan'))
    print('   Shuffle  ·  Wazuh Active Response  ·  Fail2ban\n')

def info(s): print(color('  ◉ ','cyan')+str(s))
def ok(s): print(color('  ✔ ','green')+str(s))
def warn(s): print(color('  ! ','yellow')+str(s))
def error(s): print(color('  ✖ ','red')+str(s),file=sys.stderr)

def menu(title, options):
    print('\n'+color(title,'bold'))
    for key,label in options:
        print('  '+color(key,'cyan')+'  '+label)
    if not sys.stdin.isatty(): return None
    return input(color('Choix > ','green')).strip()

class Spinner:
    def __init__(self, label):
        self.label=label;self.stop_event=threading.Event();self.thread=None
    def __enter__(self):
        if not tty():
            print('... '+self.label,flush=True)
            return self
        def animate():
            chars='◐◓◑◒'; n=0
            while not self.stop_event.wait(0.12):
                sys.stdout.write('\r'+color('  '+chars[n%4]+' ','cyan')+self.label+'   ')
                sys.stdout.flush();n+=1
            sys.stdout.write('\r'+(' '*(len(self.label)+10))+'\r');sys.stdout.flush()
        self.thread=threading.Thread(target=animate,daemon=True);self.thread.start()
        return self
    def __exit__(self,*_):
        self.stop_event.set()
        if self.thread: self.thread.join(timeout=1)
