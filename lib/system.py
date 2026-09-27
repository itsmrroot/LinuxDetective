# =============================================================================
#  Linux Detective - Host profile
#  Powered by Bashar Salmo
#  LD-SELF-MARKER
# =============================================================================

import os
import platform
import re
import socket

from . import core


def hostname():
    name = (core.read_text('/etc/hostname') or '').strip().split('\n')[0]
    if not name and core.CTX.live:
        name = socket.gethostname()
    return name or 'unknown-host'


def profile():
    info = core.CTX.system_info
    osr = {}
    for line in core.read_lines('/etc/os-release'):
        m = re.match(r'^([A-Z_]+)=(.*)$', line)
        if m:
            osr[m.group(1)] = m.group(2).strip().strip('"\'')
    info['Hostname'] = hostname()
    info['Operating system'] = osr.get('PRETTY_NAME') or osr.get('NAME') or 'unknown'
    info['Scan mode'] = 'Live host' if core.CTX.live else 'Mounted image at %s' % core.CTX.root
    info['Running as root'] = 'Yes' if core.CTX.is_root else 'No'
    db = core.pkg()
    info['Package manager'] = db.kind or 'not detected'
    if db.kind and db.available():
        info['Installed packages'] = str(len(db.installed))
        info['Files in package database'] = str(len(db.owners))
    if core.CTX.live:
        info['Kernel'] = platform.release()
        info['Architecture'] = platform.machine()
        bt = core.boot_time()
        if bt:
            info['Boot time (UTC)'] = core.ts(bt)
            core.add_timeline(bt, 'System', 'System boot')
        tz = (core.read_text('/etc/timezone') or '').strip()
        if not tz and os.path.islink('/etc/localtime'):
            tz = os.readlink('/etc/localtime').split('zoneinfo/')[-1]
        info['Timezone'] = tz or 'unknown'
        if os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv'):
            info['Container'] = 'Yes - results describe the container, not its host'
    else:
        kernels = core.listdir('/lib/modules') or core.listdir('/usr/lib/modules')
        info['Installed kernels'] = ', '.join(kernels) or 'unknown'
