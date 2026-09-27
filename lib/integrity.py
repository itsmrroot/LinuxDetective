# =============================================================================
#  Linux Detective - Package integrity sweep & setuid / setgid inventory
#  Powered by Bashar Salmo
#  LD-SELF-MARKER
#
#  Compares every executable and shared library in the system directories
#  with the package database (dpkg / rpm / apk / pacman), and inventories
#  every setuid / setgid file on the filesystem.
# =============================================================================

import os
import re
import stat

from . import core

BIN_DIRS = ['/usr/bin', '/usr/sbin', '/bin', '/sbin']
LIB_DIRS = ['/usr/lib', '/usr/lib64', '/usr/lib32', '/lib', '/lib64', '/lib32', '/usr/libexec']
SO_RX = re.compile(r'\.so(\.\d+)*$')

# Pseudo filesystems and container storage are skipped by the full-disk setuid sweep.
SKIP_TREES = ['/proc', '/sys', '/dev', '/run', '/var/lib/docker', '/var/lib/containers', '/snap',
              '/var/lib/snapd/snap', '/var/lib/lxc', '/var/lib/lxd']
EXTRA_TREES = ['/dev/shm', '/run/user', '/run/shm']


NETWORK_FS = {'nfs', 'nfs4', 'cifs', 'smb3', 'smbfs', 'fuse.sshfs', 'sshfs', 'ceph', 'glusterfs', 'fuse.glusterfs',
              'afs', '9p', 'fuse.rclone', 'fuse.s3fs', 'davfs', 'fuse.davfs2'}


def network_mounts():
    """Mount points of network filesystems (live host only): never crawled."""
    out = set()
    if not core.CTX.live:
        return out
    for line in (core.read_proc('/proc/self/mounts') or '').splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] in NETWORK_FS:
            out.add(parts[1].replace('\\040', ' '))
    return out


def _unique_dirs(dirs):
    """Drops directories that are the same place (merged /usr: /bin -> /usr/bin)."""
    seen, out = set(), []
    for d in dirs:
        if not core.isdir(d):
            continue
        real = os.path.realpath(core.phys(d))
        if real in seen:
            continue
        seen.add(real)
        out.append(d)
    return out


def _row(path, st, owner, state, note=''):
    info = core.file_info(path)
    return {'Path': path, 'Package': owner, 'Version': core.pkg().installed.get(owner, '') if owner else '',
            'State': state, 'Mode': stat.filemode(st.st_mode), 'Owner': core.user_name(st.st_uid), 'Size': st.st_size,
            'ModifiedUtc': core.ts(st.st_mtime), 'ChangedUtc': core.ts(st.st_ctime), 'SHA256': info['SHA256'], 'Note': note}


def _evidence(r):
    return 'path=%s | package=%s %s | sha256=%s | size=%s | mtime=%s | ctime=%s | mode=%s | owner=%s' % (
        r['Path'], r['Package'] or '-', r['Version'], r['SHA256'] or '-', r['Size'], r['ModifiedUtc'], r['ChangedUtc'],
        r['Mode'], r['Owner'])


def _candidate_files(quick):
    """(path, lstat, kind) for executables in bin dirs and ELF shared objects in lib dirs."""
    for d in _unique_dirs(BIN_DIRS):
        for name in core.listdir(d):
            p = d.rstrip('/') + '/' + name
            st = core.lstat(p)
            if st is not None and (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
                yield p, st, 'bin'
    if quick:
        return
    for d in _unique_dirs(LIB_DIRS):
        for p, st in core.walk(d, max_depth=1, max_files=500000):
            if stat.S_ISREG(st.st_mode) and SO_RX.search(p) and '/modules/' not in p:
                yield p, st, 'lib'


def sweep():
    ctx = core.CTX
    db = core.pkg()
    if not db.kind or not db.available():
        core.log('No readable package database - integrity sweep skipped (%s)' % (db.error or 'none found'), 'WARN')
        core.add_finding('Info', 'Visibility', 'Package integrity could not be checked',
                         'No readable package database was found, so modified or unpackaged system files cannot be detected.',
                         db.error or 'package manager: ' + (db.kind or 'not detected'))
        return
    modified, unowned, checked, verified = [], [], 0, 0
    for p, st, kind in _candidate_files(ctx.opts.get('quick')):
        if core.is_self_text(p):
            continue
        checked += 1
        if stat.S_ISLNK(st.st_mode):
            if not db.owner(p):
                target = core.proc_readlink(core.phys_nofollow(p))
                resolved = target if target.startswith('/') else os.path.normpath(os.path.dirname(p) + '/' + target)
                if core.path_risk(resolved) == 'High':
                    r = _row(p, st, '', 'symlink', 'points to ' + target)
                    unowned.append(r)
                    core.add_finding('High', 'Integrity', 'System command is a symlink into a temporary or hidden location',
                                     'Commands in system directories should never resolve to world-writable or hidden paths.',
                                     _evidence(r) + ' | target=' + target, 'T1036.005', st.st_ctime, 'Package integrity')
            continue
        owner = db.owner(p)
        if owner:
            state = db.verify(p)
            if state:
                verified += 1
            if state == 'modified':
                r = _row(p, st, owner, 'modified', db.diversion(p))
                modified.append(r)
                core.flag_file(p, 'differs from package ' + owner)
                sev = 'High'
                core.add_finding(sev, 'Integrity', 'Packaged system file has been modified',
                                 'The file no longer matches the digest shipped by package %s. Compare it with a clean copy of '
                                 'the same package version before trusting any output of this program.' % owner,
                                 _evidence(r), 'T1554', st.st_ctime, 'Package integrity')
            continue
        # Not owned by any package
        if kind == 'bin' and not (st.st_mode & 0o111) and not core.file_info(p)['IsELF']:
            continue  # plain data file, e.g. a README dropped by an installer
        if kind == 'lib' and not core.file_info(p)['IsELF']:
            continue
        note = db.diversion(p)
        r = _row(p, st, '', 'unowned', note)
        unowned.append(r)
        core.flag_file(p, 'not owned by any package')
        recent = core.in_window(st.st_ctime) or core.in_window(st.st_mtime)
        if note:
            core.add_finding('Low', 'Integrity', 'System file replaced through a local dpkg diversion',
                             'An administrator (or installer) diverted the packaged file. Confirm the diversion is expected: %s.' % note,
                             _evidence(r), 'T1554', st.st_ctime, 'Package integrity')
            continue
        what = 'Executable' if kind == 'bin' else 'Shared library'
        detail = 'No installed package owns this file. Software installed outside the package manager lives in /usr/local or ' \
                 '/opt; a file here was placed by hand, by an installer script, or by an intruder.'
        if recent:
            detail += ' It was created or changed within the investigation window.'
        core.add_finding('High' if recent else 'Medium', 'Integrity',
                         '%s in a system directory is not owned by any package' % what,
                         detail, _evidence(r), 'T1036.005', st.st_ctime, 'Package integrity')
    core.save_artifact('ModifiedPackageFiles', 'Integrity', modified, 'System files that differ from the digest their package shipped')
    core.save_artifact('UnownedSystemFiles', 'Integrity', unowned, 'Executables and libraries in system directories that no package owns')
    ctx.system_info['Integrity sweep'] = '%d files checked, %d verified against package digests, %d modified, %d unowned' % (
        checked, verified, len(modified), len(unowned))
    core.log('Integrity: %d files checked, %d verified, %d modified, %d unowned' % (checked, verified, len(modified), len(unowned)),
             'OK' if not modified else 'WARN')


def setuid_inventory():
    ctx = core.CTX
    db = core.pkg()
    have_db = bool(db.kind) and db.available()
    quick = ctx.opts.get('quick')
    tops = ['/'] if not quick else _unique_dirs(BIN_DIRS + LIB_DIRS + ['/usr/local', '/opt', '/home', '/root', '/tmp', '/var/tmp'])
    skip = set(SKIP_TREES) | network_mounts()
    for c in (ctx.case_dir, ctx.opts.get('tool_root')):
        if c:
            skip.add(core.logical(c))
    rows, seen = [], set()
    max_files = ctx.opts.get('max_files', 3000000)
    trees = tops + ([t for t in EXTRA_TREES if core.isdir(t)] if ctx.live else [])
    for top in trees:
        for p, st in core.walk(top, max_depth=64, max_files=max_files, skip=skip):
            if not stat.S_ISREG(st.st_mode) or not (st.st_mode & (stat.S_ISUID | stat.S_ISGID)):
                continue
            key = (st.st_dev, st.st_ino)
            if key in seen:
                continue
            seen.add(key)
            owner = db.owner(p) if have_db else ''
            state = db.verify(p) if owner else ''
            kind = 'setuid' if st.st_mode & stat.S_ISUID else 'setgid'
            r = _row(p, st, owner, state or ('unowned' if have_db and not owner else 'unknown'), kind)
            rows.append(r)
            ev = _evidence(r)
            risk = core.path_risk(p)
            if owner and state == 'modified':
                core.flag_file(p, 'setuid/setgid file differs from package')
                core.add_finding('Critical', 'Integrity', 'Setuid / setgid file differs from its package',
                                 'A privileged program no longer matches package %s. A modified setuid binary is a classic backdoor '
                                 'that grants root to whoever knows how to trigger it.' % owner, ev, 'T1548.001,T1554', st.st_ctime,
                                 'Setuid inventory')
            elif have_db and not owner:
                core.flag_file(p, 'unowned setuid/setgid file')
                sev = 'High'
                if risk == 'None' and re.match(r'^/(opt|usr/local)/', p):
                    sev = 'Medium'
                core.add_finding(sev, 'Integrity', 'Setuid / setgid file not owned by any package',
                                 'Every %s file runs with the rights of its owner (%s). Confirm which software installed it.' % (
                                     kind, r['Owner']) + (' It sits in a high-risk location.' if risk == 'High' else ''),
                                 ev, 'T1548.001', st.st_ctime, 'Setuid inventory')
            if st.st_mode & stat.S_IWOTH:
                core.add_finding('High', 'Integrity', 'Setuid / setgid file is writable by every user',
                                 'Anyone can replace the contents of this privileged program.', ev, 'T1548.001', st.st_ctime,
                                 'Setuid inventory')
    core.save_artifact('SetuidSetgidFiles', 'Integrity', rows, 'Every setuid / setgid file with its package and verification state')
    ctx.system_info['Setuid / setgid files'] = str(len(rows))
    core.log('Setuid / setgid inventory: %d files' % len(rows), 'INFO')
