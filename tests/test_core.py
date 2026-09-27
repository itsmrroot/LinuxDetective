#!/usr/bin/env python3
# =============================================================================
#  Linux Detective - engine self test (Powered by Bashar Salmo)
#  Runs on any OS with Python 3.6+ and never touches the host: every file it
#  reads lives in a temporary fake "mounted image".
#      python3 -B tests/test_core.py
# =============================================================================

import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

sys.dont_write_bytecode = True
TOOL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOL_ROOT)

from lib import core, rules  # noqa: E402


def write(root, path, data, mode=None):
    p = os.path.join(root, path.lstrip('/'))
    d = os.path.dirname(p)
    if not os.path.isdir(d):
        os.makedirs(d)
    with open(p, 'wb') as fh:
        fh.write(data.encode() if isinstance(data, str) else data)
    if mode is not None:
        os.chmod(p, mode)
    return p


class ImageTestCase(unittest.TestCase):
    """A fake Debian-style image with usrmerge symlinks and a dpkg database."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='ld_test_')
        self.root = os.path.join(self.tmp, 'img')
        os.makedirs(self.root)
        r = self.root
        write(r, '/usr/bin/ls', b'\x7fELF-genuine-ls')
        write(r, '/usr/bin/tool', b'unowned')
        write(r, '/usr/sbin/tool', b'a different file')
        os.symlink('usr/bin', os.path.join(r, 'bin'))           # usrmerge: /bin -> usr/bin
        os.symlink('/usr/bin/ls', os.path.join(r, 'usr/bin/dir'))  # absolute symlink inside the image
        write(r, '/etc/passwd', 'root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n')
        os.makedirs(os.path.join(r, 'root'))
        os.makedirs(os.path.join(r, 'home/bob'))
        write(r, '/var/lib/dpkg/info/coreutils.list', '/.\n/bin\n/bin/ls\n')
        write(r, '/var/lib/dpkg/info/coreutils.md5sums', hashlib.md5(b'\x7fELF-genuine-ls').hexdigest() + '  bin/ls\n')
        write(r, '/var/lib/dpkg/info/other.list', '/usr/bin/tool\n')
        write(r, '/var/lib/dpkg/status', 'Package: coreutils\nVersion: 9.4-1\n\nPackage: other\nVersion: 1.0\n')
        self.case = os.path.join(self.tmp, 'case')
        os.makedirs(self.case)
        core.new_context({'root': self.root, 'days': 30, 'tool_root': TOOL_ROOT, 'max_hash_bytes': 1024 * 1024})
        core.CTX.case_dir = self.case

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TimeAndText(unittest.TestCase):
    def setUp(self):
        core.new_context({'root': '/', 'days': 30, 'tool_root': TOOL_ROOT})

    def test_ts(self):
        self.assertEqual(core.ts(0), '')
        self.assertEqual(core.ts(None), '')
        self.assertEqual(core.ts(1700000000), '2023-11-14 22:13:20')
        self.assertEqual(core.ts('1700000000'), '2023-11-14 22:13:20')
        self.assertEqual(core.ts('2023-11-14 22:13:20'), '2023-11-14 22:13:20')
        self.assertEqual(core.ts('garbage'), '')

    def test_limit(self):
        self.assertEqual(core.limit(None), '')
        self.assertTrue(core.limit('x' * 50, 10).endswith('[truncated]'))

    def test_printable(self):
        self.assertEqual(core.printable(b'a\x00b'), 'a\\x00b')

    def test_public_ip(self):
        self.assertTrue(core.is_public_ip('8.8.8.8'))
        self.assertTrue(core.is_public_ip('::ffff:8.8.8.8'))
        for ip in ('10.1.2.3', '192.168.1.1', '172.20.0.1', '127.0.0.1', '169.254.1.1', '100.64.0.1',
                   '::1', 'fe80::1%eth0', '0.0.0.0', '', '-', 'not-an-ip'):
            self.assertFalse(core.is_public_ip(ip), ip)


class Findings(unittest.TestCase):
    def setUp(self):
        core.new_context({'root': '/', 'days': 30, 'tool_root': TOOL_ROOT})

    def test_grouping(self):
        core.add_finding('Medium', 'Cat', 'Same thing', evidence='job_1234 ran', when=1700000000)
        core.add_finding('High', 'Cat', 'Same thing', evidence='job_5678 ran', when=1700000100)
        self.assertEqual(len(core.CTX.findings), 1)
        f = core.CTX.findings[0]
        self.assertEqual(f['Occurrences'], 2)
        self.assertEqual(f['Severity'], 'High')
        self.assertEqual(f['FirstSeen'], '2023-11-14 22:13:20')
        self.assertEqual(f['LastSeen'], '2023-11-14 22:15:00')

    def test_timeline_from_finding(self):
        core.add_finding('High', 'Cat', 'Timed', when=1700000000)
        core.add_finding('Info', 'Cat', 'Info only', when=1700000000)
        self.assertEqual(len(core.CTX.timeline), 1)

    def test_allowlist(self):
        path = os.path.join(tempfile.mkdtemp(), 'allow.txt')
        with open(path, 'w') as fh:
            fh.write('# comment\npath:/opt/backup/* | backup agent\nhash:' + 'a' * 64 + '\n')
        self.assertEqual(core.import_allowlist(path), 2)
        f = core.add_finding('High', 'Cat', 'Thing', evidence='/opt/backup/run.sh')
        self.assertEqual(f['Severity'], 'Info')
        self.assertTrue(f['Allowlisted'])
        self.assertEqual(f['OriginalSeverity'], 'High')
        self.assertIn('backup agent', f['Detail'])
        g = core.add_finding('High', 'Cat', 'Other', evidence='sha256 ' + 'A' * 64)
        self.assertTrue(g['Allowlisted'])
        h = core.add_finding('High', 'Cat', 'Not allowlisted', evidence='/usr/bin/x')
        self.assertEqual(h['Severity'], 'High')

    def test_self_exclusion(self):
        core.CTX.case_dir = '/mnt/usb/Reports/LDCase_web01_20260101_101010'
        self.assertTrue(core.is_self_text('cp x /mnt/usb/Reports/LDCase_web01_20260101_101010/raw'))
        self.assertTrue(core.is_self_text('tar xf /media/LDCase_db-2_20250505_050505.tar.gz'))
        self.assertTrue(core.is_self_text(TOOL_ROOT + '/lib/core.py'))
        # Mentioning the tool's name must not hide anything
        self.assertFalse(core.is_self_text('LinuxDetective LD-SELF-MARKER LDCase_'))


class ImagePaths(ImageTestCase):
    def test_absolute_symlink_stays_inside_image(self):
        self.assertEqual(core.phys('/usr/bin/dir'), self.root + '/usr/bin/ls')
        self.assertEqual(core.phys('/bin/ls'), self.root + '/usr/bin/ls')
        self.assertEqual(core.read_bytes('/usr/bin/dir'), b'\x7fELF-genuine-ls')

    def test_logical(self):
        self.assertEqual(core.logical(self.root + '/etc/passwd'), '/etc/passwd')
        self.assertEqual(core.logical(self.root), '/')
        # A sibling folder that merely starts with the same name is not inside the image
        self.assertEqual(core.logical(self.root + '2/etc/passwd'), self.root + '2/etc/passwd')

    def test_lstat_does_not_follow_last_symlink(self):
        os.symlink('/tmp/.x/payload', os.path.join(self.root, 'usr/bin/dangling'))
        st = core.lstat('/usr/bin/dangling')
        self.assertIsNotNone(st)
        import stat as st_mod
        self.assertTrue(st_mod.S_ISLNK(st.st_mode))
        self.assertTrue(core.exists('/usr/bin/dangling'))
        self.assertTrue(core.exists('/bin/dangling'))  # parent symlink (/bin -> usr/bin) is still resolved
        self.assertEqual(os.readlink(core.phys_nofollow('/bin/dangling')), '/tmp/.x/payload')

    def test_dotdot_cannot_escape(self):
        self.assertTrue(core.phys('/../../../etc/passwd').startswith(self.root))

    def test_walk(self):
        seen = set(p for p, st in core.walk('/usr'))
        self.assertIn('/usr/bin/ls', seen)
        self.assertIn('/usr/sbin/tool', seen)

    def test_users(self):
        names = [u['name'] for u in core.load_users()]
        self.assertEqual(names, ['root', 'bob'])
        self.assertEqual(core.user_name(1000), 'bob')
        self.assertEqual(core.user_name(4242), '4242')
        homes = [h for u, h in core.user_homes()]
        self.assertEqual(homes, ['/root', '/home/bob'])

    def test_fifo_does_not_block(self):
        if not hasattr(os, 'mkfifo'):
            self.skipTest('no FIFOs on this OS')
        os.mkfifo(os.path.join(self.root, 'tmp_fifo'))
        result = {}
        t = threading.Thread(target=lambda: result.setdefault('v', core.read_bytes('/tmp_fifo')))
        t.daemon = True
        t.start()
        t.join(3)
        self.assertFalse(t.is_alive(), 'read_bytes blocked on a FIFO')
        self.assertIsNone(result.get('v'))

    def test_gzip(self):
        import gzip
        write(self.root, '/var/log/x.log.1.gz', gzip.compress(b'line1\nline2\n'))
        self.assertEqual(core.read_lines('/var/log/x.log.1.gz'), ['line1', 'line2'])

    def test_file_info_and_hashes(self):
        info = core.file_info('/usr/bin/ls')
        self.assertTrue(info['Exists'])
        self.assertTrue(info['IsELF'])
        self.assertEqual(info['SHA256'], hashlib.sha256(b'\x7fELF-genuine-ls').hexdigest())
        self.assertEqual(info['Package'], 'coreutils')
        self.assertIn(info['SHA256'], core.CTX.observed['hashes'])
        self.assertFalse(core.file_info('/nope')['Exists'])


class PackageDatabase(ImageTestCase):
    def test_dpkg_owner_through_usrmerge(self):
        p = core.pkg()
        self.assertEqual(p.kind, 'dpkg')
        self.assertEqual(p.owner('/usr/bin/ls'), 'coreutils')
        self.assertEqual(p.owner('/bin/ls'), 'coreutils')
        self.assertEqual(p.installed.get('coreutils'), '9.4-1')

    def test_alias_does_not_borrow_owner_of_a_different_file(self):
        # /usr/sbin/tool and /usr/bin/tool are two different files; only /usr/bin/tool is packaged.
        self.assertEqual(core.pkg().owner('/usr/bin/tool'), 'other')
        self.assertEqual(core.pkg().owner('/usr/sbin/tool'), '')
        self.assertTrue(core.pkg_unowned('/usr/sbin/tool'))

    def test_verify(self):
        p = core.pkg()
        self.assertEqual(p.verify('/usr/bin/ls'), 'ok')
        write(self.root, '/usr/bin/ls', b'\x7fELF-modified')
        self.assertEqual(p.verify('/usr/bin/ls'), 'modified')
        self.assertEqual(p.verify('/usr/bin/tool'), '')  # no digest shipped

    def test_verify_cache_notices_changes(self):
        p = core.pkg()
        self.assertEqual(p.verify('/usr/bin/ls'), 'ok')
        self.assertEqual(p.verify('/usr/bin/ls'), 'ok')  # served from cache
        time.sleep(0.01)
        write(self.root, '/usr/bin/ls', b'\x7fELF-modified!')  # different size and mtime
        self.assertEqual(p.verify('/usr/bin/ls'), 'modified')

    def test_dpkg_diversions(self):
        r = self.root
        # A local diversion (like Ubuntu's container "man" stub) and a package diversion
        write(r, '/usr/bin/man', b'#!/bin/sh\necho stub\n')
        write(r, '/usr/bin/man.REAL', b'real man')
        write(r, '/usr/bin/fmt', b'fmt from wrapper')
        write(r, '/usr/bin/fmt.distrib', b'fmt from coreutils')
        write(r, '/var/lib/dpkg/diversions',
              '/usr/bin/man\n/usr/bin/man.REAL\n:\n/usr/bin/fmt\n/usr/bin/fmt.distrib\nwrapper\n')
        write(r, '/var/lib/dpkg/info/man-db.list', '/usr/bin/man\n')
        write(r, '/var/lib/dpkg/info/man-db.md5sums', hashlib.md5(b'real man').hexdigest() + '  usr/bin/man\n')
        write(r, '/var/lib/dpkg/info/coreutils.list', '/.\n/bin\n/bin/ls\n/usr/bin/fmt\n')
        write(r, '/var/lib/dpkg/info/coreutils.md5sums', hashlib.md5(b'\x7fELF-genuine-ls').hexdigest() + '  bin/ls\n' +
              hashlib.md5(b'fmt from coreutils').hexdigest() + '  usr/bin/fmt\n')
        write(r, '/var/lib/dpkg/info/wrapper.list', '/usr/bin/fmt\n')
        write(r, '/var/lib/dpkg/info/wrapper.md5sums', hashlib.md5(b'fmt from wrapper').hexdigest() + '  usr/bin/fmt\n')
        core.CTX.pkg = None
        p = core.pkg()
        self.assertEqual(p.owner('/usr/bin/man'), '')           # local stub: really unpackaged
        self.assertIn('local diversion', p.diversion('/usr/bin/man'))
        self.assertEqual(p.owner('/usr/bin/man.REAL'), 'man-db')
        self.assertEqual(p.verify('/usr/bin/man.REAL'), 'ok')
        self.assertEqual(p.verify('/usr/bin/man'), '')          # no digest for a local stub
        self.assertEqual(p.owner('/usr/bin/fmt'), 'wrapper')
        self.assertEqual(p.verify('/usr/bin/fmt'), 'ok')
        self.assertEqual(p.owner('/usr/bin/fmt.distrib'), 'coreutils')
        self.assertEqual(p.verify('/usr/bin/fmt.distrib'), 'ok')
        write(r, '/usr/bin/fmt.distrib', b'tampered')
        self.assertEqual(p.verify('/usr/bin/fmt.distrib'), 'modified')

    def test_apk(self):
        shutil.rmtree(os.path.join(self.root, 'var/lib/dpkg'))
        import base64
        sha1 = hashlib.sha1(b'\x7fELF-genuine-ls').digest()
        write(self.root, '/lib/apk/db/installed',
              'P:busybox\nV:1.36\nF:usr/bin\nR:ls\nZ:Q1' + base64.b64encode(sha1).decode() + '\nR:other\n\n'
              'P:musl\nV:1.2\nF:lib\nR:ld-musl.so.1\n')
        core.CTX.pkg = None
        p = core.pkg()
        self.assertEqual(p.kind, 'apk')
        self.assertEqual(p.owner('/usr/bin/ls'), 'busybox')
        self.assertEqual(p.owner('/lib/ld-musl.so.1'), 'musl')
        self.assertEqual(p.verify('/usr/bin/ls'), 'ok')
        self.assertEqual(p.verify('/usr/bin/other'), '')  # the digest of ls must not stick to the next file

    def test_pacman(self):
        shutil.rmtree(os.path.join(self.root, 'var/lib/dpkg'))
        write(self.root, '/var/lib/pacman/local/ALPM_DB_VERSION', '9\n')
        write(self.root, '/var/lib/pacman/local/coreutils-9.5-1/files', '%FILES%\nusr/\nusr/bin/\nusr/bin/ls\n\n%BACKUP%\n')
        write(self.root, '/var/lib/pacman/local/python-pip-24.0-2/files', '%FILES%\nusr/bin/pip\n')
        import gzip
        mtree = '#mtree\n/set type=file uid=0 gid=0 mode=644\n./usr/bin/ls time=1.0 mode=755 size=15 sha256digest=%s\n' % \
            hashlib.sha256(b'\x7fELF-genuine-ls').hexdigest()
        write(self.root, '/var/lib/pacman/local/coreutils-9.5-1/mtree', gzip.compress(mtree.encode()))
        core.CTX.pkg = None
        p = core.pkg()
        self.assertEqual(p.kind, 'pacman')
        self.assertEqual(p.owner('/usr/bin/ls'), 'coreutils')
        self.assertEqual(p.owner('/bin/ls'), 'coreutils')
        self.assertEqual(p.owner('/usr/bin/pip'), 'python-pip')
        self.assertEqual(p.installed.get('python-pip'), '24.0-2')
        self.assertNotIn('ALPM_DB_VERSION', p.installed)
        self.assertEqual(p.verify('/usr/bin/ls'), 'ok')
        write(self.root, '/usr/bin/ls', b'\x7fELF-modified')
        self.assertEqual(p.verify('/usr/bin/ls'), 'modified')

    def test_no_database(self):
        shutil.rmtree(os.path.join(self.root, 'var/lib/dpkg'))
        core.CTX.pkg = None
        self.assertEqual(core.pkg().kind, '')
        self.assertFalse(core.pkg_unowned('/usr/bin/ls'))  # unknown is not "unowned"


class Rules(unittest.TestCase):
    def setUp(self):
        core.new_context({'root': '/', 'days': 30, 'tool_root': TOOL_ROOT})
        self.dir = tempfile.mkdtemp()

    def test_load_and_check(self):
        path = os.path.join(self.dir, 'r.json')
        with open(path, 'w') as fh:
            json.dump({'commandRules': [
                {'id': 'T-1', 'severity': 'Medium', 'mitre': 'T1059.004', 'title': 'Test rule', 'pattern': r'\bhello-marker\b'},
                {'id': 'T-2', 'severity': 'High', 'title': 'Broken', 'pattern': '(unclosed'}]}, fh)
        self.assertEqual(rules.load(path), 1)
        self.assertEqual(rules.check_command('echo hello-marker', 'test'), 1)
        self.assertEqual(rules.check_command('echo nothing', 'test'), 0)
        self.assertEqual(core.CTX.findings[0]['Title'], 'Test rule')

    def test_missing_file_is_fine(self):
        self.assertEqual(rules.load(os.path.join(self.dir, 'missing.json')), 0)
        self.assertEqual(rules.check_command('anything', 'test'), 0)

    def test_repo_rule_file_is_valid(self):
        path = os.path.join(TOOL_ROOT, 'rules', 'detection-data.json')
        if os.path.isfile(path):
            with io.open(path, encoding='utf-8') as fh:
                n = len(json.load(fh).get('commandRules', []))
            self.assertEqual(rules.load(path), n)


if __name__ == '__main__':
    unittest.main(verbosity=1)
