#!/usr/bin/env python3
# =============================================================================
#  Linux Detective - end-to-end scan test (Powered by Bashar Salmo)
#  Builds a fake Debian image with planted problems, runs the real CLI against
#  it in image mode and checks the findings and the case folder.
#      python3 -B tests/test_scan.py
# =============================================================================

import csv
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest

sys.dont_write_bytecode = True
TOOL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOL_ROOT)
sys.path.insert(0, os.path.join(TOOL_ROOT, 'tests'))

import linux_detective  # noqa: E402
from test_core import write  # noqa: E402

GOOD = {'/usr/bin/ls': b'\x7fELF ls', '/usr/bin/passwd': b'\x7fELF passwd', '/usr/lib/x86_64-linux-gnu/libc.so.6': b'\x7fELF libc'}


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='ld_scan_')
        r = cls.root = os.path.join(cls.tmp, 'img')
        os.makedirs(r)
        os.symlink('usr/bin', os.path.join(r, 'bin'))
        os.symlink('usr/lib', os.path.join(r, 'lib'))
        for p, data in GOOD.items():
            write(r, p, data, 0o755)
        os.chmod(os.path.join(r, 'usr/bin/passwd'), 0o4755)
        write(r, '/usr/bin/ls', b'\x7fELF ls, but modified', 0o755)          # modified packaged binary
        write(r, '/usr/sbin/sysmond', b'\x7fELF unknown', 0o755)             # unpackaged executable
        write(r, '/usr/lib/x86_64-linux-gnu/libz9.so.1', b'\x7fELF lib', 0o644)  # unpackaged library
        write(r, '/usr/bin/README.txt', b'not executable', 0o644)             # ignored
        write(r, '/var/tmp/.cache/helper', b'\x7fELF helper', 0o4755)        # unpackaged setuid in a hidden temp folder
        os.symlink('/tmp/.x/ls', os.path.join(r, 'usr/bin/lss'))              # system command pointing into /tmp
        write(r, '/etc/hostname', 'web-01\n')
        write(r, '/etc/os-release', 'PRETTY_NAME="Test Linux 1.0"\n')
        write(r, '/etc/passwd', 'root:x:0:0:root:/root:/bin/bash\n')
        lst = '/.\n/usr\n/usr/bin\n/usr/bin/ls\n/usr/bin/passwd\n/usr/lib/x86_64-linux-gnu/libc.so.6\n'
        md5 = ''.join('%s  %s\n' % (hashlib.md5(d).hexdigest(), p.lstrip('/')) for p, d in GOOD.items())
        write(r, '/var/lib/dpkg/info/base.list', lst)
        write(r, '/var/lib/dpkg/info/base.md5sums', md5)
        write(r, '/var/lib/dpkg/status', 'Package: base\nVersion: 1.0\n')
        cls.out = os.path.join(cls.tmp, 'Reports')
        cls.rc = linux_detective.main(['--root', r, '--output', cls.out, '--case-id', 'TEST-1', '--analyst', 'tester',
                                       '--allowlist', os.path.join(cls.tmp, 'none.txt')])
        cls.case = [os.path.join(cls.out, d) for d in os.listdir(cls.out) if d.startswith('LDCase_') and os.path.isdir(os.path.join(cls.out, d))][0]
        with io.open(os.path.join(cls.case, 'findings.json'), encoding='utf-8') as fh:
            cls.findings = json.load(fh)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def find(self, title, path):
        return [f for f in self.findings if f['Title'] == title and ('path=%s ' % path) in f['Evidence'] + ' ']

    def test_exit_code_and_case_name(self):
        self.assertEqual(self.rc, 0)
        self.assertTrue(os.path.basename(self.case).startswith('LDCase_web-01_'))

    def test_modified_binary(self):
        f = self.find('Packaged system file has been modified', '/usr/bin/ls')
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]['Severity'], 'High')

    def test_unowned_executable_and_library(self):
        self.assertTrue(self.find('Executable in a system directory is not owned by any package', '/usr/sbin/sysmond'))
        self.assertTrue(self.find('Shared library in a system directory is not owned by any package', '/usr/lib/x86_64-linux-gnu/libz9.so.1'))
        self.assertFalse([f for f in self.findings if '/usr/bin/README.txt' in f['Evidence']])

    def test_symlink_into_tmp(self):
        self.assertTrue(self.find('System command is a symlink into a temporary or hidden location', '/usr/bin/lss'))

    def test_setuid(self):
        f = self.find('Setuid / setgid file not owned by any package', '/var/tmp/.cache/helper')
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]['Severity'], 'High')
        # packaged, unmodified setuid binary: inventoried but not flagged
        self.assertFalse([x for x in self.findings if '/usr/bin/passwd' in x['Evidence']])
        with io.open(os.path.join(self.case, 'raw', 'SetuidSetgidFiles.csv'), encoding='utf-8') as fh:
            paths = sorted(r['Path'] for r in csv.DictReader(fh))
        self.assertEqual(paths, ['/usr/bin/passwd', '/var/tmp/.cache/helper'])

    def test_no_duplicates_through_usrmerge(self):
        self.assertFalse([f for f in self.findings if 'path=/bin/' in f['Evidence']])

    def test_ids_and_order(self):
        self.assertEqual([f['Id'] for f in self.findings], ['LD-%04d' % i for i in range(1, len(self.findings) + 1)])
        order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sev = [order[f['Severity']] for f in self.findings]
        self.assertEqual(sev, sorted(sev))

    def test_verdict(self):
        with io.open(os.path.join(self.case, 'system_info.json'), encoding='utf-8') as fh:
            info = json.load(fh)
        self.assertEqual(info['Verdict'], 'HIGHLY SUSPICIOUS')
        self.assertEqual(info['Hostname'], 'web-01')
        self.assertEqual(info['Operating system'], 'Test Linux 1.0')

    def test_manifest_matches_files(self):
        with io.open(os.path.join(self.case, 'manifest.sha256.csv'), encoding='utf-8') as fh:
            rows = list(csv.DictReader(fh))
        self.assertTrue(any(r['File'] == 'findings.json' for r in rows))
        for r in rows:
            with open(os.path.join(self.case, r['File']), 'rb') as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), r['SHA256'], r['File'])

    def test_archive_and_history(self):
        arc = self.case + '.tar.gz'
        with open(arc, 'rb') as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        with open(arc + '.sha256') as fh:
            self.assertTrue(fh.read().startswith(digest))
        with tarfile.open(arc) as t:
            self.assertIn(os.path.basename(self.case) + '/findings.json', t.getnames())
        with io.open(os.path.join(self.out, 'scan_history.csv'), encoding='utf-8') as fh:
            hist = list(csv.DictReader(fh))
        self.assertEqual(hist[-1]['CaseId'], 'TEST-1')
        self.assertEqual(hist[-1]['Verdict'], 'HIGHLY SUSPICIOUS')

    def test_nothing_written_into_the_image(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            for n in filenames + dirnames:
                self.assertFalse(n.startswith('LDCase_') or n.endswith('.pyc'), os.path.join(dirpath, n))


if __name__ == '__main__':
    unittest.main(verbosity=1)
