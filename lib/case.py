# =============================================================================
#  Linux Detective - Case folder, SHA-256 manifest, archive and scan history
#  Powered by Bashar Salmo
#  LD-SELF-MARKER
# =============================================================================

import csv
import hashlib
import io
import os
import re
import tarfile
import time

from . import core


def create(output_dir, host):
    ctx = core.CTX
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', host)[:60] or 'host'
    ctx.case_name = 'LDCase_%s_%s' % (safe, time.strftime('%Y%m%d_%H%M%S', time.gmtime(ctx.start)))
    ctx.case_dir = os.path.join(os.path.abspath(output_dir), ctx.case_name)
    ctx.raw_dir = os.path.join(ctx.case_dir, 'raw')
    ctx.files_dir = os.path.join(ctx.case_dir, 'files')
    for d in (ctx.case_dir, ctx.raw_dir, ctx.files_dir):
        os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(ctx.case_dir, 0o700)  # evidence may contain sensitive data
    ctx.log_file = os.path.join(ctx.case_dir, 'collection.log')
    return ctx.case_dir


def _sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for b in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def write_manifest():
    """manifest.sha256.csv: SHA-256 of every file in the case folder (chain of custody)."""
    ctx = core.CTX
    rows = []
    for dirpath, dirnames, filenames in os.walk(ctx.case_dir):
        dirnames.sort()
        for n in sorted(filenames):
            p = os.path.join(dirpath, n)
            rel = os.path.relpath(p, ctx.case_dir)
            if rel == 'manifest.sha256.csv':
                continue
            rows.append({'File': rel, 'SHA256': _sha256(p), 'Size': os.path.getsize(p)})
    path = os.path.join(ctx.case_dir, 'manifest.sha256.csv')
    core.write_csv(path, rows, ['File', 'SHA256', 'Size'])
    return path


def archive():
    """<case>.tar.gz next to the case folder, plus <case>.tar.gz.sha256."""
    ctx = core.CTX
    out = ctx.case_dir + '.tar.gz'
    with tarfile.open(out, 'w:gz') as tar:
        tar.add(ctx.case_dir, arcname=ctx.case_name)
    os.chmod(out, 0o600)
    digest = _sha256(out)
    with io.open(out + '.sha256', 'w', encoding='ascii') as fh:
        fh.write('%s  %s\n' % (digest, os.path.basename(out)))
    return out, digest


HISTORY_COLUMNS = ['ScanStartUtc', 'Host', 'CaseId', 'Analyst', 'Mode', 'Verdict', 'RiskScore', 'Critical', 'High',
                   'Medium', 'Low', 'Info', 'ToolVersion', 'CaseFolder', 'Archive']


def append_history(v, c, archive_path=''):
    """One line per scan in <output>/scan_history.csv so earlier scans are easy to find and compare."""
    ctx = core.CTX
    path = os.path.join(os.path.dirname(ctx.case_dir), 'scan_history.csv')
    new = not os.path.exists(path)
    with io.open(path, 'a', encoding='utf-8', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=HISTORY_COLUMNS)
        if new:
            w.writeheader()
        w.writerow({'ScanStartUtc': core.ts(ctx.start), 'Host': ctx.system_info.get('Hostname', ''),
                    'CaseId': ctx.opts.get('case_id', ''), 'Analyst': ctx.opts.get('analyst', ''),
                    'Mode': 'live' if ctx.live else 'image:' + ctx.root, 'Verdict': v['Level'], 'RiskScore': v['Score'],
                    'Critical': c['Critical'], 'High': c['High'], 'Medium': c['Medium'], 'Low': c['Low'], 'Info': c['Info'],
                    'ToolVersion': core.VERSION, 'CaseFolder': ctx.case_dir, 'Archive': archive_path})
    return path
