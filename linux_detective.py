#!/usr/bin/env python3
# =============================================================================
#  Linux Detective - forensic triage & compromise assessment for Linux
#  Powered by Bashar Salmo
#  LD-SELF-MARKER
#
#  Usage:
#    sudo ./linux_detective.py                          # live host
#    sudo ./linux_detective.py --root /mnt/evidence     # disk image mounted read-only
#    sudo ./linux_detective.py --output /media/usb/Reports --case-id IR-2026-042 --analyst "Jane Doe"
# =============================================================================

import argparse
import datetime
import os
import sys
import time

sys.dont_write_bytecode = True  # never leave .pyc files next to the tool (it may run from evidence media)
TOOL_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOL_ROOT)

from lib import case, core, integrity, report, rules, system  # noqa: E402

BANNER = r'''
  _     _                    ____       _            _   _
 | |   (_)_ __  _   ___  __ |  _ \  ___| |_ ___  ___| |_(_)_   _____
 | |   | | '_ \| | | \ \/ / | | | |/ _ \ __/ _ \/ __| __| \ \ / / _ \
 | |___| | | | | |_| |>  <  | |_| |  __/ ||  __/ (__| |_| |\ V /  __/
 |_____|_|_| |_|\__,_/_/\_\ |____/ \___|\__\___|\___|\__|_| \_/ \___|
'''


def parse_args(argv):
    p = argparse.ArgumentParser(prog='linux_detective.py',
                                description='%s v%s - forensic triage & compromise assessment for Linux. %s.' %
                                (core.TOOL, core.VERSION, core.BRAND))
    p.add_argument('--root', default='/', help='Analyse a filesystem mounted at this path instead of the live host')
    p.add_argument('--output', default=os.path.join(TOOL_ROOT, 'Reports'),
                   help='Folder for case folders and scan_history.csv (default: Reports/ next to the tool; use external media)')
    p.add_argument('--days', type=int, default=30, help='Investigation window in days (default 30)')
    p.add_argument('--since', help='Start of the investigation window as YYYY-MM-DD (overrides --days; useful for old images)')
    p.add_argument('--case-id', default='', help='Case / ticket reference printed in the output')
    p.add_argument('--analyst', default=os.environ.get('SUDO_USER') or os.environ.get('USER') or '', help='Analyst name')
    p.add_argument('--quick', action='store_true', help='Faster run: binaries only, setuid sweep limited to common folders')
    p.add_argument('--max-files', type=int, default=3000000, help='Upper bound of files visited by the setuid sweep')
    p.add_argument('--allowlist', default=os.path.join(TOOL_ROOT, 'iocs', 'allowlist.txt'), help='Known-good rules file')
    p.add_argument('--rules', default='', help='Extra command-rule JSON file (same format as rules/detection-data.json)')
    p.add_argument('--no-archive', action='store_true', help='Do not create the .tar.gz archive of the case folder')
    p.add_argument('--version', action='version', version='%s %s' % (core.TOOL, core.VERSION))
    a = p.parse_args(argv)
    if a.days < 1 or a.days > 3650:
        p.error('--days must be between 1 and 3650')
    if a.since:
        try:
            a.since_epoch = (datetime.datetime.strptime(a.since, '%Y-%m-%d') - datetime.datetime(1970, 1, 1)).total_seconds()
        except ValueError:
            p.error('--since must look like 2026-09-01')
    else:
        a.since_epoch = None
    a.root = os.path.abspath(a.root)
    if not os.path.isdir(a.root):
        p.error('--root %s is not a directory' % a.root)
    if a.root == '/' and not sys.platform.startswith('linux'):
        p.error('live analysis needs Linux; on %s use --root <mounted Linux filesystem>' % sys.platform)
    return a


def same_filesystem(a, b):
    try:
        return os.stat(a).st_dev == os.stat(b).st_dev
    except OSError:
        return False


def main(argv=None):
    a = parse_args(sys.argv[1:] if argv is None else argv)
    print(core.color(BANNER, '36'))
    print('        Forensic Triage & Compromise Assessment  v%s' % core.VERSION)
    print(core.color('        %s' % core.BRAND, '33'))
    print('')

    ctx = core.new_context({'root': a.root, 'days': a.days, 'since_epoch': a.since_epoch, 'tool_root': TOOL_ROOT,
                            'case_id': a.case_id or 'LD-' + time.strftime('%Y%m%d-%H%M%S'), 'analyst': a.analyst,
                            'quick': a.quick, 'max_files': a.max_files,
                            'max_hash_bytes': (25 if a.quick else 150) * 1024 * 1024})
    os.makedirs(a.output, exist_ok=True)
    case.create(a.output, system.hostname())
    core.log('%s v%s - %s' % (core.TOOL, core.VERSION, core.BRAND), 'INFO')
    core.log('Case %s | analyst %s | %s | output %s' % (ctx.opts['case_id'], a.analyst or '-',
             'live host' if ctx.live else 'image at ' + a.root, ctx.case_dir), 'INFO')
    if not ctx.is_root:
        core.log('NOT running as root - many system files are unreadable and results will be incomplete. Re-run with sudo.', 'WARN')
    if ctx.live and same_filesystem(ctx.case_dir, '/'):
        core.log('Output is on the system disk. For evidential work write to external media (--output /media/usb/Reports) '
                 'to avoid overwriting deleted data.', 'WARN')
    n = core.import_allowlist(a.allowlist)
    if n:
        core.log('Allowlist: %d known-good rule(s) loaded from %s' % (n, a.allowlist), 'INFO')
    n = rules.load(os.path.join(TOOL_ROOT, 'rules', 'detection-data.json'), a.rules)
    core.log('Command rules loaded: %d' % n, 'INFO')

    exit_code = 0
    try:
        core.run_collector('Host profile', system.profile)
        core.run_collector('Package integrity', integrity.sweep)
        core.run_collector('Setuid / setgid inventory', integrity.setuid_inventory)
    except KeyboardInterrupt:
        core.log('Interrupted - writing what was collected so far', 'WARN')
        exit_code = 130

    core.log('Writing results', 'STEP')
    findings, v = report.export()
    core.log('Sealing the case folder (SHA-256 manifest)', 'INFO')
    ctx.log_file = ''  # nothing may change inside the case folder once the manifest is written
    case.write_manifest()
    archive_path = ''
    if not a.no_archive:
        try:
            archive_path, digest = case.archive()
            core.log('Case archive: %s (SHA-256 %s)' % (archive_path, digest), 'OK')
        except (OSError, IOError) as e:
            core.log('Archive failed: %s' % e, 'WARN')
    c = report.counts()
    history = case.append_history(v, c, archive_path)

    colour = {'crit': '31', 'high': '33', 'med': '33', 'ok': '32'}[v['Css']]
    print('')
    print(core.color('=' * 78, '90'))
    print(core.color('  VERDICT: %s   (risk score %s/100)' % (v['Level'], v['Score']), colour))
    print('  Critical %d | High %d | Medium %d | Low %d | Info %d' % (c['Critical'], c['High'], c['Medium'], c['Low'], c['Info']))
    print('')
    for f in [f for f in findings if f['Severity'] in ('Critical', 'High')][:15]:
        print(core.color('  [%s] %-8s %s' % (f['Id'], f['Severity'], f['Title']), '31' if f['Severity'] == 'Critical' else '33'))
        print(core.color('            %s' % core.limit(f['Evidence'], 110), '90'))
    print('')
    print(core.color('  Case   : %s' % ctx.case_dir, '36'))
    print(core.color('  History: %s' % history, '36'))
    if archive_path:
        print(core.color('  Archive: %s' % archive_path, '36'))
    print(core.color('=' * 78, '90'))
    print(core.color('  %s - %s' % (core.TOOL, core.BRAND), '33'))
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
