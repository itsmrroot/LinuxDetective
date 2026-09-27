# =============================================================================
#  Linux Detective - User-supplied command rules
#  Powered by Bashar Salmo
#  LD-SELF-MARKER
#
#  Command-line rules are data, not code: add them to rules/detection-data.json
#  (or pass --rules <file>) and they are applied to every shell history line,
#  cron entry, systemd Exec line and process command line the tool collects.
# =============================================================================

import io
import json
import os
import re

from . import core

COMMAND_RULES = []

# Only the ATT&CK ids the tool itself emits need a name here; ids from user rules
# are still linked to attack.mitre.org in the report.
MITRE_NAMES = {
    'T1014': 'Rootkit', 'T1053.003': 'Cron', 'T1543.002': 'Systemd Service', 'T1037.004': 'RC Scripts',
    'T1546.004': 'Unix Shell Configuration Modification', 'T1574.006': 'Dynamic Linker Hijacking',
    'T1098.004': 'SSH Authorized Keys', 'T1547.006': 'Kernel Modules and Extensions', 'T1548.001': 'Setuid and Setgid',
    'T1548.003': 'Sudo and Sudo Caching', 'T1136.001': 'Local Account', 'T1078.003': 'Local Accounts',
    'T1554': 'Compromise Host Software Binary', 'T1070.002': 'Clear Linux or Mac System Logs',
    'T1562.012': 'Disable or Modify Linux Audit System', 'T1562.001': 'Disable or Modify Tools',
    'T1110': 'Brute Force', 'T1021.004': 'SSH', 'T1078': 'Valid Accounts', 'T1036.005': 'Match Legitimate Name or Location',
    'T1564.001': 'Hidden Files and Directories', 'T1105': 'Ingress Tool Transfer', 'T1204.002': 'Malicious File',
    'T1588.002': 'Tool', 'T1219': 'Remote Access Tools', 'T1556.003': 'Pluggable Authentication Modules',
    'T1059.004': 'Unix Shell',
}


def mitre_name(tid):
    return MITRE_NAMES.get(tid, '')


def _add_rules(items, origin):
    n = 0
    for r in items or []:
        try:
            COMMAND_RULES.append({'id': r['id'], 'severity': r['severity'], 'mitre': r.get('mitre', ''),
                                  'title': r['title'], 'rx': re.compile(r['pattern'], re.I)})
            n += 1
        except (re.error, KeyError) as e:
            core.log('Rule %s from %s failed to compile: %s' % (r.get('id'), origin, e), 'WARN')
    return n


def load(path, extra=None):
    """Loads command rules. Returns the number of rules loaded (0 is valid: the tool still runs)."""
    del COMMAND_RULES[:]
    total = 0
    for p in [path, extra]:
        if p and os.path.isfile(p):
            with io.open(p, encoding='utf-8') as fh:
                total += _add_rules(json.load(fh).get('commandRules', []), p)
    return total


def check_command(text, source, when=None, context='', category='Execution'):
    """Applies every command rule to one command line and raises a finding per hit."""
    if not text or not COMMAND_RULES or core.is_self_text(text):
        return 0
    n = 0
    for r in COMMAND_RULES:
        if r['rx'].search(text):
            detail = 'Rule %s matched in %s.' % (r['id'], source)
            if context:
                detail += ' ' + context
            core.add_finding(r['severity'], category, r['title'], detail, text, r['mitre'], when, source)
            n += 1
    return n
