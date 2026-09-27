# =============================================================================
#  Linux Detective - Verdict and machine-readable output (JSON / CSV)
#  Powered by Bashar Salmo
#  LD-SELF-MARKER
# =============================================================================

import io
import json
import os
import time

from . import core

FINDING_COLUMNS = ['Id', 'Severity', 'Category', 'Title', 'Detail', 'Evidence', 'Mitre', 'Source', 'FirstSeen',
                   'LastSeen', 'Occurrences', 'Allowlisted', 'OriginalSeverity']


def counts():
    c = dict((s, 0) for s in core.SEVERITIES)
    for f in core.CTX.findings:
        c[f['Severity']] += 1
    return c


def verdict():
    c = counts()
    score = min(100, sum(core.SEV_WEIGHT[f['Severity']] for f in core.CTX.findings))
    if c['Critical']:
        return {'Level': 'COMPROMISED', 'Css': 'crit', 'Score': score,
                'Text': 'Critical indicators of compromise were found. Treat this host as compromised: contain it and start incident response now.'}
    if c['High'] >= 3:
        return {'Level': 'HIGHLY SUSPICIOUS', 'Css': 'high', 'Score': score,
                'Text': 'Multiple high-severity indicators were found. Compromise is likely until each one is explained.'}
    if c['High']:
        return {'Level': 'SUSPICIOUS', 'Css': 'high', 'Score': score,
                'Text': 'High-severity indicators were found and need analyst validation.'}
    if c['Medium'] >= 5:
        return {'Level': 'NEEDS REVIEW', 'Css': 'med', 'Score': score,
                'Text': 'Several anomalies were found. None is conclusive on its own; review them together with the timeline.'}
    return {'Level': 'NO STRONG INDICATORS', 'Css': 'ok', 'Score': score,
            'Text': 'No strong indicators of compromise were detected by the checks that ran. This does not prove the host is clean.'}


def sorted_findings():
    fs = sorted(core.CTX.findings, key=lambda f: (f['LastSeen'] or ''), reverse=True)
    fs.sort(key=lambda f: (core.SEV_ORDER[f['Severity']], f['Category'], f['Title']))
    for i, f in enumerate(fs, 1):
        f['Id'] = 'LD-%04d' % i
    return fs


def export():
    ctx = core.CTX
    ctx.end = ctx.end or time.time()
    fs = sorted_findings()
    d = ctx.case_dir
    with io.open(os.path.join(d, 'findings.json'), 'w', encoding='utf-8') as fh:
        json.dump(fs, fh, indent=2, ensure_ascii=False)
    core.write_csv(os.path.join(d, 'findings.csv'), fs, FINDING_COLUMNS)
    tl = sorted(ctx.timeline, key=lambda t: t['TimeUtc'], reverse=True)
    core.write_csv(os.path.join(d, 'timeline.csv'), tl, ['TimeUtc', 'Severity', 'Source', 'Description', 'Detail'])
    v = verdict()
    summary = dict(ctx.system_info)
    summary.update({'Case ID': ctx.opts.get('case_id', ''), 'Analyst': ctx.opts.get('analyst', ''),
                    'Tool': '%s v%s (%s)' % (core.TOOL, core.VERSION, core.BRAND),
                    'Collection start (UTC)': core.ts(ctx.start), 'Collection end (UTC)': core.ts(ctx.end),
                    'Investigation window': 'since %s UTC' % core.ts(ctx.since),
                    'Verdict': v['Level'], 'Risk score': v['Score']})
    with io.open(os.path.join(d, 'system_info.json'), 'w', encoding='utf-8') as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
    core.write_csv(os.path.join(d, 'collection_stats.csv'), ctx.stats, ['Collector', 'Status', 'Seconds', 'NewFindings', 'Error'])
    if ctx.allowlist:
        core.save_artifact('AllowlistHits', 'Threat Intel',
                           [{'Type': a['type'], 'Rule': a['rule'], 'Reason': a['reason'], 'Hits': a['hits']} for a in ctx.allowlist],
                           'Allowlist rules and how many findings each one downgraded')
    return fs, v
