# =============================================================================
#  Linux Detective - Core engine
#  Powered by Bashar Salmo
#  LD-SELF-MARKER (lets the tool exclude its own activity from detections)
#
#  Context, findings, timeline, artifacts, allowlist, logging and the file /
#  process / package helpers every collector uses. Standard library only and
#  compatible with Python 3.6+ so it runs on old enterprise servers too.
# =============================================================================

import csv
import datetime
import errno
import fnmatch
import hashlib
import io
import ipaddress
import os
import posixpath
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time

VERSION = '1.0.0'
TOOL = 'Linux Detective'
BRAND = 'Powered by Bashar Salmo'

SEV_ORDER = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
SEV_WEIGHT = {'Critical': 40, 'High': 15, 'Medium': 5, 'Low': 1, 'Info': 0}
SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info']

# Case folders are named LDCase_<HOST>_<yyyymmdd>_<HHMMSS>.
CASE_FOLDER_RX = re.compile(r'/LDCase_[A-Za-z0-9._-]+_\d{8}_\d{6}(/|\.tar\.gz\b|$)')

# World-writable / volatile locations attackers stage payloads in, and hidden directories anywhere.
HIGH_RISK_PATH_RX = re.compile(
    r'^(/tmp/|/var/tmp/|/dev/shm/|/run/shm/|/dev/(?!(null|zero|u?random|pts/|tty|console|fd/|stdin|stdout|stderr))|'
    r'/var/lock/|/run/lock/|/var/spool/(?!(cron|anacron|at|mail|postfix|cups|rsyslog|exim4|lpd|plymouth|abrt|clientmqueue|mqueue))|'
    r'/var/crash/|/var/mail/|/var/www/.*\.(so|elf|bin)$|/usr/share/fonts/.*\.(so|elf|sh)$)'
    r'|/\.{1,3}[^/]*/|/\.\.\.|/\s|/ +/')
USER_PATH_RX = re.compile(r'^(/home/|/root/|/var/www/|/srv/|/opt/|/usr/local/|/run/user/)')

TRUSTED_BIN_DIRS = ['/usr/bin', '/usr/sbin', '/bin', '/sbin', '/usr/local/bin', '/usr/local/sbin']

CTX = None


class Context(object):
    def __init__(self, opts):
        self.opts = opts
        self.root = os.path.abspath(opts.get('root') or '/')
        self.live = self.root == '/'
        self.days = int(opts.get('days', 30))
        self.start = time.time()
        self.end = None
        self.since = opts.get('since_epoch') or (self.start - self.days * 86400)
        self.is_root = hasattr(os, 'geteuid') and os.geteuid() == 0
        self.case_name = ''
        self.case_dir = ''
        self.raw_dir = ''
        self.files_dir = ''
        self.log_file = ''
        self.findings = []
        self.finding_index = {}
        self.timeline = []
        self.max_timeline = 80000
        self.artifacts = {}
        self.artifact_order = []
        self.stats = []
        self.file_cache = {}
        self.system_info = {}
        self.observed = {'hashes': {}, 'ips': {}, 'domains': {}}
        self.suspicious_files = {}
        self.autoruns = []
        self.processes = {}
        self.memory_image = ''
        self.allowlist = []
        self.users = None
        self.pkg = None
        self.notes = []
        self.self_pids = set()


def new_context(opts):
    global CTX
    CTX = Context(opts)
    CTX.self_pids.add(os.getpid())
    return CTX


# ----------------------------------------------------------------------------- console / logging
_COLORS = {'INFO': '\033[90m', 'WARN': '\033[33m', 'ERROR': '\033[31m', 'OK': '\033[32m', 'STEP': '\033[36m'}
_USE_COLOR = sys.stdout.isatty() and os.environ.get('NO_COLOR') is None


def color(text, code):
    if not _USE_COLOR:
        return text
    return '\033[%sm%s\033[0m' % (code, text)


def log(message, level='INFO'):
    line = '[%s] [%-5s] %s' % (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), level, message)
    if _USE_COLOR:
        print(_COLORS.get(level, '') + line + '\033[0m')
    else:
        print(line)
    sys.stdout.flush()
    if CTX is not None and CTX.log_file:
        try:
            with io.open(CTX.log_file, 'a', encoding='utf-8') as fh:
                fh.write(line + '\n')
        except Exception:
            pass


def run_collector(name, fn, *args):
    log('Collecting: %s' % name, 'STEP')
    t0 = time.time()
    before = len(CTX.findings)
    status, err = 'OK', ''
    try:
        fn(*args)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        import traceback
        status, err = 'ERROR', '%s: %s' % (type(e).__name__, e)
        log('%s failed: %s' % (name, err), 'ERROR')
        if CTX.log_file:
            try:
                with io.open(CTX.log_file, 'a', encoding='utf-8') as fh:
                    fh.write(traceback.format_exc() + '\n')
            except Exception:
                pass
    CTX.stats.append({'Collector': name, 'Status': status, 'Seconds': round(time.time() - t0, 1),
                      'NewFindings': len(CTX.findings) - before, 'Error': err})


# ----------------------------------------------------------------------------- text / time helpers
def limit(text, n=2000):
    if text is None:
        return ''
    t = str(text).strip()
    if len(t) > n:
        return t[:n] + ' ...[truncated]'
    return t


def printable(data):
    """Bytes -> readable text, control characters made visible."""
    if isinstance(data, bytes):
        data = data.decode('utf-8', 'replace')
    return ''.join(c if (c >= ' ' or c in '\t\n') and c != '\x7f' else '\\x%02x' % ord(c) for c in data)


def ts(value):
    """Epoch seconds / datetime -> 'YYYY-MM-DD HH:MM:SS' (UTC), '' when unknown."""
    if value is None or value == '':
        return ''
    try:
        if isinstance(value, datetime.datetime):
            if value.tzinfo is not None:
                value = value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
            if value.year < 1980:
                return ''
            return value.strftime('%Y-%m-%d %H:%M:%S')
        if isinstance(value, str):
            if re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$', value):
                return value
            value = float(value)
        v = float(value)
        if v < 315532800 or v > 4102444800:  # 1980 .. 2100
            return ''
        return datetime.datetime.fromtimestamp(v, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''


def in_window(epoch):
    return epoch is not None and epoch >= CTX.since


# Numbers glued to names and UUIDs differ between otherwise identical events;
# they are masked in the grouping key so repeats collapse into one finding with a count.
_UUID_RX = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
_NUM_RX = re.compile(r'(?<=[_\-A-Za-z\[=:])\d{2,}')


def grouping_key(text):
    return _NUM_RX.sub('#', _UUID_RX.sub('{UUID}', text or ''))


# ----------------------------------------------------------------------------- findings
def add_finding(severity, category, title, detail='', evidence='', mitre='', when=None, source='', group=True):
    evidence = limit(evidence, 2000)
    key = ('%s|%s|%s' % (category, title, grouping_key(evidence) if group else evidence)).lower()
    t = ts(when)
    f = CTX.finding_index.get(key)
    if f is not None:
        f['Occurrences'] += 1
        if t and (not f['FirstSeen'] or t < f['FirstSeen']):
            f['FirstSeen'] = t
        if t and t > f['LastSeen']:
            f['LastSeen'] = t
        if not f['Allowlisted'] and SEV_ORDER[severity] < SEV_ORDER[f['Severity']]:
            f['Severity'] = severity
        return f
    original = severity
    allow = test_allowlisted('%s\n%s\n%s' % (title, evidence, detail)) if CTX.allowlist else None
    if allow:
        severity = 'Info'
        detail = "ALLOWLISTED (was %s) by rule '%s'%s. %s" % (original, allow['rule'], (' - ' + allow['reason']) if allow['reason'] else '', detail)
    f = {'Id': '', 'Severity': severity, 'Category': category, 'Title': title, 'Detail': limit(detail, 1500),
         'Evidence': evidence, 'Mitre': mitre, 'Source': source, 'FirstSeen': t, 'LastSeen': t,
         'Occurrences': 1, 'Allowlisted': bool(allow), 'OriginalSeverity': original}
    CTX.finding_index[key] = f
    CTX.findings.append(f)
    if t and severity != 'Info':
        add_timeline(when, 'Finding/' + category, title, evidence, severity)
    return f


# ----------------------------------------------------------------------------- allowlist
# iocs/allowlist.txt - one rule per line:  hash:<md5|sha1|sha256> | path:<wildcard> | text:<wildcard>
# optionally followed by " | reason". Matching findings are kept but downgraded to Info.
def import_allowlist(path):
    CTX.allowlist = []
    if not path or not os.path.isfile(path):
        return 0
    with io.open(path, encoding='utf-8', errors='replace') as fh:
        for line in fh:
            t = line.strip()
            if not t or t.startswith('#'):
                continue
            reason = ''
            m = re.match(r'^(.*?)\s+\|\s+(.*)$', t)
            if m:
                t, reason = m.group(1).strip(), m.group(2).strip()
            m = re.match(r'^(hash|path|text):(.+)$', t, re.I)
            if m:
                kind, pattern = m.group(1).lower(), m.group(2).strip()
            elif re.match(r'^([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$', t):
                kind, pattern = 'hash', t
            else:
                kind, pattern = 'text', t
            if kind != 'hash':
                if not pattern.startswith('*'):
                    pattern = '*' + pattern
                if not pattern.endswith('*'):
                    pattern += '*'
                rx = re.compile(fnmatch.translate(pattern), re.I | re.S)
            else:
                rx = None
            CTX.allowlist.append({'type': kind, 'pattern': pattern.lower(), 'rx': rx, 'reason': reason, 'rule': t, 'hits': 0})
    return len(CTX.allowlist)


def test_allowlisted(text, count=True):
    if not text:
        return None
    low = text.lower()
    for a in CTX.allowlist:
        hit = (a['pattern'] in low) if a['type'] == 'hash' else bool(a['rx'].match(text))
        if hit:
            if count:
                a['hits'] += 1
            return a
    return None


# ----------------------------------------------------------------------------- timeline / artifacts / indicators
def add_timeline(when, source, description, detail='', severity='Info'):
    if len(CTX.timeline) >= CTX.max_timeline:
        return
    t = ts(when)
    if not t:
        return
    if severity != 'Info' and CTX.allowlist and test_allowlisted('%s\n%s' % (description, detail), count=False):
        severity = 'Info'
    CTX.timeline.append({'TimeUtc': t, 'Severity': severity, 'Source': source,
                         'Description': limit(description, 300), 'Detail': limit(detail, 600)})


def save_artifact(name, section, rows, description=''):
    rows = [r for r in (rows or []) if r]
    CTX.artifacts[name] = {'Name': name, 'Section': section, 'Description': description, 'Count': len(rows), 'Rows': rows}
    if name not in CTX.artifact_order:
        CTX.artifact_order.append(name)
    if rows and CTX.raw_dir:
        try:
            write_csv(os.path.join(CTX.raw_dir, name + '.csv'), rows)
        except Exception as e:
            log('Could not export artifact %s: %s' % (name, e), 'WARN')


def write_csv(path, rows, columns=None):
    if columns is None:
        columns = []
        for r in rows:
            for k in r.keys():
                if k not in columns:
                    columns.append(k)
    with io.open(path, 'w', encoding='utf-8', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=columns, extrasaction='ignore')
        w.writeheader()
        for r in rows:
            w.writerow(dict((k, '' if r.get(k) is None else r.get(k)) for k in columns))


def add_observed(kind, value, source):
    if not value:
        return
    v = str(value).strip().rstrip('.').lower()
    if v and v not in CTX.observed[kind]:
        CTX.observed[kind][v] = source


# ----------------------------------------------------------------------------- self exclusion
def is_self_text(text):
    """True when text points into this run's tool / case folder, or into a Linux Detective case folder.
    Merely mentioning the tool's name hides nothing, so an attacker cannot use it to slip past."""
    if not text:
        return False
    for anchor in (CTX.opts.get('tool_root'), CTX.case_dir):
        if anchor and len(anchor) > 1 and anchor in text:
            return True
    return bool(CASE_FOLDER_RX.search(text))


# ----------------------------------------------------------------------------- path helpers (live host or mounted image)
def _resolve_in_root(path, depth=0):
    parts = [p for p in path.split('/') if p]
    cur = '/'
    for part in parts:
        if part == '.':
            continue
        if part == '..':
            cur = posixpath.dirname(cur) or '/'
            continue
        cand = posixpath.join(cur, part)
        full = CTX.root + cand
        if depth < 40 and os.path.islink(full):
            try:
                target = os.readlink(full)
            except OSError:
                cur = cand
                continue
            if not target.startswith('/'):
                target = posixpath.join(cur, target)
            cur = _resolve_in_root(target, depth + 1)
        else:
            cur = cand
    return cur


def phys(path):
    """Logical path on the investigated system -> physical path to open (mounted-image aware:
    absolute symlinks inside the image are resolved inside the image, never on the analysis host)."""
    if CTX.live:
        return path
    return CTX.root.rstrip('/') + _resolve_in_root(path)


def logical(physical_path):
    if CTX.live:
        return physical_path
    r = CTX.root.rstrip('/')
    if physical_path == r:
        return '/'
    if physical_path.startswith(r + '/'):
        return physical_path[len(r):]
    return physical_path


def phys_nofollow(path):
    """Like phys(), but the last component is not resolved: a symlink stays a symlink (lstat / readlink)."""
    if CTX.live:
        return path
    parent, name = posixpath.split(posixpath.normpath('/' + path.lstrip('/')))
    if not name:
        return CTX.root.rstrip('/') or '/'
    return phys(parent).rstrip('/') + '/' + name


def exists(path):
    return os.path.lexists(phys_nofollow(path))


def isdir(path):
    return os.path.isdir(phys(path))


def listdir(path):
    try:
        return sorted(os.listdir(phys(path)))
    except OSError:
        return []


def lstat(path):
    try:
        return os.lstat(phys_nofollow(path))
    except OSError:
        return None


def _open_ro(p):
    """Opens read-only without updating the access time where the kernel allows it,
    and without ever blocking on a FIFO an attacker left behind."""
    base = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0)
    noatime = getattr(os, 'O_NOATIME', 0)
    try:
        fd = os.open(p, base | noatime)
    except OSError as e:
        if noatime and e.errno == errno.EPERM:
            fd = os.open(p, base)
        else:
            raise
    return os.fdopen(fd, 'rb')


def read_bytes(path, max_bytes=8 * 1024 * 1024, is_phys=False):
    p = path if is_phys else phys(path)
    try:
        st = os.stat(p)
        if not stat.S_ISREG(st.st_mode):
            return None
        with _open_ro(p) as fh:
            return fh.read(max_bytes)
    except (OSError, IOError):
        return None


def read_text(path, max_bytes=8 * 1024 * 1024, is_phys=False):
    data = read_bytes(path, max_bytes, is_phys)
    if data is None:
        return None
    if path.endswith('.gz') and data[:2] == b'\x1f\x8b':
        import gzip
        try:
            data = gzip.decompress(data)[:max_bytes * 4]
        except Exception:
            return None
    return data.decode('utf-8', 'replace')


def read_lines(path, max_bytes=64 * 1024 * 1024):
    t = read_text(path, max_bytes)
    return t.splitlines() if t else []


def read_proc(path, max_bytes=4 * 1024 * 1024):
    """/proc and /sys pseudo files (live mode only)."""
    try:
        with _open_ro(path) as fh:
            return fh.read(max_bytes).decode('utf-8', 'replace')
    except (OSError, IOError):
        return None


def glob_paths(pattern):
    import glob
    r = CTX.root.rstrip('/')
    if CTX.live:
        return sorted(glob.glob(pattern))
    return sorted(logical(p) for p in glob.glob(r + pattern))


def walk(top, max_depth=12, max_files=200000, follow_mounts=True, skip=None):
    """Yields (logical_path, lstat) for every file and directory below top."""
    skip = skip or set()
    start = phys(top)
    if not os.path.isdir(start):
        return
    try:
        root_dev = os.lstat(start).st_dev
    except OSError:
        return
    count = 0
    stack = [(start, 0)]
    while stack:
        d, depth = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            p = e.path
            lp = logical(p)
            if lp in skip:
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            count += 1
            if count > max_files:
                return
            yield lp, st
            if stat.S_ISDIR(st.st_mode) and depth < max_depth:
                if not follow_mounts and st.st_dev != root_dev:
                    continue
                stack.append((p, depth + 1))


def path_risk(path):
    if not path:
        return 'None'
    if HIGH_RISK_PATH_RX.search(path):
        return 'High'
    if USER_PATH_RX.match(path):
        return 'User'
    return 'None'


def is_elf_bytes(head):
    return head[:4] == b'\x7fELF'


# ----------------------------------------------------------------------------- hashing / file info
def hash_file(path, is_phys=False, max_bytes=None):
    """Returns (md5, sha1, sha256) in one pass, or ('','','') when unreadable or too large."""
    p = path if is_phys else phys(path)
    if max_bytes is None:
        max_bytes = CTX.opts.get('max_hash_bytes', 150 * 1024 * 1024)
    try:
        st = os.stat(p)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return '', '', ''
        h5, h1, h256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        with _open_ro(p) as fh:
            while True:
                b = fh.read(1024 * 1024)
                if not b:
                    break
                h5.update(b)
                h1.update(b)
                h256.update(b)
        return h5.hexdigest(), h1.hexdigest(), h256.hexdigest()
    except (OSError, IOError):
        return '', '', ''


def file_info(path, do_hash=True):
    """Metadata of a file on the investigated system (logical path). Cached."""
    if not path:
        return None
    key = (path, do_hash)
    if key in CTX.file_cache:
        return CTX.file_cache[key]
    info = {'Path': path, 'Exists': False, 'Size': 0, 'Mode': '', 'Owner': '', 'Uid': None, 'Mtime': None,
            'Ctime': None, 'Atime': None, 'SHA256': '', 'MD5': '', 'SHA1': '', 'IsELF': False, 'Package': '',
            'Suid': False, 'Sgid': False}
    st = lstat(path)
    if st is not None:
        info['Exists'] = True
        info['Size'] = st.st_size
        info['Mode'] = stat.filemode(st.st_mode)
        info['Uid'] = st.st_uid
        info['Owner'] = user_name(st.st_uid)
        info['Mtime'], info['Ctime'], info['Atime'] = st.st_mtime, st.st_ctime, st.st_atime
        info['Suid'] = bool(st.st_mode & stat.S_ISUID)
        info['Sgid'] = bool(st.st_mode & stat.S_ISGID)
        if stat.S_ISREG(st.st_mode):
            head = read_bytes(path, 4) or b''
            info['IsELF'] = is_elf_bytes(head)
            if do_hash:
                info['MD5'], info['SHA1'], info['SHA256'] = hash_file(path)
                if info['SHA256']:
                    add_observed('hashes', info['SHA256'], path)
                    add_observed('hashes', info['MD5'], path)
                    add_observed('hashes', info['SHA1'], path)
        info['Package'] = pkg().owner(path)
    CTX.file_cache[key] = info
    return info


def flag_file(path, reason):
    """Remembers a file for YARA scanning, IOC matching and evidence copy."""
    if path and path not in CTX.suspicious_files:
        CTX.suspicious_files[path] = reason


def copy_evidence(src_phys, name_hint=''):
    """Copies a file (e.g. a deleted binary recovered from /proc/<pid>/exe) into files/ as <sha256>.bin."""
    if not CTX.files_dir:
        return ''
    try:
        _, _, sha = hash_file(src_phys, is_phys=True, max_bytes=CTX.opts.get('max_copy_bytes', 100 * 1024 * 1024))
        if not sha:
            return ''
        dest_dir = os.path.join(CTX.files_dir, 'flagged')
        if not os.path.isdir(dest_dir):
            os.makedirs(dest_dir)
        dest = os.path.join(dest_dir, sha + '.bin')
        if not os.path.exists(dest):
            with _open_ro(src_phys) as src, open(dest, 'wb') as out:
                shutil.copyfileobj(src, out)
            os.chmod(dest, 0o400)
            with io.open(os.path.join(dest_dir, 'index.csv'), 'a', encoding='utf-8') as fh:
                fh.write('"%s","%s"\n' % (sha, (name_hint or src_phys).replace('"', "'")))
        return dest
    except (OSError, IOError):
        return ''


# ----------------------------------------------------------------------------- users
def load_users():
    if CTX.users is not None:
        return CTX.users
    users = []
    for line in read_lines('/etc/passwd'):
        parts = line.split(':')
        if len(parts) < 7 or line.startswith('#'):
            continue
        try:
            uid, gid = int(parts[2]), int(parts[3])
        except ValueError:
            continue
        users.append({'name': parts[0], 'pw': parts[1], 'uid': uid, 'gid': gid, 'gecos': parts[4],
                      'home': parts[5], 'shell': parts[6]})
    if not users and CTX.live:
        for p in pwd.getpwall():
            users.append({'name': p.pw_name, 'pw': p.pw_passwd, 'uid': p.pw_uid, 'gid': p.pw_gid, 'gecos': p.pw_gecos,
                          'home': p.pw_dir, 'shell': p.pw_shell})
    CTX.users = users
    return users


_UID_NAMES = {}


def _uid_map():
    users = load_users()
    key = id(users)
    if _UID_NAMES.get('key') != key:
        _UID_NAMES.clear()
        _UID_NAMES['key'] = key
        _UID_NAMES['map'] = {}
        for u in users:
            _UID_NAMES['map'].setdefault(u['uid'], u['name'])  # first entry wins, like getpwuid
    return _UID_NAMES['map']


def user_name(uid):
    return _uid_map().get(uid, str(uid))


def uid_known(uid):
    return uid in _uid_map()


NOLOGIN_RX = re.compile(r'(nologin|/false|/sync|/shutdown|/halt)$')


def user_homes():
    """(user, home) for every account with a real home directory, plus root; deduplicated."""
    seen, out = set(), []
    for u in load_users():
        h = u['home']
        if not h or h in ('/', '/nonexistent', '/dev/null') or h in seen:
            continue
        if not isdir(h):
            continue
        seen.add(h)
        out.append((u, h))
    for h in listdir('/home'):
        hp = '/home/' + h
        if hp not in seen and isdir(hp):
            seen.add(hp)
            out.append(({'name': h, 'uid': -1, 'shell': '', 'home': hp}, hp))
    return out


# ----------------------------------------------------------------------------- external commands (read-only)
def which(cmd):
    if not CTX.live:
        return ''
    for d in TRUSTED_BIN_DIRS:
        p = os.path.join(d, cmd)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return ''


def run(args, timeout=60, env=None, max_bytes=64 * 1024 * 1024):
    """Runs a read-only command with a clean environment. Returns (rc, stdout text) or (None, '')."""
    exe = args[0] if args[0].startswith('/') else which(args[0])
    if not exe:
        return None, ''
    e = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'SYSTEMD_PAGER': '', 'PAGER': 'cat'}
    if env:
        e.update(env)
    try:
        p = subprocess.Popen([exe] + list(args[1:]), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, env=e)
        CTX.self_pids.add(p.pid)
        try:
            out, _ = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, _ = p.communicate()
            log('Command timed out: %s' % ' '.join(args), 'WARN')
        return p.returncode, out[:max_bytes].decode('utf-8', 'replace')
    except (OSError, ValueError) as ex:
        log('Command failed: %s (%s)' % (' '.join(args), ex), 'WARN')
        return None, ''


# ----------------------------------------------------------------------------- network helpers
def is_public_ip(ip):
    if not ip:
        return False
    s = ip.strip().strip('[]').split('%')[0]
    if s.lower().startswith('::ffff:'):
        s = s[7:]
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return False
    if a.version == 4 and a in ipaddress.ip_network('100.64.0.0/10'):
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved)


# ----------------------------------------------------------------------------- package database
class PackageDB(object):
    """Which package owns a file, and the digest the package shipped for it.
    Supports dpkg (Debian/Ubuntu), rpm (RHEL/Fedora/SUSE), apk (Alpine) and pacman (Arch)."""

    ALIASES = [('/usr/bin/', '/bin/'), ('/usr/sbin/', '/sbin/'), ('/usr/lib/', '/lib/'), ('/usr/lib64/', '/lib64/'),
               ('/usr/lib32/', '/lib32/'), ('/usr/libx32/', '/libx32/'), ('/usr/sbin/', '/usr/bin/')]

    def __init__(self):
        self.kind = ''
        self.owners = None
        self.digests = {}
        self.digest_algo = {}
        self.installed = {}
        self.error = ''
        self._verified = {}
        # dpkg-divert: original path -> (diverted-to path, diverting package or ':' for a local diversion)
        self.div_from = {}
        self.div_to = {}
        self.div_owners = {}
        self.pkg_digests = {}

    def detect(self):
        if isdir('/var/lib/dpkg/info'):
            self.kind = 'dpkg'
        elif exists('/lib/apk/db/installed'):
            self.kind = 'apk'
        elif isdir('/var/lib/pacman/local'):
            self.kind = 'pacman'
        elif isdir('/var/lib/rpm') or isdir('/usr/lib/sysimage/rpm'):
            self.kind = 'rpm'
        return self.kind

    def available(self):
        self._load()
        return bool(self.owners)

    def _load(self):
        if self.owners is not None:
            return
        self.owners = {}
        t0 = time.time()
        try:
            getattr(self, '_load_' + self.kind, lambda: None)()
        except Exception as e:
            self.error = str(e)
            log('Package database could not be read (%s): %s' % (self.kind, e), 'WARN')
        if self.owners:
            log('Package database (%s): %d files from %d packages indexed in %.1fs' %
                (self.kind, len(self.owners), len(self.installed), time.time() - t0), 'INFO')

    def _load_dpkg(self):
        info = '/var/lib/dpkg/info'
        # Diversions come in blocks of three lines: original path, diverted-to path, package (':' = local)
        div = read_lines('/var/lib/dpkg/diversions')
        for i in range(0, len(div) - 2, 3):
            self.div_from[div[i]] = (div[i + 1], div[i + 2])
            self.div_to[div[i + 1]] = div[i]
        for f in listdir(info):
            if f.endswith('.list'):
                pkgname = f[:-5].split(':')[0]
                self.installed[pkgname] = ''
                for line in read_lines(info + '/' + f, 32 * 1024 * 1024):
                    if line and line != '/.':
                        self.owners.setdefault(line, pkgname)
                        if line in self.div_from:
                            self.div_owners.setdefault(line, []).append(pkgname)
        # Shipped MD5 digests (package verification without running dpkg)
        for f in listdir(info):
            if f.endswith('.md5sums'):
                pkgname = f[:-8].split(':')[0]
                for line in read_lines(info + '/' + f, 32 * 1024 * 1024):
                    parts = line.split(None, 1)
                    if len(parts) == 2 and len(parts[0]) == 32:
                        p = '/' + parts[1].lstrip('/')
                        self.digests[p] = parts[0].lower()
                        self.digest_algo[p] = 'md5'
                        if p in self.div_from:
                            self.pkg_digests[(pkgname, p)] = parts[0].lower()
        status = read_text('/var/lib/dpkg/status') or ''
        for block in status.split('\n\n'):
            m = re.search(r'^Package: (\S+)', block, re.M)
            v = re.search(r'^Version: (\S+)', block, re.M)
            if m and v:
                self.installed[m.group(1)] = v.group(1)

    def _load_apk(self):
        import base64
        pkgname, d, last = '', '', ''
        for line in read_lines('/lib/apk/db/installed'):
            if line.startswith('P:'):
                pkgname, last = line[2:], ''
                self.installed[pkgname] = ''
            elif line.startswith('V:'):
                self.installed[pkgname] = line[2:]
            elif line.startswith('F:'):
                d = '/' + line[2:]
            elif line.startswith('R:'):
                p = d.rstrip('/') + '/' + line[2:]
                self.owners.setdefault(p, pkgname)
                last = p
            elif line.startswith('Z:Q1') and last:
                try:
                    self.digests[last] = base64.b64decode(line[4:]).hex()
                    self.digest_algo[last] = 'sha1'
                except Exception:
                    pass

    def _load_pacman(self):
        base = '/var/lib/pacman/local'
        for d in listdir(base):
            if not isdir(base + '/' + d):  # e.g. the ALPM_DB_VERSION file
                continue
            parts = d.rsplit('-', 2)
            pkgname = parts[0] if len(parts) == 3 else d
            self.installed[pkgname] = '-'.join(parts[1:])
            in_files = False
            for line in read_lines(base + '/' + d + '/files'):
                if line.startswith('%'):
                    in_files = line == '%FILES%'
                    continue
                if in_files and line and not line.endswith('/'):
                    self.owners.setdefault('/' + line, pkgname)
            # Shipped SHA-256 digests live in the gzip-compressed mtree file
            data = read_bytes(base + '/' + d + '/mtree', 64 * 1024 * 1024)
            if data and data[:2] == b'\x1f\x8b':
                import gzip
                try:
                    text = gzip.decompress(data).decode('utf-8', 'replace')
                except Exception:
                    text = ''
                for line in text.splitlines():
                    if not line.startswith('./') or 'sha256digest=' not in line:
                        continue
                    fields = line.split(' ')
                    path = '/' + fields[0][2:].replace('\\040', ' ')
                    for f in fields[1:]:
                        if f.startswith('sha256digest='):
                            self.digests[path] = f.split('=', 1)[1].lower()
                            self.digest_algo[path] = 'sha256'

    def _load_rpm(self):
        args = ['rpm']
        if not CTX.live:
            args += ['--root', CTX.root]
        rpm_exe = shutil.which('rpm') if not CTX.live else which('rpm')
        if not rpm_exe:
            self.error = 'rpm command not available'
            log('rpm database present but the rpm command is not available - package ownership checks disabled', 'WARN')
            return
        args[0] = rpm_exe
        rc, out = run(args + ['-qa', '--qf', r'[%{FILENAMES}\t%{=NAME}\t%{FILEDIGESTS}\t%{=FILEDIGESTALGO}\n]'], timeout=300)
        algos = {'1': 'md5', '2': 'sha1', '8': 'sha256', '9': 'sha384', '10': 'sha512'}
        for line in out.splitlines():
            parts = line.split('\t')
            if len(parts) < 4:
                continue
            path, name, digest, algo = parts[0], parts[1], parts[2], parts[3]
            self.owners.setdefault(path, name)
            self.installed[name] = ''
            if digest and digest != '(none)':
                self.digests[path] = digest.lower()
                self.digest_algo[path] = algos.get(algo, 'md5')

    @staticmethod
    def _same_file(path, alias):
        """An alias (e.g. /bin/ls for /usr/bin/ls) only counts when it is the very same file on disk,
        or does not exist at all (the package database lists a path that a merged-/usr symlink covers).
        Otherwise an unpackaged /usr/sbin/x could borrow the owner of a different, packaged /usr/bin/x."""
        a = phys(alias)
        if not os.path.lexists(a):
            return True
        try:
            return os.path.samefile(phys(path), a)
        except OSError:
            return False

    def _candidates(self, path):
        out = [path]
        real = path
        try:
            real = _resolve_in_root(path) if not CTX.live else os.path.realpath(path)
        except Exception:
            pass
        if real != path:
            out.append(real)
        for base in (path, real):
            for a, b in self.ALIASES:
                for src, dst in ((a, b), (b, a)):
                    if base.startswith(src):
                        alias = dst + base[len(src):]
                        if alias not in out and self._same_file(path, alias):
                            out.append(alias)
        return out

    def owner(self, path):
        if not self.kind:
            return ''
        self._load()
        for c in self._candidates(path):
            if c in self.div_from:  # the file here now comes from the diverting package (or the admin)
                by = self.div_from[c][1]
                return '' if by == ':' else by
            if c in self.div_to:  # the displaced original still belongs to its package
                orig = self.div_to[c]
                by = self.div_from[orig][1]
                for o in self.div_owners.get(orig, []):
                    if o != by:
                        return o
                continue
            o = self.owners.get(c)
            if o:
                return o
        return ''

    def diversion(self, path):
        """Explains a dpkg-divert entry covering this path, or ''."""
        self._load()
        for c in self._candidates(path):
            if c in self.div_from:
                to, by = self.div_from[c]
                who = 'a local diversion (dpkg-divert --local)' if by == ':' else 'package ' + by
                return 'diverted by %s; the packaged original was moved to %s' % (who, to)
            if c in self.div_to:
                return 'packaged original of %s, moved here by dpkg-divert' % self.div_to[c]
        return ''

    def _want_digest(self, c):
        if c in self.div_from:
            by = self.div_from[c][1]
            return self.pkg_digests.get((by, c)) if by != ':' else None
        if c in self.div_to:
            orig = self.div_to[c]
            by = self.div_from[orig][1]
            for o in self.div_owners.get(orig, []):
                if o != by and (o, orig) in self.pkg_digests:
                    return self.pkg_digests[(o, orig)]
            return None
        return self.digests.get(c)

    def verify(self, path):
        """'ok', 'modified' or '' (unknown) - compares the file with the digest its package shipped.
        Cached per (path, size, mtime, ctime) so a file that changes during the run is hashed again."""
        self._load()
        try:
            st = os.stat(phys(path))  # the file that gets hashed (symlinks followed)
            key = (path, st.st_size, st.st_mtime, st.st_ctime)
        except OSError:
            key = None
        if key is not None and key in self._verified:
            return self._verified[key]
        result = self._verify(path)
        if key is not None:
            self._verified[key] = result
        return result

    def _verify(self, path):
        for c in self._candidates(path):
            if c in self.div_from or c in self.div_to:
                want = self._want_digest(c)
                if not want:
                    return ''
            else:
                want = self.digests.get(c)
            if not want:
                continue
            algo = self.digest_algo.get(c, 'md5')
            p = phys(path)
            try:
                h = hashlib.new(algo)
                with _open_ro(p) as fh:
                    while True:
                        b = fh.read(1024 * 1024)
                        if not b:
                            break
                        h.update(b)
            except (OSError, IOError, ValueError):
                return ''
            return 'ok' if h.hexdigest().lower() == want else 'modified'
        return ''


def pkg():
    if CTX.pkg is None:
        CTX.pkg = PackageDB()
        CTX.pkg.detect()
    return CTX.pkg


def pkg_unowned(path):
    """True only when a package database is available and no package owns the path."""
    p = pkg()
    return bool(p.kind) and p.available() and not p.owner(path)


# ----------------------------------------------------------------------------- processes (live)
def boot_time():
    t = read_proc('/proc/stat') or ''
    m = re.search(r'^btime (\d+)', t, re.M)
    return int(m.group(1)) if m else None


_CLK_TCK = None


def clk_tck():
    global _CLK_TCK
    if _CLK_TCK is None:
        try:
            _CLK_TCK = os.sysconf('SC_CLK_TCK')
        except (ValueError, OSError, AttributeError):
            _CLK_TCK = 100
    return _CLK_TCK


def proc_readlink(p):
    try:
        return os.readlink(p)
    except OSError:
        return ''
