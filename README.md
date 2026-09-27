<div align="center">

# 🐧🕵️ Linux Detective

### Forensic triage & compromise assessment for Linux

**Powered by Bashar Salmo**

[![Python](https://img.shields.io/badge/Python-3.6%2B-3776AB?logo=python&logoColor=white)](#-quick-start)
[![Dependencies](https://img.shields.io/badge/dependencies-none-2EA043)](#-quick-start)
[![Distros](https://img.shields.io/badge/tested-Ubuntu%20%7C%20Rocky%20%7C%20Alpine%20%7C%20Arch-E95420?logo=linux&logoColor=white)](#-tested-on)
[![Host impact](https://img.shields.io/badge/host%20impact-read--only-2EA043)](#-forensic-principles)
[![Status](https://img.shields.io/badge/status-early%20development-orange)](#-roadmap)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

*A Linux server may have been hacked. Linux Detective helps you find out, without destroying the evidence.*

[Quick start](#-quick-start) •
[What works today](#-what-works-today) •
[Runbook](#-investigation-runbook) •
[Roadmap](#-roadmap) •
[Rules](#-bring-your-own-rules)

</div>

---

> [!NOTE]
> **Early development.** The forensic engine, package-integrity verification and the investigation runbook are finished and tested.
> The full one-command scanner and HTML report are on the [roadmap](#-roadmap). Until then, the [runbook](docs/linux-ir-toolkit.md) shows how to investigate a host today with proven open-source tools.

Linux Detective is the Linux counterpart of [Windows Detective](https://github.com/itsmrroot/WindowsDetective).

## ✨ Highlights

| | |
|---|---|
| ⚡ **Zero install** | Pure Python standard library, 3.6+. Runs from a USB stick on anything from Ubuntu 18.04 and RHEL 8 to current Arch |
| 🔒 **Read-only** | Opens files without updating access times where the kernel allows it, and never hangs on a FIFO left in `/tmp` |
| 📦 **Package integrity** | Finds system files that differ from what their package shipped, on **dpkg, rpm, apk and pacman**, using the package database directly |
| 💽 **Live or dead-box** | Analyse the running host, or a disk image mounted read-only. Absolute symlinks inside the image are resolved inside the image, never on your workstation |
| 🧠 **Findings, not just data** | Severity levels, grouping of repeated events, UTC timeline and MITRE ATT&CK ids, the same model as Windows Detective |
| 🧹 **Low noise** | Allowlist your known-good tools by hash, path or text. Matches are downgraded to Info, never silently hidden |

---

## 🚀 Quick start

```bash
git clone https://github.com/itsmrroot/LinuxDetective.git
cd LinuxDetective
python3 -B tests/test_core.py        # 25 self-tests, never touches the host
```

**Find system binaries that no longer match their package:**

```bash
sudo python3 -B - <<'EOF'
import os, sys
sys.path.insert(0, '.')
from lib import core
core.new_context({'root': '/', 'tool_root': '.'})
db = core.pkg()
print('package database:', db.kind or 'none')
for d in ('/usr/bin', '/usr/sbin'):
    for name in sorted(os.listdir(d)):
        p = os.path.join(d, name)
        if os.path.isfile(p) and not os.path.islink(p):
            state = db.verify(p)
            owner = db.owner(p)
            if state == 'modified' or not owner:
                print('%-9s %-40s %s' % (state or 'unowned', p, owner))
EOF
```

To check a **disk image** instead of the running system, mount it read-only and pass the mount point as `root`:

```bash
sudo mount -o ro,noexec,nodev,noload /dev/sdb1 /mnt/evidence
# ...then use {'root': '/mnt/evidence', ...} in new_context()
```

> [!TIP]
> Run from **external media** and write any output there too. Don't install anything on the suspect machine.

---

## 🔍 What works today

<details open>
<summary><b>📦 Package integrity</b></summary>

| Distro family | Database | Ownership | Verification |
|---|---|---|---|
| Debian, Ubuntu | dpkg | `/var/lib/dpkg/info/*.list` | shipped MD5 (`*.md5sums`) |
| RHEL, Rocky, Alma, Fedora, SUSE | rpm | `rpm -qa` (also `--root` for images) | shipped SHA-256 / MD5 digests |
| Alpine | apk | `/lib/apk/db/installed` | shipped SHA-1 (`Z:` lines) |
| Arch, Manjaro | pacman | `local/*/files` | shipped SHA-256 (`mtree`) |

- Works on merged-`/usr` systems (`/bin` → `/usr/bin`). An unpackaged file can never borrow the owner of a *different* packaged file with the same name.
- "Unknown" is never reported as "unowned". Without a readable package database, the ownership checks switch off.
</details>

<details>
<summary><b>🧱 Forensic engine</b></summary>

- **Findings** with severity, category, evidence, ATT&CK id, first/last seen and occurrence count. Repeats are grouped even when PIDs, numbers or UUIDs differ.
- **UTC timeline** fed by every timed finding.
- **Artifacts** saved as CSV for your own analysis.
- **Allowlist** (`hash:`, `path:`, `text:` rules with a reason). Matching findings stay visible as *Info*.
- **Self-exclusion**: the tool ignores its own folder and case folders. Merely *mentioning* its name hides nothing.
- **Evidence helpers**: MD5 / SHA-1 / SHA-256 in one pass, file metadata, recovery copies stored as `<sha256>.bin`.
- **Safe command runner**: trusted binary paths only, clean environment, timeouts.
</details>

<details>
<summary><b>📘 Investigation runbook</b></summary>

[docs/linux-ir-toolkit.md](docs/linux-ir-toolkit.md) is a step-by-step guide covering:
- building a USB kit (AVML, UAC, Velociraptor, chkrootkit, rkhunter);
- live response in order of volatility (memory first);
- dead-box analysis of a mounted image;
- analysis tips and chain of custody.
</details>

---

## 🧪 Tested on

Every change runs the self-test suite and a live check against the distro's real package database (including catching a deliberately modified binary):

| Distro | Python | Package DB | Self-tests | Tampered binary caught |
|---|---|---|---|---|
| Ubuntu 18.04 | 3.6.9 | dpkg | ✅ | ✅ |
| Ubuntu 24.04 | 3.12 | dpkg | ✅ | ✅ |
| Rocky Linux 9 | 3.9 | rpm | ✅ | ✅ |
| Alpine 3.20 | 3.12 | apk | ✅ | ✅ |
| Arch Linux | 3.14 | pacman | ✅ | ✅ |

The self-tests also pass on macOS, where image mode lets you analyse a mounted Linux disk.

---

## 🗺️ Roadmap

- [x] Forensic engine (findings, timeline, allowlist, live and image mode)
- [x] Package integrity for dpkg, rpm, apk and pacman
- [x] Investigation runbook
- [ ] Case folder with SHA-256 manifest, hashed `.tar.gz` archive and scan history
- [ ] Integrity sweep of system directories, with setuid / setgid inventory
- [ ] IOC matching (hashes, IPs, domains) and YARA scanning
- [ ] Run UAC, chkrootkit and rkhunter automatically and import their results
- [ ] Filesystem timeline (Sleuth Kit bodyfile) and optional AVML memory capture
- [ ] Interactive HTML report (light & dark), JSON and CSV output
- [ ] One-command launcher

---

## 🎯 Bring your own rules

Command-line rules are data, not code. Put them in `rules/detection-data.json`, or in any JSON file passed as the extra rules file:

```json
{
  "commandRules": [
    {
      "id": "LOCAL-001",
      "severity": "Medium",
      "mitre": "T1059.004",
      "title": "Short description of what the rule catches",
      "pattern": "a case-insensitive regular expression"
    }
  ]
}
```

- **Fields:** `severity` is one of `Critical`, `High`, `Medium`, `Low` or `Info`.
- **Bad patterns:** a pattern that doesn't compile is reported and skipped; the rest still load.
- **Sources:** good places to start are the Linux rules of the [Sigma](https://github.com/SigmaHQ/sigma) project and your own incident tickets.

---

## 🧾 Forensic principles

> [!IMPORTANT]
> - Run as **root**, or much of the system is unreadable.
> - Write output to **external media** to avoid overwriting deleted data on the evidence disk.
> - Capture **memory first** when you suspect fileless malware, and **never reboot** a suspect host before that.

- Files are opened with `O_NOATIME` where permitted, so reading doesn't change access times, and with `O_NONBLOCK`, so a FIFO can't hang the tool.
- In image mode, every path is resolved inside the image, even absolute symlinks and `..`.
- This is automated triage. Validate every High or Critical finding before acting on it.

---

<details>
<summary><b>🗂️ Project layout</b></summary>

```text
lib/
├── core.py      engine: context, findings, timeline, allowlist, file / image / package helpers
└── rules.py     loads and applies user-supplied command rules
docs/
└── linux-ir-toolkit.md   investigation runbook
tests/
└── test_core.py          self-test suite (stdlib unittest)
```

</details>

---

<div align="center">

**🐧🕵️ Linux Detective**: Powered by **Bashar Salmo**

Released under the [MIT License](LICENSE)

</div>
