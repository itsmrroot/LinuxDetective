<div align="center">

# 🐧🕵️ Linux Detective

### Forensic triage & compromise assessment for Linux

**Powered by Bashar Salmo**

[![Python](https://img.shields.io/badge/Python-3.6%2B-3776AB?logo=python&logoColor=white)](#-quick-start)
[![Dependencies](https://img.shields.io/badge/dependencies-none-2EA043)](#-quick-start)
[![tests](https://github.com/itsmrroot/LinuxDetective/actions/workflows/tests.yml/badge.svg)](https://github.com/itsmrroot/LinuxDetective/actions/workflows/tests.yml)
[![Distros](https://img.shields.io/badge/tested-Ubuntu%20%7C%20Rocky%20%7C%20Alpine%20%7C%20Arch-E95420?logo=linux&logoColor=white)](#-tested-on)
[![Host impact](https://img.shields.io/badge/host%20impact-read--only-2EA043)](#-forensic-principles)
[![Status](https://img.shields.io/badge/status-early%20development-orange)](#-roadmap)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

*A Linux server may have been hacked. Linux Detective helps you find out, without destroying the evidence.*

[Quick start](#-quick-start) •
[Output](#-output) •
[What works today](#-what-works-today) •
[Runbook](#-investigation-runbook) •
[Roadmap](#-roadmap) •
[Rules](#-bring-your-own-rules)

</div>

---

> [!NOTE]
> **Early development.** Today Linux Detective checks **package integrity** and **setuid / setgid files** and produces a sealed case folder.
> More checks and the HTML report are on the [roadmap](#-roadmap). For a full investigation today, combine it with the proven open-source tools in the [runbook](docs/linux-ir-toolkit.md).

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

> [!TIP]
> Copy the folder to **external media** and write the output there too. Don't install anything on the suspect machine.

```bash
git clone https://github.com/itsmrroot/LinuxDetective.git
cd LinuxDetective
./linux-detective.sh                                   # live host (asks sudo when needed)
```

**More examples**

```bash
# Evidence-grade run: output on the USB stick, case details recorded
./linux-detective.sh --output /media/usb/Reports --case-id IR-2026-042 --analyst "Jane Doe"

# Dead-box: a disk or image mounted read-only (works from any Linux or macOS workstation)
sudo mount -o ro,noexec,nodev,noload /dev/sdb1 /mnt/evidence
./linux-detective.sh --root /mnt/evidence --since 2026-08-01

# Fast triage: binaries only, setuid sweep limited to common folders
./linux-detective.sh --quick
```

The launcher finds a suitable Python 3 (including RHEL's `platform-python`) and re-runs itself with `sudo`. You can also call `python3 -B linux_detective.py` directly.

<details>
<summary><b>⚙️ All options</b></summary>

| Option | Purpose |
|---|---|
| `--root <dir>` | Analyse a filesystem mounted at `<dir>` instead of the live host |
| `--output <dir>` | Where case folders and `scan_history.csv` go (default: `Reports/` next to the tool) |
| `--days <n>` / `--since YYYY-MM-DD` | Investigation window (default 30 days). Use `--since` for old images |
| `--case-id`, `--analyst` | Recorded in the output for chain of custody |
| `--quick` | Binaries only; setuid sweep limited to common folders |
| `--max-files <n>` | Upper bound of files the setuid sweep visits (default 3,000,000) |
| `--allowlist <file>` | Known-good rules (default `iocs/allowlist.txt`) |
| `--rules <file>` | Extra command-rule file |
| `--no-archive` | Skip the `.tar.gz` archive |

</details>

---

## 📊 Output

| Verdict | Trigger |
|---|---|
| 🔴 **COMPROMISED** | Any Critical finding |
| 🟠 **HIGHLY SUSPICIOUS** | 3 or more High findings |
| 🟠 **SUSPICIOUS** | Any High finding |
| 🟡 **NEEDS REVIEW** | 5 or more Medium findings |
| 🟢 **NO STRONG INDICATORS** | Anything else |

```text
Reports/
├── scan_history.csv                    one line per scan: time, host, verdict, risk score, counts
├── LDCase_<host>_<timestamp>.tar.gz    (+ .sha256) archive of the case folder
└── LDCase_<host>_<timestamp>/          (mode 700 - may contain sensitive data)
    ├── findings.json / findings.csv    every finding with severity, evidence and ATT&CK id
    ├── timeline.csv                    UTC timeline
    ├── system_info.json                host profile, verdict and risk score
    ├── collection.log                  what ran, when, and any errors
    ├── collection_stats.csv            duration and result of each check
    ├── manifest.sha256.csv             SHA-256 of every file (written last - chain of custody)
    └── raw/                            ModifiedPackageFiles, UnownedSystemFiles, SetuidSetgidFiles (CSV)
```

---

## 🔍 What works today

<details open>
<summary><b>📦 Package integrity</b></summary>

Every executable in `/usr/bin`, `/usr/sbin`, `/bin` and `/sbin`, and every shared library in the system library folders, is checked against the package database:

| Finding | Severity |
|---|---|
| Packaged system file has been modified | High |
| Executable / shared library in a system directory not owned by any package | Medium, **High** when created or changed within the window |
| System command is a symlink into a temporary or hidden location | High |
| System file replaced through a local `dpkg-divert` | Low |

| Distro family | Database | Ownership | Verification |
|---|---|---|---|
| Debian, Ubuntu | dpkg | `/var/lib/dpkg/info/*.list` | shipped MD5 (`*.md5sums`) |
| RHEL, Rocky, Alma, Fedora, SUSE | rpm | `rpm -qa` (also `--root` for images) | shipped SHA-256 / MD5 digests |
| Alpine | apk | `/lib/apk/db/installed` | shipped SHA-1 (`Z:` lines) |
| Arch, Manjaro | pacman | `local/*/files` | shipped SHA-256 (`mtree`) |

- Works on merged-`/usr` systems (`/bin` → `/usr/bin`). An unpackaged file can never borrow the owner of a *different* packaged file with the same name.
- Understands `dpkg-divert`, so deliberately replaced files are explained instead of reported as unknown.
- "Unknown" is never reported as "unowned". Without a readable package database, the ownership checks switch off.
</details>

<details open>
<summary><b>🔐 Setuid / setgid inventory</b></summary>

The whole filesystem is swept for setuid / setgid files. Pseudo filesystems, container storage and network shares (NFS, SMB, SSHFS) are skipped. Every file is listed with its package and verification state:

| Finding | Severity |
|---|---|
| Setuid / setgid file differs from its package | Critical |
| Setuid / setgid file not owned by any package | High (Medium under `/opt` or `/usr/local`) |
| Setuid / setgid file writable by every user | High |
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

Every push runs on GitHub Actions: the self-tests on Linux and macOS, plus a **live scan on five distros**. Each distro gets a planted modified binary, an unpackaged program and an unpackaged setuid file, and the scan must report all three with a valid manifest:

| Distro | Python | Package DB | Self-tests | Live scan catches all three |
|---|---|---|---|---|
| Ubuntu 18.04 | 3.6 | dpkg | ✅ | ✅ |
| Ubuntu 24.04 | 3.12 | dpkg | ✅ | ✅ |
| Rocky Linux 9 | 3.9 | rpm | ✅ | ✅ |
| Alpine 3.20 | 3.12 | apk | ✅ | ✅ |
| Arch Linux | 3.14 | pacman | ✅ | ✅ |

On a clean Rocky Linux 9 system the scan reports **zero findings**.

```bash
python3 -B tests/test_core.py && python3 -B tests/test_scan.py    # safe anywhere, never touches the host
```

---

## 🗺️ Roadmap

- [x] Forensic engine (findings, timeline, allowlist, live and image mode)
- [x] Package integrity for dpkg, rpm, apk and pacman
- [x] Investigation runbook
- [x] Case folder with SHA-256 manifest, hashed `.tar.gz` archive and scan history
- [x] Integrity sweep of system directories, with setuid / setgid inventory
- [x] One-command launcher
- [x] Automated tests on five distros (GitHub Actions)
- [ ] IOC matching (hashes, IPs, domains) and YARA scanning
- [ ] Run UAC, chkrootkit and rkhunter automatically and import their results
- [ ] Filesystem timeline (Sleuth Kit bodyfile) and optional AVML memory capture
- [ ] Interactive HTML report (light & dark)
- [ ] Changed configuration files in `/etc` (dpkg conffile digests)
- [ ] Read the rpm database directly, so RHEL images can be analysed without `rpm` installed

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
- **Current status:** rules are loaded and validated on every run, but none of today's checks passes command lines to them yet. The rule engine is ready for the checks that will.
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
linux_detective.py       entry point / orchestration
linux-detective.sh       launcher (finds Python 3, asks sudo)
lib/
├── core.py              engine: context, findings, timeline, allowlist, file / image / package helpers
├── system.py            host profile
├── integrity.py         package integrity sweep, setuid / setgid inventory
├── report.py            verdict, findings / timeline JSON and CSV
├── case.py              case folder, SHA-256 manifest, archive, scan history
└── rules.py             loads and applies user-supplied command rules
rules/detection-data.json   command rules (yours to fill)
iocs/allowlist.txt          known-good rules
docs/linux-ir-toolkit.md    investigation runbook
tests/
├── test_core.py         engine self-tests
├── test_scan.py         end-to-end scan of a fake image
└── integration.sh       live scan with planted problems (throwaway containers only)
```

</details>

---

<div align="center">

**🐧🕵️ Linux Detective**: Powered by **Bashar Salmo**

Released under the [MIT License](LICENSE)

</div>
