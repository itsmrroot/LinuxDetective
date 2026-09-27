# Linux investigation toolkit

A USB kit and a runbook for checking a Linux laptop or server you think was compromised.
Every tool here is open source. Check the hash of each download against its release page before you copy it onto the stick.

## 1. Build the USB stick (on a clean machine)

| Folder | Tool | Used for | Get it from |
|---|---|---|---|
| `avml/` | AVML | Memory capture (a single static binary, nothing to install) | github.com/microsoft/avml/releases |
| `uac/` | UAC | Collecting logs, configs, histories, cron, systemd and live-process data into one archive | github.com/tclahr/uac/releases |
| `velociraptor/` | Velociraptor (Linux binary) | Analysis, plus an offline collector you can build in advance | github.com/Velocidex/velociraptor/releases |
| `chkrootkit/` | chkrootkit | Rootkit checks | chkrootkit.org |
| `rkhunter/` | rkhunter | Rootkit and file-property checks | rkhunter.sourceforge.net |
| `output/` | (empty) | Evidence goes here, never onto the suspect disk | |

Format the stick as ext4 or exFAT and label it. Keep a text file on it that lists the SHA-256 of every tool.

## 2. On the suspect machine: live response

Rules first:
- **Don't reboot and don't shut down.** Memory is lost at power-off.
- **Don't install anything** from the suspect machine's package manager.
- **Write every output file to the USB stick.**
- **Keep notes as you go:** time (UTC), each command you ran, and who ran it.

```bash
# Mount the stick and become root
sudo -i
mkdir -p /mnt/usb && mount /dev/sdX1 /mnt/usb        # replace sdX1 with the stick
CASE=/mnt/usb/output/$(hostname)_$(date -u +%Y%m%d_%H%M%S)
mkdir -p "$CASE"; date -u > "$CASE/start_time.txt"

# 1) Memory first (order of volatility)
/mnt/usb/avml/avml "$CASE/memory.lime"

# 2) Triage collection with UAC
cd /mnt/usb/uac && ./uac -p ir_triage "$CASE"

# 3) Rootkit checks
/mnt/usb/chkrootkit/chkrootkit > "$CASE/chkrootkit.txt" 2>&1
rkhunter --check --sk --nocolors --logfile "$CASE/rkhunter.log" > "$CASE/rkhunter.txt" 2>&1

# 4) Package integrity: shows system files that no longer match their package
dpkg --verify > "$CASE/pkg_verify.txt" 2>&1 || true   # Debian / Ubuntu
rpm -Va       > "$CASE/pkg_verify.txt" 2>&1 || true   # RHEL / Rocky / Fedora / SUSE

# 5) Seal the evidence
date -u > "$CASE/end_time.txt"
cd "$CASE" && find . -type f ! -name SHA256SUMS -exec sha256sum {} + > SHA256SUMS
sync && cd / && umount /mnt/usb
```

Notes:
- **rkhunter:** never run `rkhunter --propupd` on the suspect machine. It records the current (possibly compromised) files as the trusted baseline.
- **chkrootkit:** a rootkit can fake the output of the machine's own `ps`, `ls` and `netstat`. `chkrootkit -p <dir>` makes it use trusted binaries from the stick.
- **UAC:** the `full` profile collects more than `ir_triage` but takes longer. UAC can also capture memory with AVML (see its documentation). Doing it separately, as above, gets it done first.

## 3. Dead-box analysis (disk image or powered-off machine)

Mount the disk or image **read-only**, and never boot it:

```bash
mkdir -p /mnt/evidence
mount -o ro,noexec,nodev,noload /dev/sdY1 /mnt/evidence     # noload: ext4 won't replay its journal
chkrootkit -r /mnt/evidence > chkrootkit_offline.txt 2>&1
```

UAC can also collect from a mounted image (`--mount-point /mnt/evidence`).

## 4. Analysis

1. **Velociraptor:** run `./velociraptor gui` on your analysis machine. It starts a local instance and opens it in the browser. Import the collection, or build an *offline collector* in advance to use in step 2. Browse the `Linux.*` artifacts for processes, cron, services, SSH keys, logins and log searches.
2. **chkrootkit / rkhunter:** read `chkrootkit.txt` for `INFECTED` lines and `rkhunter.log` for `Warning` lines. Confirm each hit before acting; both tools produce false positives.
3. **Package verification:** in the dpkg/rpm output, a `5` (or `..5`) means the file's checksum changed. A changed binary in `/bin`, `/sbin`, `/usr/bin` or `/usr/sbin` needs investigating. Changed config files are usually normal.
4. **Memory:** analyse `memory.lime` with Volatility 3. It needs a symbol table that matches the suspect machine's exact kernel.
5. **Timeline:** put auth logs, `wtmp`/`btmp` (`last -f`, `lastb -f`), the journal (`journalctl -D <dir>`) and the file timestamps from UAC's bodyfile (Sleuth Kit `mactime`) together on one UTC timeline.

## 5. Chain of custody

- Keep `SHA256SUMS` with the evidence, and re-check it with `sha256sum -c SHA256SUMS` after every copy.
- Record every hand-over: who, when (UTC) and why.
- Treat the case folder as sensitive: it can contain password hashes, keys and personal data.
