#!/usr/bin/env python3
"""OZTP Linux Desktop Agent — observes and reports Zero Trust posture to the Control Platform."""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

import httpx

AGENT_VERSION = "0.1.0"
DEFAULT_CONFIG_PATH = "/etc/oztp/oztp-agent-desktop.json"
DEFAULT_STATE_PATH = "/etc/oztp/oztp-agent-desktop-state.json"

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("oztp.agent.desktop")


# ---------------------------------------------------------------------------
# Config and state
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class AgentConfig:
    server_url: str = "https://oztp-control-platform-651946913194.us-east1.run.app"
    state_file: str = DEFAULT_STATE_PATH
    org_api_key: str | None = None
    device_name: str | None = None
    notes: str | None = "linux-desktop-agent"
    register_only: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentConfig:
        return cls(
            server_url=data.get("server_url", cls.server_url),
            state_file=data.get("state_file", cls.state_file),
            org_api_key=data.get("org_api_key"),
            device_name=data.get("device_name"),
            notes=data.get("notes", cls.notes),
            register_only=bool(data.get("register_only", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class AgentState:
    device_id: str | None = None
    api_key: str | None = None
    org_id: str | None = None
    device_name: str | None = None
    registered_at: str | None = None
    last_check_in_at: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentState:
        return cls(
            device_id=data.get("device_id"),
            api_key=data.get("api_key"),
            org_id=data.get("org_id"),
            device_name=data.get("device_name"),
            registered_at=data.get("registered_at"),
            last_check_in_at=data.get("last_check_in_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr). Never raises."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as exc:
        return -1, "", str(exc)


def _systemctl_active(service: str) -> bool | None:
    if not shutil.which("systemctl"):
        return None
    rc, out, _ = _run(["systemctl", "is-active", service])
    if out == "active":
        return True
    if out in ("inactive", "failed", "dead"):
        return False
    return None


# ---------------------------------------------------------------------------
# MAC: AppArmor / SELinux
# ---------------------------------------------------------------------------

def _check_apparmor() -> dict[str, Any]:
    result: dict[str, Any] = {"wdac_present": False, "wdac_mode": None, "wdac_policy_count": None}

    if not shutil.which("aa-status"):
        if Path("/sys/kernel/security/apparmor/profiles").exists():
            result["wdac_present"] = True
            result["wdac_mode"] = "audit"
        return result

    rc, out, _ = _run(["aa-status", "--json"])
    if rc == 0 and out:
        try:
            data = json.loads(out)
            enforced = len(data.get("profiles", {}).get("enforce", []))
            result["wdac_present"] = True
            result["wdac_policy_count"] = enforced
            result["wdac_mode"] = "enforce" if enforced > 0 else "audit"
            return result
        except (json.JSONDecodeError, KeyError):
            pass

    rc, out, _ = _run(["aa-status"])
    if rc == 0 and out:
        result["wdac_present"] = True
        m = re.search(r"(\d+) profiles? are in enforce mode", out)
        enforced = int(m.group(1)) if m else 0
        result["wdac_policy_count"] = enforced
        result["wdac_mode"] = "enforce" if enforced > 0 else "audit"

    return result


def _check_selinux() -> dict[str, Any]:
    result: dict[str, Any] = {"wdac_present": False, "wdac_mode": None, "wdac_policy_count": None}

    enforce_path = Path("/sys/fs/selinux/enforce")
    if enforce_path.exists():
        try:
            val = enforce_path.read_text().strip()
            result["wdac_present"] = True
            result["wdac_mode"] = "enforce" if val == "1" else "audit"
            result["wdac_policy_count"] = 1 if val == "1" else 0
            return result
        except OSError:
            pass

    if shutil.which("sestatus"):
        rc, out, _ = _run(["sestatus"])
        if rc == 0:
            result["wdac_present"] = True
            if "enforcing" in out.lower():
                result["wdac_mode"] = "enforce"
                result["wdac_policy_count"] = 1
            elif "permissive" in out.lower():
                result["wdac_mode"] = "audit"

    return result


def _check_selinux_booleans() -> list[dict[str, Any]]:
    """Check risky SELinux booleans; only runs on RHEL/Fedora where getsebool exists."""
    if not shutil.which("getsebool"):
        return []

    risky = ["user_exec_content", "allow_execmem", "allow_execstack"]
    enabled = [b for b in risky if "on" in _run(["getsebool", b])[1].lower()]

    if enabled:
        return [{"name": "selinux_booleans", "result": "warn",
                 "value": f"risky booleans enabled: {', '.join(enabled)}"}]
    return [{"name": "selinux_booleans", "result": "pass", "value": "risky booleans not enabled"}]


def _detect_mac() -> dict[str, Any]:
    aa = _check_apparmor()
    if aa["wdac_present"]:
        return aa
    return _check_selinux()


# ---------------------------------------------------------------------------
# Shared posture checks (carried over from server agent)
# ---------------------------------------------------------------------------

def _check_firewall() -> list[dict[str, Any]]:
    if shutil.which("ufw"):
        rc, out, _ = _run(["ufw", "status"])
        active = rc == 0 and out.lower().startswith("status: active")
        return [{"name": "firewall", "result": "pass" if active else "warn",
                 "value": f"ufw: {'active' if active else 'inactive'}"}]

    if shutil.which("firewall-cmd"):
        active = _systemctl_active("firewalld")
        if active is None:
            rc, out, _ = _run(["firewall-cmd", "--state"])
            active = rc == 0 and "running" in out.lower()
        return [{"name": "firewall", "result": "pass" if active else "warn",
                 "value": f"firewalld: {'active' if active else 'inactive'}"}]

    if shutil.which("iptables"):
        rc, out, _ = _run(["iptables", "-L", "-n"])
        active = rc == 0 and len(out.splitlines()) > 3
        return [{"name": "firewall", "result": "pass" if active else "warn",
                 "value": "iptables active" if active else "iptables: no rules found"}]

    return [{"name": "firewall", "result": "warn", "value": "no firewall tool found"}]


def _check_luks() -> list[dict[str, Any]]:
    if not shutil.which("lsblk"):
        return [{"name": "disk_encryption", "result": "warn", "value": "lsblk not found"}]

    rc, out, _ = _run(["lsblk", "-J", "-o", "NAME,TYPE"])
    if rc != 0 or not out:
        return [{"name": "disk_encryption", "result": "warn", "value": "lsblk check failed"}]

    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return [{"name": "disk_encryption", "result": "warn", "value": "lsblk parse error"}]

    def _has_crypt(devs: list[dict]) -> bool:
        for d in devs:
            if d.get("type") == "crypt":
                return True
            if _has_crypt(d.get("children") or []):
                return True
        return False

    encrypted = _has_crypt(data.get("blockdevices", []))
    return [{"name": "disk_encryption", "result": "pass" if encrypted else "warn",
             "value": "luks detected" if encrypted else "no luks device found"}]


def _check_auto_updates() -> list[dict[str, Any]]:
    # Debian/Ubuntu — unattended-upgrades
    rc, _, _ = _run(["dpkg", "-s", "unattended-upgrades"])
    if rc == 0:
        active = _systemctl_active("apt-daily-upgrade.timer")
        if active is None:
            active = _systemctl_active("apt-daily-upgrade")
        return [{"name": "auto_updates", "result": "pass" if active else "warn",
                 "value": "unattended-upgrades: enabled" if active else "installed but timer not active"}]

    # Pop!_OS — pop-upgrade handles OS and package updates
    if shutil.which("pop-upgrade"):
        active = _systemctl_active("pop-upgrade")
        return [{"name": "auto_updates", "result": "pass" if active else "warn",
                 "value": "pop-upgrade: active" if active else "pop-upgrade installed but not active"}]

    # Fallback: apt daily timers present on Ubuntu derivatives without unattended-upgrades
    apt_timer = _systemctl_active("apt-daily-upgrade.timer")
    if apt_timer is not None:
        return [{"name": "auto_updates", "result": "pass" if apt_timer else "warn",
                 "value": "apt-daily-upgrade.timer: active" if apt_timer else "apt timer not active"}]

    # RHEL/Fedora — dnf-automatic
    rc, _, _ = _run(["rpm", "-q", "dnf-automatic"])
    if rc == 0:
        active = _systemctl_active("dnf-automatic.timer")
        if active is None:
            active = _systemctl_active("dnf-automatic-install.timer")
        return [{"name": "auto_updates", "result": "pass" if active else "warn",
                 "value": "dnf-automatic: enabled" if active else "installed but timer not active"}]

    return [{"name": "auto_updates", "result": "warn", "value": "no auto-update mechanism found"}]


def _check_passwordless_sudo() -> list[dict[str, Any]]:
    sudoers_files: list[Path] = [Path("/etc/sudoers")]
    sudoers_d = Path("/etc/sudoers.d")
    if sudoers_d.exists():
        sudoers_files.extend(sudoers_d.iterdir())

    for path in sudoers_files:
        try:
            content = path.read_text(errors="replace")
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or not stripped:
                    continue
                if "nopasswd" in stripped.lower() and "root" not in stripped.lower():
                    return [{"name": "passwordless_sudo", "result": "warn",
                             "value": "NOPASSWD entry found for non-root user"}]
        except (PermissionError, OSError):
            continue

    return [{"name": "passwordless_sudo", "result": "pass", "value": "not configured"}]


# ---------------------------------------------------------------------------
# Desktop-specific checks
# ---------------------------------------------------------------------------

def _check_screen_lock() -> list[dict[str, Any]]:
    # GNOME via gsettings — works when agent is run in a user session with D-Bus
    if shutil.which("gsettings") and os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        rc, lock_out, _ = _run(["gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled"])
        if rc == 0:
            enabled = lock_out.strip() == "true"
            rc2, delay_out, _ = _run(["gsettings", "get", "org.gnome.desktop.session", "idle-delay"])
            delay = 0
            if rc2 == 0:
                m = re.search(r"\d+", delay_out)
                delay = int(m.group()) if m else 0
            result = "pass" if (enabled and delay > 0) else "warn"
            return [{"name": "screen_lock", "result": result,
                     "value": f"gnome: lock={'on' if enabled else 'off'}, idle_delay={delay}s"}]

    # GNOME via dconf system overrides — works when running as root/systemd
    dconf_db = Path("/etc/dconf/db")
    if dconf_db.exists():
        for f in dconf_db.rglob("*"):
            if not f.is_file():
                continue
            try:
                content = f.read_text(errors="replace")
                if "lock-enabled" in content:
                    enabled = "lock-enabled=true" in content
                    return [{"name": "screen_lock",
                             "result": "pass" if enabled else "warn",
                             "value": f"gnome/dconf: {'enabled' if enabled else 'disabled'}"}]
            except OSError:
                pass

    # KDE — system-wide then user config
    for kde_path in [Path("/etc/xdg/kscreenlockerrc"), Path.home() / ".config/kscreenlockerrc"]:
        if kde_path.exists():
            try:
                content = kde_path.read_text(errors="replace")
                m = re.search(r"Autolock\s*=\s*(\w+)", content, re.IGNORECASE)
                autolock = m.group(1).lower() != "false" if m else True
                return [{"name": "screen_lock",
                         "result": "pass" if autolock else "warn",
                         "value": f"kde: {'enabled' if autolock else 'disabled'}"}]
            except OSError:
                pass

    # XFCE
    if shutil.which("xfconf-query"):
        rc, out, _ = _run(["xfconf-query", "-c", "xfce4-screensaver", "-p", "/lock-enabled"])
        if rc == 0:
            enabled = out.strip().lower() == "true"
            return [{"name": "screen_lock",
                     "result": "pass" if enabled else "warn",
                     "value": f"xfce: {'enabled' if enabled else 'disabled'}"}]

    # logind fallback
    logind_files = [Path("/etc/systemd/logind.conf")]
    logind_d = Path("/etc/systemd/logind.conf.d")
    if logind_d.exists():
        logind_files.extend(logind_d.glob("*.conf"))
    for lf in logind_files:
        try:
            content = lf.read_text(errors="replace")
            if re.search(r"^\s*IdleAction\s*=\s*lock", content, re.IGNORECASE | re.MULTILINE):
                return [{"name": "screen_lock", "result": "pass",
                         "value": "logind: IdleAction=lock"}]
        except OSError:
            pass

    return [{"name": "screen_lock", "result": "warn",
             "value": "screen lock not detected (gnome/kde/xfce/logind checked)"}]


def _check_ssh_server() -> list[dict[str, Any]]:
    active = _systemctl_active("ssh")
    if active is None:
        active = _systemctl_active("sshd")
    if active:
        return [{"name": "ssh_server", "result": "warn",
                 "value": "sshd is running — verify this is intentional on a desktop"}]
    return [{"name": "ssh_server", "result": "pass", "value": "sshd not running"}]


def _check_bluetooth() -> list[dict[str, Any]]:
    active = _systemctl_active("bluetooth")
    if not active:
        return [{"name": "bluetooth", "result": "pass", "value": "bluetooth service not running"}]

    if not shutil.which("bluetoothctl"):
        return [{"name": "bluetooth", "result": "warn",
                 "value": "bluetooth running, discoverability unknown (bluetoothctl not found)"}]

    rc, out, _ = _run(["bluetoothctl", "show"])
    if rc != 0:
        return [{"name": "bluetooth", "result": "warn",
                 "value": "bluetooth running, status check failed"}]

    out_lower = out.lower()
    discoverable = "discoverable: yes" in out_lower
    pairable = "pairable: yes" in out_lower

    if discoverable and pairable:
        return [{"name": "bluetooth", "result": "fail",
                 "value": "bluetooth is discoverable and pairable"}]
    if discoverable:
        return [{"name": "bluetooth", "result": "warn", "value": "bluetooth is discoverable"}]
    return [{"name": "bluetooth", "result": "pass", "value": "bluetooth on, not discoverable"}]


def _check_guest_account() -> list[dict[str, Any]]:
    lightdm_conf = Path("/etc/lightdm/lightdm.conf")
    if lightdm_conf.exists():
        try:
            content = lightdm_conf.read_text(errors="replace")
            if re.search(r"^\s*allow-guest\s*=\s*true", content, re.IGNORECASE | re.MULTILINE):
                return [{"name": "guest_account", "result": "warn",
                         "value": "lightdm: guest login enabled"}]
            return [{"name": "guest_account", "result": "pass",
                     "value": "lightdm: guest login disabled"}]
        except OSError:
            pass

    gdm_conf = Path("/etc/gdm3/custom.conf")
    if gdm_conf.exists():
        try:
            content = gdm_conf.read_text(errors="replace")
            if re.search(r"^\s*AllowGuest\s*=\s*true", content, re.IGNORECASE | re.MULTILINE):
                return [{"name": "guest_account", "result": "warn",
                         "value": "gdm3: guest login enabled"}]
            return [{"name": "guest_account", "result": "pass",
                     "value": "gdm3: guest login not enabled"}]
        except OSError:
            pass

    return [{"name": "guest_account", "result": "pass",
             "value": "no display manager guest config found"}]


def _check_password_hash() -> list[dict[str, Any]]:
    """Flag user accounts (UID >= 1000) using weak hashing (MD5 or DES) in /etc/shadow."""
    # Build UID map so we can skip system service accounts
    uid_map: dict[str, int] = {}
    try:
        for line in Path("/etc/passwd").read_text(errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) >= 4:
                try:
                    uid_map[parts[0]] = int(parts[2])
                except ValueError:
                    pass
    except OSError:
        pass

    try:
        content = Path("/etc/shadow").read_text(errors="replace")
    except (PermissionError, OSError) as exc:
        return [{"name": "password_hash", "result": "warn",
                 "value": f"/etc/shadow not accessible: {exc}"}]

    weak: list[str] = []
    for line in content.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        username, pw_hash = parts[0], parts[1]
        if pw_hash in ("", "!", "!!", "*", "x"):
            continue
        # Skip system service accounts (UID < 1000)
        if uid_map.get(username, 1000) < 1000:
            continue
        # $1$ = MD5, no-$ prefix = DES — both are weak
        if pw_hash.startswith("$1$") or not pw_hash.startswith("$"):
            weak.append(username)

    if weak:
        return [{"name": "password_hash", "result": "warn",
                 "value": f"weak hash (MD5/DES) for: {', '.join(weak)}"}]
    return [{"name": "password_hash", "result": "pass",
             "value": "strong hashing algorithm in use"}]


def _check_pam_faillock() -> list[dict[str, Any]]:
    if Path("/etc/security/faillock.conf").exists():
        return [{"name": "pam_faillock", "result": "pass",
                 "value": "pam_faillock configured (faillock.conf present)"}]

    pam_d = Path("/etc/pam.d")
    if not pam_d.exists():
        return [{"name": "pam_faillock", "result": "warn", "value": "/etc/pam.d not found"}]

    for fname in ("common-auth", "system-auth", "password-auth"):
        fpath = pam_d / fname
        if not fpath.exists():
            continue
        try:
            content = fpath.read_text(errors="replace")
            if "pam_faillock" in content:
                return [{"name": "pam_faillock", "result": "pass",
                         "value": f"pam_faillock configured in {fname}"}]
            if "pam_tally2" in content:
                return [{"name": "pam_faillock", "result": "pass",
                         "value": f"pam_tally2 configured in {fname}"}]
        except OSError:
            pass

    return [{"name": "pam_faillock", "result": "warn",
             "value": "account lockout (pam_faillock/pam_tally2) not detected"}]


def _check_snap_confinement() -> list[dict[str, Any]]:
    if not shutil.which("snap"):
        return []

    rc, out, _ = _run(["snap", "list", "--unicode=never"])
    if rc != 0 or not out:
        return []

    unconfined: list[str] = []
    for line in out.strip().splitlines()[1:]:  # skip header
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        notes = parts[-1] if len(parts) > 1 else ""
        if "classic" in notes or "devmode" in notes:
            unconfined.append(f"{name} ({notes})")

    if unconfined:
        return [{"name": "snap_confinement", "result": "warn",
                 "value": f"unconfined snaps: {', '.join(unconfined)}"}]
    return [{"name": "snap_confinement", "result": "pass",
             "value": "all snaps strictly confined"}]


def _check_browser_apparmor() -> list[dict[str, Any]]:
    browsers = {
        "firefox": ["/snap/bin/firefox", "/usr/bin/firefox"],
        "chromium": ["/snap/bin/chromium", "/usr/bin/chromium-browser"],
        "google-chrome": ["/usr/bin/google-chrome", "/opt/google/chrome/google-chrome"],
    }

    rc, aa_out, _ = _run(["aa-status"])
    aa_text = aa_out.lower() if rc == 0 else ""

    findings: list[dict[str, Any]] = []
    for browser, paths in browsers.items():
        installed_path = next((p for p in paths if Path(p).exists()), None)
        if installed_path is None:
            continue

        # Snap installs are sandboxed by snap confinement — no separate AppArmor profile needed
        if installed_path.startswith("/snap/"):
            findings.append({"name": f"browser_apparmor_{browser}", "result": "pass",
                              "value": f"{browser}: snap-confined"})
            continue

        profile = Path(f"/etc/apparmor.d/{Path(installed_path).name}")
        has_profile = profile.exists() or browser in aa_text
        findings.append({"name": f"browser_apparmor_{browser}",
                          "result": "pass" if has_profile else "warn",
                          "value": f"{browser}: {'AppArmor profile active' if has_profile else 'no AppArmor profile'}"}
                         )

    if not findings:
        findings.append({"name": "browser_apparmor", "result": "pass",
                         "value": "no supported browsers detected"})
    return findings


def _check_powershell() -> list[dict[str, Any]]:
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        return [{"name": "powershell", "result": "pass",
                 "value": "PowerShell Core not installed"}]

    profile = Path(f"/etc/apparmor.d/{Path(pwsh).name}")
    has_profile = profile.exists()
    detail = "AppArmor profile present" if has_profile else "no AppArmor profile — unrestricted outbound access possible"
    return [{"name": "powershell", "result": "pass" if has_profile else "warn",
             "value": f"installed at {pwsh} — {detail}"}]


def _check_legacy_protocols() -> list[dict[str, Any]]:
    targets = {
        "telnetd": "telnet daemon",
        "inetutils-telnetd": "telnet daemon",
        "rsh-server": "rsh daemon",
        "rsh-client": "rsh client",
        "telnet": "telnet client",
        "rsh": "rsh client",
        "rlogin": "rlogin",
    }

    found: list[str] = []
    for pkg, label in targets.items():
        rc, _, _ = _run(["dpkg", "-s", pkg])
        if rc == 0:
            found.append(label)
            continue
        rc, _, _ = _run(["rpm", "-q", pkg])
        if rc == 0:
            found.append(label)

    for svc in ("telnetd", "rsh", "rlogin"):
        if _systemctl_active(svc):
            found.append(f"{svc} (active service)")

    daemons = [f for f in found if "daemon" in f or "active service" in f]
    result = "fail" if daemons else ("warn" if found else "pass")
    return [{"name": "legacy_protocols", "result": result,
             "value": f"found: {', '.join(found)}" if found else "none found"}]


def _check_lotl() -> list[dict[str, Any]]:
    """Passive Living-off-the-Land indicator scan. Read-only, never interferes."""
    findings: list[dict[str, Any]] = []

    # Executable files in memory-backed or world-writable temp dirs
    suspicious_exec: list[str] = []
    for dir_path in [Path("/tmp"), Path("/dev/shm")]:
        if not dir_path.exists():
            continue
        try:
            for f in dir_path.iterdir():
                if f.is_file() and os.access(str(f), os.X_OK):
                    suspicious_exec.append(f.name)
        except PermissionError:
            pass
    if suspicious_exec:
        findings.append({"name": "lotl_exec_in_tmp", "result": "warn",
                         "value": f"executable files in /tmp or /dev/shm: {', '.join(suspicious_exec[:5])}"})

    # Pipe-to-shell and base64-decode patterns in cron jobs
    PIPE_SHELL_RE = re.compile(
        r"(curl|wget)\s[^\n]*\|\s*(ba?sh|python3?|perl|ruby)\b", re.IGNORECASE
    )
    BASE64_RE = re.compile(r"base64\s+-d|echo\s+[A-Za-z0-9+/=]{30,}\s*\|", re.IGNORECASE)

    # Known-benign cron files that use base64 legitimately (e.g. Chrome update key)
    BASE64_ALLOWLIST = {"google-chrome", "google-chrome-stable", "google-earth-pro"}

    cron_sources: list[Path] = [Path("/etc/crontab")]
    for subdir in ("cron.d", "cron.daily", "cron.weekly", "cron.monthly", "cron.hourly"):
        d = Path("/etc") / subdir
        if d.is_dir():
            cron_sources.extend(d.iterdir())
    spool = Path("/var/spool/cron/crontabs")
    if spool.is_dir():
        cron_sources.extend(spool.iterdir())

    pipe_hits: set[str] = set()
    base64_hits: set[str] = set()
    for cf in cron_sources:
        if not cf.is_file():
            continue
        try:
            content = cf.read_text(errors="replace")
            for line in content.splitlines():
                if PIPE_SHELL_RE.search(line):
                    pipe_hits.add(cf.name)
                if cf.name not in BASE64_ALLOWLIST and BASE64_RE.search(line):
                    base64_hits.add(cf.name)
        except (PermissionError, OSError):
            pass

    if pipe_hits:
        findings.append({"name": "lotl_pipe_to_shell", "result": "warn",
                         "value": f"pipe-to-shell pattern in cron: {', '.join(pipe_hits)}"})
    if base64_hits:
        findings.append({"name": "lotl_base64_cron", "result": "warn",
                         "value": f"base64 decode pattern in cron: {', '.join(base64_hits)}"})

    if not findings:
        findings.append({"name": "lotl_indicators", "result": "pass",
                         "value": "no indicators found"})
    return findings


# ---------------------------------------------------------------------------
# Posture collection
# ---------------------------------------------------------------------------

def collect_posture_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    checks.extend(_check_firewall())
    checks.extend(_check_luks())
    checks.extend(_check_auto_updates())
    checks.extend(_check_passwordless_sudo())
    checks.extend(_check_screen_lock())
    checks.extend(_check_ssh_server())
    checks.extend(_check_bluetooth())
    checks.extend(_check_guest_account())
    checks.extend(_check_password_hash())
    checks.extend(_check_pam_faillock())
    checks.extend(_check_snap_confinement())
    checks.extend(_check_browser_apparmor())
    checks.extend(_check_powershell())
    checks.extend(_check_legacy_protocols())
    checks.extend(_check_lotl())
    checks.extend(_check_selinux_booleans())
    return checks


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class OztpAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.state_path = Path(config.state_file)
        self.client = httpx.Client(base_url=config.server_url.rstrip("/"), timeout=15.0)

    def close(self) -> None:
        self.client.close()

    def load_state(self) -> AgentState:
        if not self.state_path.exists():
            return AgentState(device_name=self.config.device_name or socket.gethostname())
        return AgentState.from_dict(json.loads(self.state_path.read_text()))

    def save_state(self, state: AgentState) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(state.to_dict(), indent=2))

    def ensure_registration(self) -> tuple[AgentState, dict[str, Any] | None]:
        state = self.load_state()
        if state.device_id and state.api_key:
            return state, None

        if not self.config.org_api_key:
            raise RuntimeError("org_api_key is required for first-time registration.")

        response = self.client.post(
            "/api/v1/devices/register",
            headers={"X-Org-Key": self.config.org_api_key},
            json={"device_name": state.device_name or socket.gethostname()},
        )
        response.raise_for_status()
        data = response.json()

        state.device_id = data["device_id"]
        state.api_key = data["api_key"]
        state.org_id = data.get("org_id")
        self.save_state(state)
        logger.info("Registered device_id=%s", state.device_id)
        return state, data

    def check_in(self) -> dict[str, Any]:
        state, registration = self.ensure_registration()
        if not state.device_id or not state.api_key:
            raise RuntimeError("Missing device credentials.")

        mac = _detect_mac()
        posture = collect_posture_checks()

        payload: dict[str, Any] = {
            "agent_version": AGENT_VERSION,
            "hostname": socket.gethostname(),
            "os_name": platform.system(),
            "os_version": platform.version(),
            "wdac_present": mac["wdac_present"],
            "wdac_mode": mac["wdac_mode"],
            "wdac_policy_count": mac["wdac_policy_count"],
            "posture_checks": posture,
            "events": [],
        }
        if self.config.notes:
            payload["notes"] = self.config.notes

        response = self.client.post(
            f"/api/v1/devices/{state.device_id}/check-in",
            headers={"X-API-Key": state.api_key},
            json=payload,
        )
        response.raise_for_status()
        check_in_data = response.json()

        state.last_check_in_at = check_in_data.get("last_check_in")
        self.save_state(state)

        return {
            "state": state.to_dict(),
            "registration": registration,
            "check_in": check_in_data,
            "mac": mac,
            "posture_checks": posture,
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OZTP Linux desktop agent")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to JSON config file")
    parser.add_argument("--server-url", default=None)
    parser.add_argument("--org-api-key", default=None, help="Org API key (required for first-time registration)")
    parser.add_argument("--device-name", default=None)
    parser.add_argument("--state-file", default=None)
    parser.add_argument("--register-only", action="store_true")
    return parser


def load_config(path: str) -> AgentConfig:
    p = Path(path)
    if p.exists():
        return AgentConfig.from_dict(json.loads(p.read_text()))
    return AgentConfig()


def merge_config(base: AgentConfig, args: argparse.Namespace) -> AgentConfig:
    import dataclasses as dc
    merged = dc.replace(base)
    for field in ("server_url", "org_api_key", "device_name"):
        val = getattr(args, field.replace("-", "_"), None)
        if val is not None:
            setattr(merged, field, val)
    if args.state_file:
        merged.state_file = args.state_file
    if args.register_only:
        merged.register_only = True
    return merged


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = merge_config(load_config(args.config), args)

    agent = OztpAgent(config)
    try:
        if config.register_only:
            state, registration = agent.ensure_registration()
            print(json.dumps({"registered": registration is not None, "state": state.to_dict()}, indent=2))
        else:
            result = agent.check_in()
            print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        logger.error("Agent error: %s", exc)
        return 1
    finally:
        agent.close()


if __name__ == "__main__":
    raise SystemExit(main())
