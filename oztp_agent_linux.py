#!/usr/bin/env python3
"""OZTP Linux Server Agent — observes and reports Zero Trust posture to the Control Platform."""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import platform
import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

import httpx

AGENT_VERSION = "0.1.0"
DEFAULT_CONFIG_PATH = "/etc/oztp/oztp-agent.json"
DEFAULT_STATE_PATH = "/etc/oztp/oztp-agent-state.json"

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("oztp.agent")


# ---------------------------------------------------------------------------
# Config and state
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class AgentConfig:
    server_url: str = "https://oztp-control-platform-651946913194.us-east1.run.app"
    state_file: str = DEFAULT_STATE_PATH
    org_api_key: str | None = None
    device_name: str | None = None
    notes: str | None = "linux-server-agent"
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
    """Return True if service is active, False if inactive, None if unknown."""
    if not shutil.which("systemctl"):
        return None
    rc, out, _ = _run(["systemctl", "is-active", service])
    if out == "active":
        return True
    if out in ("inactive", "failed", "dead"):
        return False
    return None


# ---------------------------------------------------------------------------
# Posture checks
# ---------------------------------------------------------------------------

def _check_apparmor() -> dict[str, Any]:
    """Return AppArmor MAC posture: wdac_present, wdac_mode, wdac_policy_count."""
    result: dict[str, Any] = {"wdac_present": False, "wdac_mode": None, "wdac_policy_count": None}

    if not shutil.which("aa-status"):
        # Check kernel support even if aa-status not installed
        profiles_path = Path("/sys/kernel/security/apparmor/profiles")
        if profiles_path.exists():
            result["wdac_present"] = True
            result["wdac_mode"] = "audit"
        return result

    rc, out, _ = _run(["aa-status", "--json"])
    if rc == 0 and out:
        try:
            data = json.loads(out)
            enforced = len(data.get("profiles", {}).get("enforce", []))
            complain = len(data.get("profiles", {}).get("complain", []))
            result["wdac_present"] = True
            result["wdac_policy_count"] = enforced
            result["wdac_mode"] = "enforce" if enforced > 0 else "audit"
            return result
        except (json.JSONDecodeError, KeyError):
            pass

    # Fallback: parse text output
    rc, out, _ = _run(["aa-status"])
    if rc == 0 and out:
        result["wdac_present"] = True
        enforced_match = re.search(r"(\d+) profiles? are in enforce mode", out)
        complain_match = re.search(r"(\d+) profiles? are in complain mode", out)
        enforced = int(enforced_match.group(1)) if enforced_match else 0
        result["wdac_policy_count"] = enforced
        result["wdac_mode"] = "enforce" if enforced > 0 else "audit"

    return result


def _check_selinux() -> dict[str, Any]:
    """Return SELinux MAC posture (fallback when AppArmor not found)."""
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


def _detect_mac() -> dict[str, Any]:
    """Detect AppArmor first, fall back to SELinux."""
    aa = _check_apparmor()
    if aa["wdac_present"]:
        return aa
    return _check_selinux()


def _check_ufw() -> list[dict[str, Any]]:
    if not shutil.which("ufw"):
        # Try iptables as fallback
        if shutil.which("iptables"):
            rc, out, _ = _run(["iptables", "-L", "-n"])
            active = rc == 0 and len(out.splitlines()) > 3
            return [{"name": "firewall", "result": "pass" if active else "warn",
                     "value": "iptables active" if active else "iptables: no rules found"}]
        return [{"name": "firewall", "result": "warn", "value": "ufw/iptables not found"}]

    rc, out, _ = _run(["ufw", "status"])
    active = rc == 0 and out.lower().startswith("status: active")
    return [{"name": "firewall_ufw", "result": "pass" if active else "warn",
             "value": "active" if active else "inactive"}]


def _check_ssh() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    # Collect all sshd config lines including drop-ins
    config_lines: list[str] = []
    main_config = Path("/etc/ssh/sshd_config")
    if main_config.exists():
        config_lines.extend(main_config.read_text(errors="replace").splitlines())
    for drop_in in sorted(Path("/etc/ssh/sshd_config.d").glob("*.conf")) if Path("/etc/ssh/sshd_config.d").exists() else []:
        config_lines.extend(drop_in.read_text(errors="replace").splitlines())

    if not config_lines:
        return [{"name": "ssh_config", "result": "warn", "value": "sshd_config not found"}]

    # Parse: last non-comment setting wins (OpenSSH behaviour)
    settings: dict[str, str] = {}
    for line in config_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            settings[parts[0].lower()] = parts[1].lower()

    # PasswordAuthentication
    pw_auth = settings.get("passwordauthentication", "yes")
    checks.append({"name": "ssh_password_auth",
                   "result": "pass" if pw_auth == "no" else "fail",
                   "value": pw_auth})

    # PermitRootLogin
    root_login = settings.get("permitrootlogin", "yes")
    safe = root_login in ("no", "prohibit-password", "forced-commands-only")
    checks.append({"name": "ssh_permit_root_login",
                   "result": "pass" if safe else "warn",
                   "value": root_login})

    return checks


def _check_auditd() -> list[dict[str, Any]]:
    active = _systemctl_active("auditd")
    if active is None:
        # Try process check
        rc, out, _ = _run(["pgrep", "-x", "auditd"])
        active = rc == 0
    return [{"name": "auditd", "result": "pass" if active else "warn",
             "value": "active" if active else "inactive"}]


def _check_fail2ban() -> list[dict[str, Any]]:
    active = _systemctl_active("fail2ban")
    if active is None:
        rc, out, _ = _run(["pgrep", "-x", "fail2ban-server"])
        active = rc == 0
    result = "pass" if active else "warn"
    return [{"name": "fail2ban", "result": result,
             "value": "active" if active else "not active"}]


def _check_luks() -> list[dict[str, Any]]:
    if not shutil.which("lsblk"):
        return [{"name": "disk_encryption", "result": "warn", "value": "lsblk not found"}]

    rc, out, _ = _run(["lsblk", "-J", "-o", "NAME,TYPE"])
    if rc != 0 or not out:
        return [{"name": "disk_encryption", "result": "warn", "value": "lsblk check failed"}]

    try:
        data = json.loads(out)
        devices = data.get("blockdevices", [])
    except json.JSONDecodeError:
        return [{"name": "disk_encryption", "result": "warn", "value": "lsblk parse error"}]

    def _has_crypt(devs: list[dict]) -> bool:
        for d in devs:
            if d.get("type") == "crypt":
                return True
            if _has_crypt(d.get("children") or []):
                return True
        return False

    encrypted = _has_crypt(devices)
    return [{"name": "disk_encryption", "result": "pass" if encrypted else "warn",
             "value": "luks detected" if encrypted else "no luks device found"}]


def _check_unattended_upgrades() -> list[dict[str, Any]]:
    # Check if package is installed
    rc, _, _ = _run(["dpkg", "-s", "unattended-upgrades"])
    if rc != 0:
        return [{"name": "auto_updates", "result": "warn", "value": "unattended-upgrades not installed"}]

    # Check if the apt daily timer is active (drives unattended-upgrades)
    active = _systemctl_active("apt-daily-upgrade.timer")
    if active is None:
        active = _systemctl_active("apt-daily-upgrade")
    return [{"name": "auto_updates", "result": "pass" if active else "warn",
             "value": "enabled" if active else "timer not active"}]


def _check_passwordless_sudo() -> list[dict[str, Any]]:
    sudoers_files: list[Path] = [Path("/etc/sudoers")]
    sudoers_d = Path("/etc/sudoers.d")
    if sudoers_d.exists():
        sudoers_files.extend(sudoers_d.iterdir())

    nopasswd_found = False
    for path in sudoers_files:
        try:
            content = path.read_text(errors="replace")
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or not stripped:
                    continue
                if "nopasswd" in stripped.lower() and "root" not in stripped.lower():
                    nopasswd_found = True
                    break
        except (PermissionError, OSError):
            continue
        if nopasswd_found:
            break

    return [{"name": "passwordless_sudo", "result": "warn" if nopasswd_found else "pass",
             "value": "NOPASSWD entry found for non-root user" if nopasswd_found else "not configured"}]


def collect_posture_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    checks.extend(_check_ufw())
    checks.extend(_check_ssh())
    checks.extend(_check_auditd())
    checks.extend(_check_fail2ban())
    checks.extend(_check_luks())
    checks.extend(_check_unattended_upgrades())
    checks.extend(_check_passwordless_sudo())
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
    parser = argparse.ArgumentParser(description="OZTP Linux server agent")
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
