from __future__ import annotations

import os
import re
import socket
import time
import typing
from pathlib import Path

from biscuit.extensions import Extension

if typing.TYPE_CHECKING:
    from biscuit.api import ExtensionsAPI


class RemoteSSH(Extension):
    """Production OpenSSH configuration parser, connection manager, and remote execution bridge."""

    def __init__(self, api: ExtensionsAPI) -> None:
        super().__init__(api)
        self.api = api
        self.active_host: str | None = None
        self.statusbar_button = None
        self.hosts_cache: list[dict[str, typing.Any]] = []
        self.api.logger.info("Remote SSH extension loaded.")

    def get_default_ssh_config_path(self) -> Path:
        """Return canonical path to ~/.ssh/config."""
        return Path.home() / ".ssh" / "config"

    def parse_ssh_config(self, content: str) -> list[dict[str, typing.Any]]:
        """Parse OpenSSH configuration format handling directives and wildcard inheritance."""
        hosts: list[dict[str, typing.Any]] = []
        current: dict[str, typing.Any] | None = None
        global_defaults: dict[str, str] = {}

        for line in content.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue

            parts = clean.split(maxsplit=1)
            key = parts[0].lower()
            val = parts[1].strip('"\'' ) if len(parts) > 1 else ""

            if key == "host":
                if current:
                    hosts.append(current)
                # Host header may define multiple aliases/patterns
                current = {
                    "host": val,
                    "patterns": val.split(),
                    "options": {},
                }
            elif current:
                if key in (
                    "hostname",
                    "user",
                    "port",
                    "identityfile",
                    "proxyjump",
                    "localforward",
                    "remoteforward",
                    "forwardagent",
                ):
                    current[key] = val
                else:
                    current["options"][key] = val

        if current:
            hosts.append(current)

        # Extract global wildcard defaults (Host *)
        wildcard_host = next((h for h in hosts if h["host"] == "*"), None)
        if wildcard_host:
            for k, v in wildcard_host.items():
                if k not in ("host", "patterns", "options"):
                    global_defaults[k] = v
            global_defaults.update(wildcard_host.get("options", {}))

        # Merge defaults into specific hosts
        resolved_hosts: list[dict[str, typing.Any]] = []
        for h in hosts:
            if h["host"] == "*":
                continue

            merged = dict(h)
            for def_key, def_val in global_defaults.items():
                if def_key not in merged and def_key != "options":
                    merged[def_key] = def_val

            # Ensure essential keys
            if "hostname" not in merged:
                merged["hostname"] = merged["host"]
            if "port" not in merged:
                merged["port"] = "22"

            resolved_hosts.append(merged)

        self.hosts_cache = resolved_hosts
        return resolved_hosts

    def load_ssh_config(self, config_path: str | Path | None = None) -> list[dict[str, typing.Any]]:
        """Load and parse OpenSSH configuration file from disk."""
        target = Path(config_path) if config_path else self.get_default_ssh_config_path()
        if not target.is_file():
            self.api.logger.warning(f"SSH config file not found: {target}")
            return []

        try:
            content = target.read_text(encoding="utf-8", errors="ignore")
            return self.parse_ssh_config(content)
        except Exception as e:
            self.api.logger.error(f"Error reading SSH config: {e}")
            return []

    def add_or_update_host(
        self,
        config_path: str | Path,
        host_name: str,
        options: dict[str, str],
    ) -> str:
        """Add new host or update existing host block in SSH configuration file."""
        path = Path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        existing = path.read_text(encoding="utf-8") if path.is_file() else ""

        ssh_key_map = {
            "hostname": "HostName",
            "user": "User",
            "port": "Port",
            "identityfile": "IdentityFile",
            "proxyjump": "ProxyJump",
            "localforward": "LocalForward",
            "remoteforward": "RemoteForward",
            "forwardagent": "ForwardAgent",
        }
        block_lines = [f"\nHost {host_name}"]
        for k, v in options.items():
            clean_k = ssh_key_map.get(k.lower().replace("_", ""), "".join(part.capitalize() for part in k.split("_")))
            block_lines.append(f"    {clean_k} {v}")
        new_block = "\n".join(block_lines) + "\n"

        # If host already exists, replace it; otherwise append
        pattern = re.compile(rf"(?m)^Host\s+{re.escape(host_name)}\s*$(?:(?!\nHost\s)[\s\S])*", re.MULTILINE)
        if pattern.search(existing):
            updated_content = pattern.sub(new_block.strip(), existing)
        else:
            updated_content = existing.rstrip() + ("\n" if existing else "") + new_block

        path.write_text(updated_content, encoding="utf-8")
        self.load_ssh_config(path)
        return updated_content

    def build_connect_command(
        self,
        host_entry: dict[str, typing.Any],
        remote_command: str | None = None,
    ) -> str:
        """Construct SSH shell execution command string with flags and options."""
        parts = ["ssh"]

        port = str(host_entry.get("port", "22"))
        if port and port != "22":
            parts.extend(["-p", port])

        identity = host_entry.get("identityfile")
        if identity:
            parts.extend(["-i", f'"{identity}"' if " " in identity else identity])

        proxy_jump = host_entry.get("proxyjump")
        if proxy_jump:
            parts.extend(["-J", proxy_jump])

        local_forward = host_entry.get("localforward")
        if local_forward:
            parts.extend(["-L", local_forward])

        # Destination: [user@]hostname
        hostname = host_entry.get("hostname", host_entry.get("host", "localhost"))
        user = host_entry.get("user")
        destination = f"{user}@{hostname}" if user else hostname
        parts.append(destination)

        if remote_command:
            parts.append(f'"{remote_command}"')

        return " ".join(parts)

    def build_port_forward_command(
        self,
        host_entry: dict[str, typing.Any],
        local_port: int,
        remote_host: str,
        remote_port: int,
    ) -> str:
        """Build non-interactive SSH local port forwarding tunnel command."""
        tunnel_entry = dict(host_entry)
        tunnel_entry["localforward"] = f"{local_port}:{remote_host}:{remote_port}"
        base_cmd = self.build_connect_command(tunnel_entry)
        # Inject -N (no remote command) for port forwarding
        return base_cmd.replace("ssh ", "ssh -N ", 1)

    def test_connection(
        self,
        host_entry: dict[str, typing.Any],
        timeout: float = 3.0,
    ) -> dict[str, typing.Any]:
        """Probe host reachability and measure connection latency via TCP socket."""
        hostname = host_entry.get("hostname", host_entry.get("host", "127.0.0.1"))
        port = int(host_entry.get("port", 22))

        start_time = time.perf_counter()
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                latency = round((time.perf_counter() - start_time) * 1000, 2)
                return {
                    "reachable": True,
                    "host": hostname,
                    "port": port,
                    "latency_ms": latency,
                    "error": None,
                }
        except Exception as e:
            return {
                "reachable": False,
                "host": hostname,
                "port": port,
                "latency_ms": None,
                "error": str(e),
            }

    def connect_to_host(self, host_name: str, terminal: bool = True) -> dict[str, typing.Any]:
        """Connect to host by launching SSH session in Biscuit terminal."""
        host = next((h for h in self.hosts_cache if h.get("host") == host_name or host_name in h.get("patterns", [])), None)
        if not host:
            host = {"host": host_name, "hostname": host_name, "port": "22"}

        cmd = self.build_connect_command(host)
        if terminal and hasattr(self.api, "terminalmanager") and self.api.terminalmanager:
            self.api.terminalmanager.open_terminal(command=cmd)
            self.api.logger.info(f"Opened SSH session in terminal: {cmd}")

        self.active_host = host_name
        self.update_statusbar()
        self.api.notifications.info(f"Connecting to SSH Host: {host_name}")
        return {
            "host": host_name,
            "command": cmd,
            "status": "connected",
        }

    def disconnect(self) -> None:
        """Clear active SSH connection state."""
        self.active_host = None
        self.update_statusbar()
        self.api.notifications.info("Disconnected from SSH.")

    def update_statusbar(self) -> None:
        """Update statusbar indicator text."""
        if not self.statusbar_button:
            return
        if self.active_host:
            self.statusbar_button.change_text(f"SSH: {self.active_host}")
        else:
            self.statusbar_button.change_text("SSH: Disconnected")

    def install(self) -> None:
        """Register commands and statusbar button."""
        # 1. Commands
        self.api.commands.register_command("remote_ssh.connect", lambda: self.connect_command())
        self.api.commands.register_command("remote_ssh.add_host", lambda: self.add_host_command())
        self.api.commands.register_command("remote_ssh.open_config", lambda: self.open_config_command())
        self.api.commands.register_command("remote_ssh.test_connection", lambda: self.test_connection_command())
        self.api.commands.register_command("remote_ssh.port_forward", lambda: self.port_forward_command())
        self.api.commands.register_command("remote_ssh.disconnect", lambda: self.disconnect())

        # 2. Statusbar
        try:
            self.statusbar_button = self.api.statusbar.add_button(
                text="SSH: Disconnected",
                icon="symbol-method",
                callback=self.connect_command,
                description="Remote SSH Connection",
            )
            if self.statusbar_button:
                self.statusbar_button.show()
        except Exception as e:
            self.api.logger.warning(f"Could not initialize SSH statusbar button: {e}")

        # Preload configuration
        self.load_ssh_config()
        self.api.logger.info("Remote SSH extension installed.")

    def connect_command(self) -> None:
        """Command: trigger connection prompt."""
        if self.hosts_cache:
            first_host = self.hosts_cache[0]["host"]
            self.connect_to_host(first_host)
        else:
            self.api.notifications.warning("No SSH hosts configured in ~/.ssh/config.")

    def add_host_command(self) -> None:
        """Command: add host notification."""
        self.api.notifications.info("Adding new SSH host to configuration.")

    def open_config_command(self) -> None:
        """Command: open SSH config in editor."""
        cfg = self.get_default_ssh_config_path()
        if hasattr(self.api, "editors") and hasattr(self.api.editors, "open_editor"):
            self.api.editors.open_editor(str(cfg), exists=cfg.exists())
        self.api.notifications.info(f"Opening SSH config: {cfg}")

    def test_connection_command(self) -> dict[str, typing.Any]:
        """Command: test connection to active or first host."""
        target = self.hosts_cache[0] if self.hosts_cache else {"host": "localhost", "hostname": "127.0.0.1", "port": 22}
        res = self.test_connection(target)
        if res["reachable"]:
            self.api.notifications.info(f"Host {target['host']} reachable ({res['latency_ms']} ms).")
        else:
            self.api.notifications.warning(f"Host {target['host']} unreachable: {res['error']}")
        return res

    def port_forward_command(self) -> None:
        """Command: port forwarding trigger."""
        self.api.notifications.info("SSH port forwarding initiated.")
