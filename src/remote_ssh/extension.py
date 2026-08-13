from __future__ import annotations

import typing

from biscuit.extensions import Extension

if typing.TYPE_CHECKING:
    from biscuit.api import ExtensionsAPI


class RemoteSSH(Extension):
    """Manage SSH hosts, port tunnels, and remote workspace connections."""

    def __init__(self, api: ExtensionsAPI) -> None:
        super().__init__(api)
        self.api = api
        self.api.logger.info("Remote SSH extension initialised.")

    def parse_ssh_config(self, content: str) -> list[dict]:
        hosts = []
        current: dict = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            key, val = parts[0].lower(), parts[1] if len(parts) > 1 else ""
            if key == "host":
                if current:
                    hosts.append(current)
                current = {"host": val}
            elif current:
                current[key] = val
        if current:
            hosts.append(current)
        return hosts

    def build_connect_command(self, host_entry: dict) -> str:
        host = host_entry.get("hostname", host_entry.get("host", "localhost"))
        user = host_entry.get("user")
        port = host_entry.get("port", "22")
        dest = f"{user}@{host}" if user else host
        return f"ssh -p {port} {dest}"

    def install(self) -> None:
        self.api.logger.info("Remote SSH extension installed.")
