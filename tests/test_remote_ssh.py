from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.remote_ssh import setup
from src.remote_ssh.extension import RemoteSSH


class TestRemoteSSHExtension:
    def test_setup_and_registration(self, mock_api) -> None:
        setup(mock_api)
        assert "remote_ssh" in mock_api.registered_extensions
        ext = mock_api.registered_extensions["remote_ssh"]
        assert isinstance(ext, RemoteSSH)

    def test_install_registers_commands_and_statusbar(self, mock_api) -> None:
        ext = RemoteSSH(mock_api)
        ext.install()

        # Commands
        commands = mock_api.commands.commands
        assert "remote_ssh.connect" in commands
        assert "remote_ssh.add_host" in commands
        assert "remote_ssh.open_config" in commands
        assert "remote_ssh.test_connection" in commands
        assert "remote_ssh.port_forward" in commands
        assert "remote_ssh.disconnect" in commands

        # Statusbar
        assert ext.statusbar_button is not None
        assert ext.statusbar_button.visible is True
        assert "SSH: Disconnected" in ext.statusbar_button.text

    def test_parse_ssh_config_with_directives_and_wildcard(self, mock_api) -> None:
        ext = RemoteSSH(mock_api)
        sample_config = """
# Global defaults
Host *
    User developer
    Port 2222
    ForwardAgent yes

# Specific host 1
Host dev-server
    HostName 192.168.1.100
    IdentityFile ~/.ssh/id_rsa
    ProxyJump bastion.example.com

# Specific host 2 with overridden port and user
Host prod-db
    HostName db.internal.net
    User postgres
    Port 5432
"""
        hosts = ext.parse_ssh_config(sample_config)
        assert len(hosts) == 2

        dev = next(h for h in hosts if h["host"] == "dev-server")
        assert dev["hostname"] == "192.168.1.100"
        assert dev["user"] == "developer"  # Inherited from Host *
        assert dev["port"] == "2222"       # Inherited from Host *
        assert dev["identityfile"] == "~/.ssh/id_rsa"
        assert dev["proxyjump"] == "bastion.example.com"

        prod = next(h for h in hosts if h["host"] == "prod-db")
        assert prod["hostname"] == "db.internal.net"
        assert prod["user"] == "postgres"  # Overridden
        assert prod["port"] == "5432"      # Overridden

    def test_build_connect_command_combinations(self, mock_api) -> None:
        ext = RemoteSSH(mock_api)

        # Basic host
        cmd1 = ext.build_connect_command({"host": "myserver", "hostname": "myserver.com", "port": "22"})
        assert cmd1 == "ssh myserver.com"

        # Host with custom port, user, key, and jump host
        host2 = {
            "host": "custom",
            "hostname": "10.0.0.5",
            "user": "ubuntu",
            "port": "2200",
            "identityfile": "/keys/my_key.pem",
            "proxyjump": "jump.company.com",
        }
        cmd2 = ext.build_connect_command(host2, remote_command="uname -a")
        assert "ssh" in cmd2
        assert "-p 2200" in cmd2
        assert "-i /keys/my_key.pem" in cmd2
        assert "-J jump.company.com" in cmd2
        assert "ubuntu@10.0.0.5" in cmd2
        assert '"uname -a"' in cmd2

    def test_build_port_forward_command(self, mock_api) -> None:
        ext = RemoteSSH(mock_api)
        host = {"host": "bastion", "hostname": "bastion.net", "user": "admin", "port": "22"}
        cmd = ext.build_port_forward_command(host, 8080, "localhost", 80)
        assert "ssh -N" in cmd
        assert "-L 8080:localhost:80" in cmd
        assert "admin@bastion.net" in cmd

    def test_add_or_update_host(self, mock_api, tmp_path) -> None:
        ext = RemoteSSH(mock_api)
        cfg_file = tmp_path / "config"
        cfg_file.write_text("# Initial Config\nHost existing-server\n    HostName 10.0.0.1\n", encoding="utf-8")

        # Add new host
        ext.add_or_update_host(cfg_file, "new-server", {"hostname": "10.0.0.2", "user": "root", "port": "2222"})
        content = cfg_file.read_text(encoding="utf-8")
        assert "Host new-server" in content
        assert "HostName 10.0.0.2" in content
        assert "User root" in content
        assert "Port 2222" in content
        assert "Host existing-server" in content

        # Update existing host
        ext.add_or_update_host(cfg_file, "existing-server", {"hostname": "10.0.0.99", "user": "admin"})
        updated = cfg_file.read_text(encoding="utf-8")
        assert "HostName 10.0.0.99" in updated

    def test_test_connection_reachable(self, mock_api) -> None:
        ext = RemoteSSH(mock_api)
        host = {"host": "test-box", "hostname": "127.0.0.1", "port": 22}

        with patch("socket.create_connection", return_value=MagicMock()):
            res = ext.test_connection(host)
            assert res["reachable"] is True
            assert res["latency_ms"] is not None
            assert res["error"] is None

    def test_test_connection_unreachable(self, mock_api) -> None:
        ext = RemoteSSH(mock_api)
        host = {"host": "offline-box", "hostname": "192.0.2.1", "port": 22}

        with patch("socket.create_connection", side_effect=TimeoutError("Connection timed out")):
            res = ext.test_connection(host)
            assert res["reachable"] is False
            assert "Connection timed out" in res["error"]

    def test_connect_to_host_terminal(self, mock_api) -> None:
        ext = RemoteSSH(mock_api)
        ext.install()
        ext.hosts_cache = [{"host": "web-srv", "hostname": "web.net", "user": "deploy", "port": "22"}]

        res = ext.connect_to_host("web-srv", terminal=True)
        assert res["status"] == "connected"
        assert ext.active_host == "web-srv"
        assert ext.statusbar_button.text == "SSH: web-srv"
        assert len(mock_api.terminalmanager.opened_terminals) == 1
        assert "ssh deploy@web.net" in mock_api.terminalmanager.opened_terminals[0]

    def test_disconnect(self, mock_api) -> None:
        ext = RemoteSSH(mock_api)
        ext.install()
        ext.active_host = "web-srv"
        ext.update_statusbar()
        assert ext.statusbar_button.text == "SSH: web-srv"

        ext.disconnect()
        assert ext.active_host is None
        assert ext.statusbar_button.text == "SSH: Disconnected"

    def test_manifest_schema_and_dependencies(self) -> None:
        import tomllib

        manifest_path = Path(__file__).parent.parent / "extension.toml"
        assert manifest_path.exists()
        with open(manifest_path, "rb") as f:
            data = tomllib.load(f)

        assert data["extension"]["id"] == "remote_ssh"
        assert data["extension"]["author"] == "tomlin7"
        assert data["extension"]["version"] == "0.2.0"
        assert "paramiko>=3.4.0" in data["dependencies"]["python"]
        assert "ssh" in data["dependencies"]["tools"]
        assert len(data["contributes"]["commands"]) >= 6
