from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.remote_ssh import setup
from src.remote_ssh.extension import RemoteSSH


class TestRemoteSSHExtension:
    def test_extension_setup(self, app_instance) -> None:
        setup(app_instance.api)
        ext = RemoteSSH(app_instance.api)
        config = """Host myserver\n    HostName 192.168.1.10\n    User dev\n    Port 2222"""
        hosts = ext.parse_ssh_config(config)
        assert len(hosts) == 1
        cmd = ext.build_connect_command(hosts[0])
        assert "ssh -p 2222 dev@192.168.1.10" in cmd
