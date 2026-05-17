import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


def load_monitor_server():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("monitor_server", root / "monitor_server.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


monitor_server = load_monitor_server()


class CmuxSendTests(unittest.TestCase):
    def test_default_send_mode_remains_stdin(self):
        config = monitor_server.load_config("/tmp/agent-foreman-missing-config.json")
        self.assertEqual(config["send_mode"], "stdin")

    def test_managed_host_accepts_cmux_send_mode(self):
        config = monitor_server.load_config(None)
        vault = monitor_server.CredentialVault(Path("/tmp/unused-credentials.enc.json"))
        store = monitor_server.ManagedHostStore(config, vault)

        store._validate_payload(
            {
                "name": "local",
                "ssh_target": "127.0.0.1",
                "port": 22,
                "username": "sentropsy",
                "mode": "ssh",
                "send_mode": "cmux",
            }
        )

    @mock.patch.object(monitor_server, "get_process_env")
    def test_get_cmux_context_reads_workspace_and_surface_from_process_env(self, env_mock):
        env_mock.return_value = {
            "CMUX_WORKSPACE_ID": "workspace-123",
            "CMUX_SURFACE_ID": "surface-456",
        }

        context = monitor_server.get_cmux_context(1234)

        self.assertEqual(context, {"workspace_id": "workspace-123", "surface_id": "surface-456"})

    @mock.patch.object(monitor_server.subprocess, "run")
    def test_send_via_cmux_sends_message_then_enter_to_surface(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")
        agent = {
            "pid": 1234,
            "cmux_workspace_id": "workspace-123",
            "cmux_surface_id": "surface-456",
        }

        result = monitor_server.send_via_cmux_local(agent, "继续")

        self.assertEqual(result["returncode"], 0)
        self.assertEqual(
            run_mock.call_args_list[0].args[0],
            [
                "cmux",
                "send",
                "--workspace",
                "workspace-123",
                "--surface",
                "surface-456",
                "继续",
            ],
        )
        self.assertEqual(
            run_mock.call_args_list[1].args[0],
            [
                "cmux",
                "send-key",
                "--workspace",
                "workspace-123",
                "--surface",
                "surface-456",
                "Enter",
            ],
        )

    def test_send_via_cmux_requires_workspace_and_surface(self):
        result = monitor_server.send_via_cmux_local({"pid": 1234}, "继续")

        self.assertEqual(result["returncode"], 1)
        self.assertIn("CMUX_WORKSPACE_ID", result["stderr"])


if __name__ == "__main__":
    unittest.main()
