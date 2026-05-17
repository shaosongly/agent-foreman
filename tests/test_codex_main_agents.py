import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


def load_monitor_server():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("monitor_server", root / "monitor_server.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


monitor_server = load_monitor_server()


class CodexMainAgentTests(unittest.TestCase):
    def test_infer_agent_type_rejects_codex_helper_processes(self):
        helper_commands = [
            "./Codex Computer Use.app/Contents/MacOS/SkyComputerUseClient mcp",
            "/Applications/Codex.app/Contents/Resources/node_repl",
            "/Applications/Codex.app/Contents/Resources/codex app-server --listen stdio://",
            "cmux hooks feed --source codex --event PermissionRequest",
        ]

        for command in helper_commands:
            with self.subTest(command=command):
                self.assertEqual(monitor_server.infer_agent_type(command), "")

    def test_infer_agent_type_keeps_foreground_auto_review_codex_process(self):
        command = (
            "codex resume -m codex-auto-review -a never -s read-only "
            "019e3015-671b-7ec2-a133-1cf4a7b77c99"
        )

        self.assertEqual(monitor_server.infer_agent_type(command), "codex")

    def test_extract_codex_session_id_from_resume_command(self):
        args = "codex resume -m gpt-5.5 019e30e1-4343-7c11-a58e-c95df56f4fe2"

        self.assertEqual(
            monitor_server.extract_codex_session_id(args),
            "019e30e1-4343-7c11-a58e-c95df56f4fe2",
        )

    def test_parse_codex_session_marks_auto_review_as_approval_review(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "rollout-auto-review.jsonl"
            path.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "timestamp": "2026-05-17T03:10:39.230Z",
                                "type": "session_meta",
                                "payload": {
                                    "id": "review-session",
                                    "cwd": "/repo",
                                    "source": {"subagent": {"other": "guardian"}},
                                    "thread_source": "subagent",
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "timestamp": "2026-05-17T03:10:39.230Z",
                                "type": "turn_context",
                                "payload": {"model": "codex-auto-review"},
                            }
                        ),
                    ]
                ),
                encoding="utf-8",
            )

            session = monitor_server.parse_codex_session(path)

        self.assertEqual(session["session_kind"], "approval_review")

    def test_match_sessions_prefers_process_session_id_over_same_cwd_newer_session(self):
        proc = monitor_server.ProcInfo(
            pid=1,
            ppid=0,
            stat="S+",
            etimes=100,
            cpu=0.0,
            mem=0.0,
            args="codex resume main-session",
            cwd="/repo",
            agent_type="codex",
            start_ts=1000,
            session_id="main-session",
        )
        sessions = [
            {
                "session_id": "review-session",
                "session_kind": "approval_review",
                "cwd": "/repo",
                "start_ts": 2000,
                "heartbeat_ts": 2000,
            },
            {
                "session_id": "main-session",
                "session_kind": "main",
                "cwd": "/repo",
                "start_ts": 900,
                "heartbeat_ts": 900,
            },
        ]

        matched = monitor_server.match_sessions([proc], sessions)

        self.assertEqual(matched[1]["session_id"], "main-session")

    def test_match_sessions_allows_foreground_approval_review_session_by_id(self):
        proc = monitor_server.ProcInfo(
            pid=1,
            ppid=0,
            stat="S+",
            etimes=100,
            cpu=0.0,
            mem=0.0,
            args="codex resume -m codex-auto-review review-session",
            cwd="/repo",
            agent_type="codex",
            start_ts=1000,
            session_id="review-session",
        )
        sessions = [
            {
                "session_id": "review-session",
                "session_kind": "approval_review",
                "cwd": "/repo",
                "start_ts": 1000,
                "heartbeat_ts": 1000,
            }
        ]

        matched = monitor_server.match_sessions([proc], sessions)

        self.assertEqual(matched[1]["session_id"], "review-session")

    def test_match_sessions_does_not_guess_cmux_codex_session_by_cwd(self):
        proc = monitor_server.ProcInfo(
            pid=1,
            ppid=0,
            stat="S+",
            etimes=100,
            cpu=0.0,
            mem=0.0,
            args="codex",
            cwd="/repo",
            agent_type="codex",
            start_ts=1000,
            session_id=None,
            cmux_workspace_id="workspace-123",
            cmux_surface_ref="surface:2",
        )
        sessions = [
            {
                "session_id": "other-session",
                "session_kind": "main",
                "cwd": "/repo",
                "start_ts": 1002,
                "heartbeat_ts": 1002,
            }
        ]

        matched = monitor_server.match_sessions([proc], sessions)

        self.assertNotIn(1, matched)

    def test_session_override_wins_by_workspace_name(self):
        proc = monitor_server.ProcInfo(
            pid=1,
            ppid=0,
            stat="S+",
            etimes=100,
            cpu=0.0,
            mem=0.0,
            args="codex",
            cwd="/repo",
            agent_type="codex",
            start_ts=1000,
            session_id="auto-session",
            cmux_workspace_id="workspace-123",
            cmux_surface_ref="surface:2",
            match_source="cmux_tag",
        )

        applied = monitor_server.apply_session_overrides(
            [proc],
            {
                "session_overrides": {
                    "cmux_workspace_name:知识库构建": {
                        "session_id": "manual-session",
                        "alias": "知识库构建",
                    }
                }
            },
            {"workspace-123": "知识库构建"},
        )

        self.assertEqual(applied[1]["session_id"], "manual-session")
        self.assertEqual(proc.session_id, "manual-session")
        self.assertEqual(proc.match_source, "manual_override")
        self.assertEqual(proc.override_alias, "知识库构建")

    def test_parse_codex_session_marks_final_answer_as_result_to_review(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "rollout-main.jsonl"
            path.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "timestamp": "2026-05-17T03:00:00.000Z",
                                "type": "session_meta",
                                "payload": {
                                    "id": "main-session",
                                    "cwd": "/repo",
                                    "source": "cli",
                                    "thread_source": "user",
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "timestamp": "2026-05-17T03:01:00.000Z",
                                "type": "event_msg",
                                "payload": {"type": "user_message", "message": "do the work"},
                            }
                        ),
                        json.dumps(
                            {
                                "timestamp": "2026-05-17T03:02:00.000Z",
                                "type": "event_msg",
                                "payload": {
                                    "type": "agent_message",
                                    "message": "实现完成。",
                                    "phase": "final_answer",
                                },
                            }
                        ),
                    ]
                ),
                encoding="utf-8",
            )

            session = monitor_server.parse_codex_session(path)

        self.assertTrue(session["has_result"])
        self.assertEqual(session["pending_items"], ["有新结果待查看"])


if __name__ == "__main__":
    unittest.main()
