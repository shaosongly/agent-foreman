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


ROOT = Path(__file__).resolve().parents[1]
monitor_server = load_monitor_server()


class LocalCmuxDashboardTests(unittest.TestCase):
    @mock.patch.object(monitor_server.subprocess, "run")
    def test_list_cmux_workspace_names_parses_titles(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "  workspace:1 8B058AF7-1210-4880-8257-96EC5C656581  知识库构建\n"
                "* workspace:2 CF7534E1-8C81-4659-A90A-BDAF283EE40A  IOS开发  [selected]\n"
            ),
            stderr="",
        )

        names = monitor_server.list_cmux_workspace_names()

        self.assertEqual(names["8B058AF7-1210-4880-8257-96EC5C656581"], "知识库构建")
        self.assertEqual(names["CF7534E1-8C81-4659-A90A-BDAF283EE40A"], "IOS开发")

    @mock.patch.object(monitor_server.subprocess, "run")
    def test_list_cmux_process_contexts_propagates_parent_chain(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "0.1\t49790976\t1\tprocess\t28760\t"
                "surface:2\tlogin\n"
                "0.1\t49790976\t1\tprocess\t28761\t28760\tzsh\n"
                "0.1\t49790976\t1\tprocess\t28762\t28761\tcodex\n"
                "0.1\t49790976\t1\tprocess\t28762\t"
                "workspace:F3A4C221-2C13-4166-AAB1-A242861C4F99:tag:codex.019e3015-671b-7ec2-a133-1cf4a7b77c99\tcodex\n"
                "0.1\t49790976\t1\tprocess\t28763\t28762\tnode\n"
            ),
            stderr="",
        )

        contexts = monitor_server.list_cmux_process_contexts()

        self.assertEqual(contexts[28762]["workspace_id"], "F3A4C221-2C13-4166-AAB1-A242861C4F99")
        self.assertEqual(contexts[28762]["session_id"], "019e3015-671b-7ec2-a133-1cf4a7b77c99")
        self.assertEqual(contexts[28762]["surface_ref"], "surface:2")
        self.assertEqual(contexts[28763]["workspace_id"], "F3A4C221-2C13-4166-AAB1-A242861C4F99")
        self.assertEqual(contexts[28763]["session_id"], "019e3015-671b-7ec2-a133-1cf4a7b77c99")
        self.assertEqual(contexts[28763]["surface_ref"], "surface:2")

    def test_frontend_uses_markdown_renderer_and_workspace_title(self):
        js = (ROOT / "static" / "app.js").read_text(encoding="utf-8")

        self.assertIn("function renderMarkdown(text)", js)
        self.assertIn("escapeHtml", js)
        self.assertIn("agent.cmux_workspace_name", js)
        self.assertIn("请总结当前状态", js)
        self.assertIn("renderToolFilters(snapshot)", js)
        self.assertIn("toolStatusFilters", js)
        self.assertIn("toggleToolStatusFilter(tool, status)", js)
        self.assertIn("chip.disabled = count === 0", js)
        self.assertIn("matchSourceLabels", js)
        self.assertIn("agent.cmux_surface_ref", js)
        css = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")
        self.assertIn("repeat(auto-fit", css)
        self.assertIn("980px", css)
        self.assertIn("grid-template-areas:", css)
        self.assertIn('"hero recent actions"', css)
        self.assertIn(".status-count:disabled", css)

    def test_local_cmux_documentation_exists(self):
        doc = (ROOT / "docs" / "local-cmux-codex-dashboard.md").read_text(encoding="utf-8")

        self.assertIn("send_mode: \"cmux\"", doc)
        self.assertIn("dashboard.agent_types", doc)
        self.assertIn("codex-auto-review", doc)
        self.assertIn("Markdown", doc)
        self.assertIn("session_overrides", doc)
        self.assertIn("CMUX tag", doc)

    def test_local_cmux_example_defaults_to_codex_only(self):
        config = (ROOT / "config.local-cmux.example.json").read_text(encoding="utf-8")

        self.assertIn('"agent_types": ["codex"]', config)
        self.assertIn('"hide_empty_tools": true', config)
        self.assertIn('"session_overrides": {}', config)


if __name__ == "__main__":
    unittest.main()
