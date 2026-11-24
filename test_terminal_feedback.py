"""Protect the distinctions between reachability, restrictions and WARP status."""

from contextlib import redirect_stdout
from io import StringIO
import os
import unittest
from unittest.mock import patch

import rayzento_core as core
import rayzento_menu as menu
import rayzento_terminal as terminal
import rayzento_warp as warp
from rayzento_warp_checks import page_result, PageResult


class TerminalFeedbackTests(unittest.TestCase):
    def test_page_restrictions_are_visible_even_with_http_200(self):
        self.assertEqual(page_result("", "200", "www.google.com.hk"),
                         PageResult("warning", "跳转香港站"))
        self.assertEqual(page_result("<title>Just a moment</title>", "200", "chatgpt.com"),
                         PageResult("warning", "遇到验证页"))
        self.assertEqual(page_result("unsupported_country", "200", "gemini.google.com"),
                         PageResult("warning", "检测到地区限制"))
        self.assertEqual(page_result("", "200", "www.netflix.com"), PageResult("ok", "页面可达"))
        self.assertEqual(page_result("", "503", "www.netflix.com").kind, "error")

    def test_color_only_in_supported_terminals(self):
        with patch.dict(os.environ, {"TERM": "xterm"}, clear=True):
            stream = StringIO()
            self.assertEqual(terminal.badge("ok", stream=stream), "【完成】")
            with patch.object(stream, "isatty", return_value=True):
                self.assertIn("\x1b[32m", terminal.badge("ok", stream=stream))
                with patch.dict(os.environ, {"NO_COLOR": ""}):
                    self.assertEqual(terminal.badge("ok", stream=stream), "【完成】")

    def test_pending_rollback_explains_how_to_recover(self):
        with redirect_stdout(StringIO()) as output, patch.object(warp, "probe") as probe:
            warp.show_status({"phase": "restoring"})
        probe.assert_not_called()
        self.assertIn("等待完成回退", output.getvalue())
        self.assertIn("选「3」恢复", output.getvalue())

    def test_enabled_configuration_with_failed_probe_reports_failure(self):
        state = {"phase": "enabled", "cores": {}, "address": "172.16.0.2"}
        with redirect_stdout(StringIO()) as output:
            with patch.object(warp, "probe", side_effect=core.Failure("测试失败")):
                with self.assertRaisesRegex(core.Failure, "实际出口检查失败"):
                    warp.show_status(state)
        self.assertNotIn("【完成】", output.getvalue())

    def test_interactive_menu_keeps_output_visible_and_redraws_on_enter(self):
        with redirect_stdout(StringIO()) as output:
            with patch.object(output, "isatty", return_value=True):
                with patch("builtins.input", side_effect=["1", "1", "", "0"]):
                    menu.menu("测试菜单", (None, (("查看", lambda: print("检测结果")),)))
        self.assertEqual(output.getvalue().count("测试菜单"), 2)
        self.assertEqual(output.getvalue().count("检测结果"), 2)
