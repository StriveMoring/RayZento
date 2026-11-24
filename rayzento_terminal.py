"""Readable terminal labels with an automatic plain-text fallback."""

import os
import sys


COLORS = {"ok": "32", "warning": "33", "error": "31", "info": "36", "heading": "1;36"}
LABELS = {"ok": "完成", "warning": "注意", "error": "失败", "info": "提示"}
SERVICE_STATES = {
    "active": ("ok", "运行中"), "inactive": ("info", "已停止"),
    "failed": ("error", "运行失败"), "activating": ("warning", "启动中"),
    "deactivating": ("warning", "停止中"), "reloading": ("warning", "重新加载中"),
}
STARTUP_STATES = {
    "enabled": "已开启", "disabled": "已关闭", "enabled-runtime": "仅本次开机启用",
    "masked": "已屏蔽", "masked-runtime": "仅本次开机屏蔽", "static": "由依赖启动",
}


def color(text, kind, *, stream=None):
    stream = sys.stdout if stream is None else stream
    if not stream.isatty() or "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return text
    return f"\x1b[{COLORS[kind]}m{text}\x1b[0m"


def badge(kind, label=None, *, stream=None):
    return color(f"【{label or LABELS[kind]}】", kind, stream=stream)


def result(kind, message, *, stream=None):
    stream = sys.stdout if stream is None else stream
    print(f"{badge(kind, stream=stream)} {message}", file=stream, flush=True)


def service_status(state, startup):
    kind, label = SERVICE_STATES.get(state, ("warning", "状态未知"))
    return f"{badge(kind, label)} · 开机自启{STARTUP_STATES.get(startup, '状态未知')}"
