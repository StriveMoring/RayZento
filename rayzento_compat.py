"""Host compatibility checks shared by management commands."""
from dataclasses import dataclass
from pathlib import Path
import platform
import shutil
import subprocess
import sys


SUPPORTED = {"debian": ("12", "13"), "ubuntu": ("22.04", "24.04", "26.04")}
SUPPORT_TEXT = "Debian 12/13、Ubuntu 22.04/24.04/26.04 LTS"
ARCHES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
SWAP_FILESYSTEMS = ("ext4", "xfs")


@dataclass(frozen=True)
class Host:
    system: str
    distro: str
    version: str
    machine: str
    systemd: bool
    python: tuple

    def problems(self):
        issues = []
        if self.system != "Linux":
            issues.append(f"需要 Linux，当前为 {self.system}。")
        elif self.version not in SUPPORTED.get(self.distro, ()):
            issues.append(f"系统 {self.distro} {self.version} 未纳入支持范围。支持 {SUPPORT_TEXT}。")
        if self.machine not in ARCHES:
            issues.append(f"架构 {self.machine} 未支持，需 amd64 或 arm64。")
        if not self.systemd:
            issues.append("需要实际运行 systemd，且 PID 1 为 systemd。")
        if self.python < (3, 10):
            issues.append("需要 Python 3.10 或更新版本。")
        return issues


def inspect():
    system = platform.system()
    release, pid_one = {}, ""
    if system == "Linux":
        try:
            release = platform.freedesktop_os_release()
        except OSError:
            pass
        try:
            pid_one = Path("/proc/1/comm").read_text().strip()
        except OSError:
            pass
    return Host(system, release.get("ID", "未知"), release.get("VERSION_ID", "未知"),
                platform.machine().lower(), pid_one == "systemd" and Path("/run/systemd/system").is_dir(),
                tuple(sys.version_info[:3]))


def probe(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None


def container_status():
    result = probe("systemd-detect-virt", "--container")
    if result is None or result.returncode not in (0, 1) or result.stderr.strip():
        return None
    return result.returncode == 0


def report():
    host = inspect()
    print(f"系统 {host.system} · {host.distro} {host.version}")
    print(f"架构 {host.machine} · Python {'.'.join(map(str, host.python))}")
    if host.system == "Linux":
        print(f"内核 {platform.release()}")
    print(f"systemd 作为 PID 1 {'是' if host.systemd else '否'}")
    problems = host.problems()
    if problems:
        for problem in problems:
            print(f"  - {problem}")
        return False

    virt = probe("systemd-detect-virt")
    kind = virt.stdout.strip() if virt is not None and virt.returncode in (0, 1) else ""
    container = container_status()
    print(f"虚拟化 {'未检测到虚拟化' if kind == 'none' else kind or '未知'}")
    print("基础系统通过。核心安装时还会试运行对应的官方二进制。")
    missing = [name for name in ("systemctl", "ss", "openssl", "sysctl", "modprobe", "swapon") if not shutil.which(name)]
    if missing:
        print(f"缺少命令 {', '.join(missing)}。一键安装器可补齐发行版依赖。")
    fs = probe("findmnt", "-n", "-o", "FSTYPE", "--target", "/")
    filesystem = fs.stdout.strip() if fs is not None and fs.returncode == 0 else "未知"
    print(f"根分区 {filesystem} · 可用 {shutil.disk_usage('/').free / 1024**3:.1f} GiB")
    ipv4 = probe("ip", "-4", "-o", "address", "show", "scope", "global")
    if ipv4 is not None and ipv4.returncode == 0 and not ipv4.stdout.strip():
        print("未检测到全局范围的 IPv4 地址，默认节点需要可用的 IPv4 入站。")
    if container is not False:
        print("Swap 和 BBR 调优已限制。此环境为容器或无法确认虚拟化权限。")
    else:
        if filesystem not in SWAP_FILESYSTEMS:
            print("新建 Swap 文件仅支持 ext4 或 XFS。")
        else:
            print("根文件系统符合新建 Swap 的要求，仍需检查空间和已有 Swap。")
        module = probe("modinfo", "-F", "filename", "tcp_bbr")
        try:
            available = Path("/proc/sys/net/ipv4/tcp_available_congestion_control").read_text().split()
        except OSError:
            available = []
        if "bbr" in available:
            print("内核已提供可用的 BBR。")
        elif module is not None and module.returncode == 0:
            print("发现 tcp_bbr 模块，启用前仍需由实际内核验证。")
        else:
            print("当前未确认内核可用 BBR。")
    print("节点公网可达性取决于服务商安全组、防火墙和对应 TCP/UDP 端口。")
    return True
